//! The /proc files paludarium has, generated when opened: the mount table
//! (`/proc/self/mountinfo`, `/proc/mounts`) from the filesystem's mounts,
//! `loadavg`, `meminfo`, `stat` and `uptime`, `/proc/sys` ([`crate::sysctl`]),
//! and this process's directory with its
//! `status`, `stat`, `cmdline`, `comm`, the `exe` and `cwd` links, its `fd`
//! directory of links to the open descriptors, its `ns` directory of links
//! to its namespaces, and its `maps`, which alone is generated as it is
//! read.
use paludarium_host::{FileHandle, FileStat};
use paludarium_mmu::{MemoryView, Prot, Usage, Vma, vm};
use paludarium_types::Errno;
use paludarium_vfs::MountPoint;
use std::sync::{Mutex, PoisonError};

/// What `stat` reports for one of these files: a regular 0444 file. Linux's
/// /proc reports size 0; this reports the real length, because reads of a
/// regular file stop at its size.
pub(crate) fn stat(length: usize) -> FileStat {
    FileStat {
        size: length as u64,
        mode: 0o100_444,
        links: 1,
        ..FileStat::default()
    }
}
/// `environ`'s `stat`: as [`stat`], but 0400, as Linux keeps it to the
/// process's owner.
pub(crate) fn private_stat(length: usize) -> FileStat {
    FileStat {
        mode: 0o100_400,
        ..stat(length)
    }
}
/// The paths served, and whether each one is the mountinfo format.
pub(crate) fn mount_table(path: &[u8]) -> Option<bool> {
    match path {
        b"/proc/self/mountinfo" => Some(true),
        b"/proc/self/mounts" | b"/proc/mounts" => Some(false),
        _ => None,
    }
}

/// This process's own /proc entries, under `/proc/self` or `/proc/<pid>`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OwnEntry {
    Directory,
    Status,
    Stat,
    Cmdline,
    Environ,
    Comm,
    /// The links to the running program and to the current directory.
    Exe,
    Cwd,
    Maps,
    /// `smaps`: `maps` with what each VMA holds and its flags.
    Smaps,
    /// `fd`, and one of its links by descriptor number.
    Descriptors,
    Descriptor(u32),
    /// `fdinfo`, and its file of a descriptor by number.
    DescriptorInfos,
    DescriptorInfo(u32),
}
pub(crate) fn own_entry(path: &[u8], pid: u32) -> Option<OwnEntry> {
    let rest = path.strip_prefix(b"/proc/")?;
    let (head, tail) = rest
        .iter()
        .position(|&b| b == b'/')
        .map_or((rest, &b""[..]), |at| (&rest[..at], &rest[at..]));
    if head != b"self" && head != pid.to_string().as_bytes() {
        return None;
    }
    match tail {
        b"" | b"/" => Some(OwnEntry::Directory),
        b"/status" => Some(OwnEntry::Status),
        b"/stat" => Some(OwnEntry::Stat),
        b"/cmdline" => Some(OwnEntry::Cmdline),
        b"/environ" => Some(OwnEntry::Environ),
        b"/comm" => Some(OwnEntry::Comm),
        b"/exe" => Some(OwnEntry::Exe),
        b"/cwd" => Some(OwnEntry::Cwd),
        b"/maps" => Some(OwnEntry::Maps),
        b"/smaps" => Some(OwnEntry::Smaps),
        b"/fd" | b"/fd/" => Some(OwnEntry::Descriptors),
        b"/fdinfo" | b"/fdinfo/" => Some(OwnEntry::DescriptorInfos),
        _ => match tail.strip_prefix(b"/fdinfo/") {
            // A regular file, which no `/` follows.
            Some(name) if !name.ends_with(b"/") => {
                descriptor_number(name).map(OwnEntry::DescriptorInfo)
            }
            Some(_) => None,
            None => descriptor_number(tail.strip_prefix(b"/fd/")?).map(OwnEntry::Descriptor),
        },
    }
}
/// The names in this process's directory, with their `d_type`, in the order
/// Linux's `tgid_base_stuff` lists them, of the entries paludarium has.
pub(crate) const OWN_NAMES: [(&[u8], u8); 18] = [
    (b"task", 4),
    (b"fd", 4),
    (b"fdinfo", 4),
    (b"ns", 4),
    (b"environ", 8),
    (b"status", 8),
    (b"comm", 8),
    (b"cmdline", 8),
    (b"stat", 8),
    (b"maps", 8),
    (b"cwd", 10),
    (b"exe", 10),
    (b"mounts", 8),
    (b"mountinfo", 8),
    (b"smaps", 8),
    (b"uid_map", 8),
    (b"gid_map", 8),
    (b"setgroups", 8),
];
/// The names in another process's directory, in the same order.
pub(crate) const TASK_NAMES: [(&[u8], u8); 12] = [
    (b"task", 4),
    (b"ns", 4),
    (b"environ", 8),
    (b"status", 8),
    (b"comm", 8),
    (b"cmdline", 8),
    (b"stat", 8),
    (b"cwd", 10),
    (b"exe", 10),
    (b"uid_map", 8),
    (b"gid_map", 8),
    (b"setgroups", 8),
];

/// An entry of another process's directory, `/proc/<pid>`, or of a
/// thread's, `/proc/<pid>/task/<tid>` (the reader's own threads too).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TaskEntry {
    Directory,
    /// `task`, the directory of the process's threads.
    Threads,
    Status,
    Stat,
    Cmdline,
    Environ,
    Comm,
    Exe,
    Cwd,
    /// `/proc/thread-self`, a link to the reading thread's directory.
    ThreadLink,
    /// `ns`, the directory of the task's namespaces, and one of its links.
    Namespaces,
    Namespace(crate::namespaces::Entry),
    /// `uid_map` or `gid_map`, and `setgroups`, of the task's user
    /// namespace.
    IdMap(crate::users::Ids),
    Setgroups,
    /// A name paludarium does not have there.
    Missing,
}
/// A path [`task_path`] found: the process, the thread under `task` if the
/// path names one, and the entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct TaskPath {
    pub pid: u32,
    pub tid: Option<u32>,
    pub entry: TaskEntry,
}
/// The path under `/proc/<pid>` of a process other than `own`, the reader,
/// under `task` of any process, or under `/proc/thread-self`, the reading
/// thread `own_tid`'s; `None` for the rest of the reader's own directory,
/// which [`own_entry`] finds. The path is taken as it reads, `.` and `..`
/// included.
pub(crate) fn task_path(path: &[u8], own: u32, own_tid: u32) -> Option<TaskPath> {
    if !path.starts_with(b"/proc/") {
        return None;
    }
    // `/proc/thread-self` is the link itself; with a slash or more after
    // it, the directory it leads to.
    let link_itself = path.ends_with(b"/thread-self");
    let path = paludarium_vfs::normalize_path(path).ok()?;
    let rest = path.strip_prefix(b"/proc/")?;
    let mut parts = rest.split(|&b| b == b'/');
    let head = parts.next()?;
    let thread_self = head == b"thread-self";
    let pid = if head == b"self" || thread_self {
        own
    } else {
        descriptor_number(head).filter(|&pid| pid != 0)?
    };
    let parts: Vec<&[u8]> = parts.collect();
    let file = |name: &[u8]| match name {
        b"status" => TaskEntry::Status,
        b"stat" => TaskEntry::Stat,
        b"cmdline" => TaskEntry::Cmdline,
        b"environ" => TaskEntry::Environ,
        b"comm" => TaskEntry::Comm,
        b"exe" => TaskEntry::Exe,
        b"cwd" => TaskEntry::Cwd,
        b"ns" => TaskEntry::Namespaces,
        b"uid_map" => TaskEntry::IdMap(crate::users::Ids::User),
        b"gid_map" => TaskEntry::IdMap(crate::users::Ids::Group),
        b"setgroups" => TaskEntry::Setgroups,
        _ => TaskEntry::Missing,
    };
    // An entry of the task's directory, or a link of its `ns`.
    let entry = |parts: &[&[u8]]| match parts {
        [name] => file(name),
        [b"ns", name] => {
            crate::namespaces::Entry::named(name).map_or(TaskEntry::Missing, TaskEntry::Namespace)
        }
        _ => TaskEntry::Missing,
    };
    let thread = |name: &[u8]| descriptor_number(name).filter(|&tid| tid != 0);
    let (tid, entry) = match parts[..] {
        [] if thread_self && link_itself => (Some(own_tid), TaskEntry::ThreadLink),
        [] if thread_self => (Some(own_tid), TaskEntry::Directory),
        _ if thread_self => (Some(own_tid), entry(&parts)),
        [b"task"] => (None, TaskEntry::Threads),
        [b"task", tid] => (Some(thread(tid)?), TaskEntry::Directory),
        [b"task", tid, ref rest @ ..] => (Some(thread(tid)?), entry(rest)),
        // The process's own `ns` and user namespace files are here; the
        // rest of its own directory is `own_entry`'s.
        [b"ns", ..] | [b"uid_map" | b"gid_map" | b"setgroups"] => (None, entry(&parts)),
        _ if pid == own => return None,
        [] => (None, TaskEntry::Directory),
        _ => (None, entry(&parts)),
    };
    Some(TaskPath { pid, tid, entry })
}

/// System-wide files under /proc.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SystemEntry {
    Loadavg,
    Meminfo,
    Stat,
    Uptime,
}
pub(crate) fn system_entry(path: &[u8]) -> Option<SystemEntry> {
    match path {
        b"/proc/loadavg" => Some(SystemEntry::Loadavg),
        b"/proc/meminfo" => Some(SystemEntry::Meminfo),
        b"/proc/stat" => Some(SystemEntry::Stat),
        b"/proc/uptime" => Some(SystemEntry::Uptime),
        _ => None,
    }
}
/// `/proc/loadavg` as Linux's `loadavg_proc_show` prints it. The averages
/// are 0, as `sysinfo` reports them, since nothing measures the load.
pub(crate) fn render_loadavg(running: usize, tasks: usize, last_pid: u32) -> Vec<u8> {
    format!("0.00 0.00 0.00 {running}/{tasks} {last_pid}\n").into_bytes()
}
/// `/proc/uptime` as Linux's `uptime_proc_show` prints it, from the
/// monotonic clock that `sysinfo` reports too, with no idle time counted.
pub(crate) fn render_uptime(nanoseconds: u64) -> Vec<u8> {
    let hundredths = nanoseconds / 10_000_000;
    format!("{}.{:02} 0.00\n", hundredths / 100, hundredths % 100).into_bytes()
}
/// The figures `/proc/stat` reports.
pub(crate) struct SystemStat {
    /// The CPUs, as `sched_getaffinity` counts them.
    pub(crate) cpus: usize,
    /// When the system booted, in seconds since the epoch: the real-time
    /// clock less the monotonic one.
    pub(crate) boot_time: u64,
    /// The process and thread IDs handed out so far.
    pub(crate) forks: u32,
    pub(crate) running: usize,
}
/// `/proc/stat` as Linux's `show_stat` prints it: the time every CPU spent
/// in each state, all 0 as `/proc/uptime` counts no idle time, a line for
/// each CPU, no interrupts, context switches or softirqs (a count of 0 with
/// none listed after it, or all 10 kinds at 0), the boot time, the forks
/// and the running tasks with none blocked.
pub(crate) fn render_system_stat(stat: &SystemStat) -> Vec<u8> {
    const TIMES: &str = " 0 0 0 0 0 0 0 0 0 0";
    let mut out = format!("cpu {TIMES}\n");
    for cpu in 0..stat.cpus {
        out.push_str(&format!("cpu{cpu}{TIMES}\n"));
    }
    out.push_str(&format!(
        "intr 0\nctxt 0\nbtime {}\nprocesses {}\nprocs_running {}\nprocs_blocked 0\nsoftirq 0{TIMES}\n",
        stat.boot_time, stat.forks, stat.running
    ));
    out.into_bytes()
}
/// `/proc/meminfo` in Linux's field order and format, with the memory
/// `sysinfo` reports: all of it free and nothing used, no swap and no huge
/// pages.
pub(crate) fn render_meminfo(total: u64) -> Vec<u8> {
    let kb = total / 1024;
    let mut fields: Vec<(&str, u64)> =
        vec![("MemTotal", kb), ("MemFree", kb), ("MemAvailable", kb)];
    fields.extend(
        [
            "Buffers",
            "Cached",
            "SwapCached",
            "Active",
            "Inactive",
            "Active(anon)",
            "Inactive(anon)",
            "Active(file)",
            "Inactive(file)",
            "Unevictable",
            "Mlocked",
            "SwapTotal",
            "SwapFree",
            "Dirty",
            "Writeback",
            "AnonPages",
            "Mapped",
            "Shmem",
            "KReclaimable",
            "Slab",
            "SReclaimable",
            "SUnreclaim",
            "KernelStack",
            "PageTables",
            "NFS_Unstable",
            "Bounce",
            "WritebackTmp",
        ]
        .map(|name| (name, 0)),
    );
    fields.extend([("CommitLimit", kb), ("Committed_AS", 0)]);
    fields.extend(["VmallocTotal", "VmallocUsed", "VmallocChunk", "Percpu"].map(|name| (name, 0)));
    let mut out = String::new();
    for (name, value) in fields {
        out.push_str(&format!("{:<16}{value:>8} kB\n", format!("{name}:")));
    }
    // Counts of huge pages have no unit.
    for name in [
        "HugePages_Total",
        "HugePages_Free",
        "HugePages_Rsvd",
        "HugePages_Surp",
    ] {
        out.push_str(&format!("{:<16}{:>8}\n", format!("{name}:"), 0));
    }
    out.push_str(&format!("{:<16}{:>8} kB\n", "Hugepagesize:", 2048));
    out.push_str(&format!("{:<16}{:>8} kB\n", "Hugetlb:", 0));
    out.into_bytes()
}

/// What `/proc/<pid>/stat` reports.
pub(crate) struct ProcessStat<'a> {
    pub pid: u32,
    pub name: &'a [u8],
    /// The state's letter, and whether it is waiting somewhere (`wchan`).
    pub state: char,
    pub waiting: bool,
    pub exit_signal: i32,
    pub parent: u32,
    pub group: u32,
    pub session: u32,
    /// `tty_nr` and `tpgid`: the controlling terminal's device and its
    /// foreground group, or 0 and -1.
    pub terminal: (u32, i32),
    /// Process and waited-for children's CPU time, in nanoseconds.
    pub cpu: u64,
    pub children_cpu: u64,
    pub nice: i32,
    pub threads: usize,
    /// The total size of the mappings, in bytes.
    pub virtual_size: u64,
    pub rss_limit: u64,
    pub start_stack: u64,
    pub start_brk: u64,
    /// `[arg_start, arg_end)` and `[env_start, env_end)`.
    pub arguments: (u64, u64),
    pub environment: (u64, u64),
    pub pending: u64,
    pub blocked: u64,
    pub ignored: u64,
    pub caught: u64,
}
/// `/proc/<pid>/stat` as Linux's `do_task_stat` prints it: 52 fields, and
/// 0 for what nothing measures (page faults, resident memory, start time,
/// the code range and the scheduler's figures).
pub(crate) fn render_stat(s: &ProcessStat<'_>) -> Vec<u8> {
    /// USER_HZ, the unit of the times, as on x86-64 Linux.
    const TICKS: u64 = 100;
    let ticks = |ns: u64| ns / (1_000_000_000 / TICKS);
    let fields: [String; 50] = [
        s.state.to_string(),
        s.parent.to_string(),
        s.group.to_string(),
        s.session.to_string(),
        s.terminal.0.to_string(),
        s.terminal.1.to_string(),
        // PF_RANDOMIZE, as for a process that address space randomization
        // applies to.
        "4194304".into(),
        "0".into(),
        "0".into(),
        "0".into(),
        "0".into(),
        ticks(s.cpu).to_string(),
        "0".into(),
        ticks(s.children_cpu).to_string(),
        "0".into(),
        (20 + s.nice).to_string(),
        s.nice.to_string(),
        s.threads.to_string(),
        "0".into(), // itrealvalue
        "0".into(), // starttime
        s.virtual_size.to_string(),
        "0".into(), // rss
        s.rss_limit.to_string(),
        "0".into(), // startcode
        "0".into(), // endcode
        s.start_stack.to_string(),
        "0".into(), // kstkesp
        "0".into(), // kstkeip
        s.pending.to_string(),
        s.blocked.to_string(),
        s.ignored.to_string(),
        s.caught.to_string(),
        u8::from(s.waiting).to_string(), // wchan
        "0".into(),                      // nswap
        "0".into(),                      // cnswap
        s.exit_signal.to_string(),
        "0".into(), // processor
        "0".into(), // rt_priority
        "0".into(), // policy: SCHED_OTHER
        "0".into(), // delayacct_blkio_ticks
        "0".into(), // guest_time
        "0".into(), // cguest_time
        "0".into(), // start_data
        "0".into(), // end_data
        s.start_brk.to_string(),
        s.arguments.0.to_string(),
        s.arguments.1.to_string(),
        s.environment.0.to_string(),
        s.environment.1.to_string(),
        "0".into(), // exit_code
    ];
    // The name's bytes as they are, as `comm` gives them.
    let mut line = format!("{} (", s.pid).into_bytes();
    line.extend(s.name.iter().take_while(|&&b| b != 0));
    line.extend(format!(") {}\n", fields.join(" ")).into_bytes());
    line
}
/// `/proc/<pid>/comm`: the name, up to its NUL, and a newline.
pub(crate) fn render_comm(name: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = name.iter().copied().take_while(|&b| b != 0).collect();
    out.push(b'\n');
    out
}

/// A descriptor's name in `fd`: decimal digits without a leading zero (but
/// "0"), within `u32`, as Linux's name_to_int reads them; a trailing slash
/// is allowed.
fn descriptor_number(name: &[u8]) -> Option<u32> {
    let name = name.strip_suffix(b"/").unwrap_or(name);
    if name.is_empty() || name.len() > 1 && name[0] == b'0' || !name.iter().all(u8::is_ascii_digit)
    {
        return None;
    }
    std::str::from_utf8(name).ok()?.parse().ok()
}
/// The `fd` directory's `stat`: 0500 and owned, as Linux shows it.
pub(crate) fn descriptors_stat() -> FileStat {
    FileStat {
        mode: 0o040_500,
        links: 2,
        ..FileStat::default()
    }
}
/// The `lstat` of a link in `fd`: user permissions for the descriptor's
/// access (read gives r-x, write -wx), and size 64, as Linux shows them.
pub(crate) fn link_stat(access: u32) -> FileStat {
    let mut mode = 0o120_000;
    if access != 1 {
        mode |= 0o500;
    }
    if access != 0 {
        mode |= 0o300;
    }
    FileStat {
        mode,
        links: 1,
        size: 64,
        ..FileStat::default()
    }
}
/// `/proc/self` not followed: a symbolic link (0777) to this process's
/// directory, as Linux's `proc_self_get_link` makes it, of size 0.
pub(crate) fn self_link_stat() -> FileStat {
    FileStat {
        mode: 0o120_777,
        links: 1,
        ..FileStat::default()
    }
}
/// The `stat` of a task's `ns`: 0511, as Linux's `tgid_base_stuff` has it.
pub(crate) fn namespaces_stat() -> FileStat {
    FileStat {
        mode: 0o040_511,
        ..directory_stat()
    }
}
/// The directory's `stat`: 0555, as Linux shows it.
pub(crate) fn directory_stat() -> FileStat {
    FileStat {
        mode: 0o040_555,
        links: 2,
        ..FileStat::default()
    }
}

/// What `/proc/self/status` reports.
pub(crate) struct Status<'a> {
    pub name: &'a [u8],
    /// The umask and the descriptors in use, which a zombie no longer has.
    pub umask: Option<u32>,
    /// The state as `status` names it, such as `R (running)`.
    pub state: &'a str,
    pub tgid: u32,
    pub pid: u32,
    pub parent: u32,
    /// The process group and the session, by their IDs in the emulator.
    pub group_id: u32,
    pub session: u32,
    /// The task's own PID namespace, whose numbers of it and those of each
    /// namespace it is in the `NS*` lines give.
    pub space: &'a crate::namespaces::Namespace,
    pub descriptors: Option<usize>,
    /// The pages locked in memory (Linux's `locked_vm`), which a process
    /// that no longer has its memory does not show.
    pub locked: Option<u64>,
    pub threads: usize,
    pub queued: usize,
    pub queue_limit: u64,
    pub pending: u64,
    pub blocked: u64,
    pub ignored: u64,
    pub caught: u64,
    pub no_new_privs: bool,
    /// The seccomp mode and the number of filters.
    pub seccomp: (u8, u32),
    pub credentials: &'a crate::credentials::Credentials,
    /// The reader's user namespace, which the IDs are shown in.
    pub reader: &'a crate::namespaces::Namespace,
}
/// `/proc/<pid>/status` in Linux's field order. Of the memory fields only
/// `VmLck` is there, and none of the CPU ones, as nothing measures them;
/// parsers treat them as optional.
pub(crate) fn render_status(s: &Status<'_>) -> Vec<u8> {
    let mut name = String::new();
    for &b in s.name.iter().take_while(|&&b| b != 0) {
        match b {
            b'\\' => name.push_str("\\\\"),
            b'\n' => name.push_str("\\n"),
            _ => name.push(char::from(b)),
        }
    }
    // Linux sizes the descriptor table in powers of two from 64.
    let fd_size = s
        .descriptors
        .map_or(0, |count| count.next_power_of_two().max(64));
    let umask = s.umask.map_or_else(String::new, |umask| {
        format!("Umask:\t{:04o}\n", umask & 0o777)
    });
    let (state, tgid, pid) = (s.state, s.tgid, s.pid);
    let c = s.credentials;
    let (uid, gid) = (
        |id| s.reader.shown(crate::users::Ids::User, id),
        |id| s.reader.shown(crate::users::Ids::Group, id),
    );
    // Each group, then a space Linux has always written after them.
    let groups: Vec<String> = c.groups.iter().map(|&g| gid(g).to_string()).collect();
    let groups = groups.join(" ");
    let bounding = crate::credentials::ALL_CAPABILITIES;
    // Each ID as the PID namespace of /proc, the first, numbers it, then each
    // namespace below it down to the task's own (`task_state`).
    let levels = s.space.levels();
    let mut numbers = String::new();
    for (name, id) in [
        ("NStgid", tgid),
        ("NSpid", pid),
        ("NSpgid", s.group_id),
        ("NSsid", s.session),
    ] {
        numbers.push_str(name);
        numbers.push(':');
        for level in &levels {
            numbers.push('\t');
            numbers.push_str(&level.number(id).to_string());
        }
        numbers.push('\n');
    }
    let memory = s
        .locked
        .map_or_else(String::new, |pages| format!("VmLck:\t{:8} kB\n", pages * 4));
    format!(
        "Name:\t{name}\n{umask}State:\t{state}\nTgid:\t{tgid}\nNgid:\t0\n\
         Pid:\t{pid}\nPPid:\t{}\nTracerPid:\t0\nUid:\t{}\t{}\t{}\t{}\nGid:\t{}\t{}\t{}\t{}\n\
         FDSize:\t{fd_size}\nGroups:\t{groups} \n{numbers}{memory}Threads:\t{}\nSigQ:\t{}/{}\n\
         SigPnd:\t{:016x}\nShdPnd:\t{:016x}\nSigBlk:\t{:016x}\nSigIgn:\t{:016x}\n\
         SigCgt:\t{:016x}\nCapInh:\t{:016x}\nCapPrm:\t{:016x}\n\
         CapEff:\t{:016x}\nCapBnd:\t{bounding:016x}\nCapAmb:\t{:016x}\n\
         NoNewPrivs:\t{}\nSeccomp:\t{}\nSeccomp_filters:\t{}\n\
         voluntary_ctxt_switches:\t0\nnonvoluntary_ctxt_switches:\t0\n",
        s.parent,
        uid(c.uid),
        uid(c.euid),
        uid(c.suid),
        uid(c.fsuid),
        gid(c.gid),
        gid(c.egid),
        gid(c.sgid),
        gid(c.fsgid),
        s.threads,
        s.queued,
        s.queue_limit,
        s.pending,
        0,
        s.blocked,
        s.ignored,
        s.caught,
        c.inheritable,
        c.permitted,
        c.effective,
        0,
        u8::from(s.no_new_privs),
        s.seccomp.0,
        s.seccomp.1,
    )
    .into_bytes()
}

/// One of this process's generated directories (`/proc/self`, whose entries
/// procfs readers open relative to it, and its `fd`), with its `stat` and
/// the position `getdents` has reached in it.
pub(crate) struct OwnDirectory {
    stat: FileStat,
    position: Mutex<u64>,
}
impl OwnDirectory {
    pub(crate) fn new(stat: FileStat) -> Self {
        Self {
            stat,
            position: Mutex::new(0),
        }
    }
}
impl FileHandle for OwnDirectory {
    fn read(&self, _: &mut [u8]) -> Result<usize, Errno> {
        Err(Errno::EISDIR)
    }
    fn write(&self, _: &[u8]) -> Result<usize, Errno> {
        Err(Errno::EBADF)
    }
    /// From the start or the current entry; a directory has no end to seek
    /// from.
    fn seek(&self, offset: i64, whence: u32) -> Result<u64, Errno> {
        let mut position = self.position.lock().unwrap_or_else(PoisonError::into_inner);
        let base = match whence {
            0 => 0,
            1 => *position,
            _ => return Err(Errno::EINVAL),
        };
        *position = base.checked_add_signed(offset).ok_or(Errno::EINVAL)?;
        Ok(*position)
    }
    fn stat(&self) -> Result<FileStat, Errno> {
        Ok(self.stat)
    }
    fn truncate(&self, _: u64) -> Result<(), Errno> {
        Err(Errno::EISDIR)
    }
    fn flock(&self, _: u32) -> Result<(), Errno> {
        Ok(())
    }
    fn flags(&self) -> u32 {
        0o200000
    }
    fn set_flags(&self, _: u32) -> Result<(), Errno> {
        Ok(())
    }
}

/// A mount path as /proc writes it: space, tab, newline and backslash octal.
fn escape(path: &[u8]) -> String {
    let mut out = String::new();
    for &b in path {
        match b {
            b' ' | b'\t' | b'\n' | b'\\' => out.push_str(&format!("\\{b:03o}")),
            _ => out.push(char::from(b)),
        }
    }
    out
}

/// `mountinfo` or `mounts` lines for `mounts`; each filesystem type is also
/// its source, so host paths are not shown.
pub(crate) fn render(mounts: &[MountPoint], mountinfo: bool) -> Vec<u8> {
    let mut out = String::new();
    for (i, mount) in mounts.iter().enumerate() {
        let path = escape(&mount.path);
        if mountinfo {
            let (id, parent) = (21 + i, if i == 0 { 1 } else { 21 });
            out.push_str(&format!(
                "{id} {parent} 0:{} / {path} rw,relatime - {kind} {kind} rw\n",
                i + 1,
                kind = mount.kind
            ));
        } else {
            out.push_str(&format!(
                "{kind} {path} {kind} rw,relatime 0 0\n",
                kind = mount.kind
            ));
        }
    }
    out.into_bytes()
}

/// A file whose contents were fixed when it was opened.
pub(crate) struct GeneratedFile {
    content: Vec<u8>,
    position: Mutex<usize>,
    writable: bool,
}
impl GeneratedFile {
    /// The files are 0444, but the guest is root, which may open them for
    /// writing anyway; the write itself then fails, as on Linux.
    pub(crate) fn open(content: Vec<u8>, flags: u32) -> Self {
        Self {
            content,
            position: Mutex::new(0),
            writable: flags & 3 != 0,
        }
    }
}
impl FileHandle for GeneratedFile {
    fn read(&self, buf: &mut [u8]) -> Result<usize, Errno> {
        let mut position = self.position.lock().unwrap_or_else(PoisonError::into_inner);
        let rest = self.content.get(*position..).unwrap_or(&[]);
        let count = buf.len().min(rest.len());
        buf[..count].copy_from_slice(&rest[..count]);
        *position += count;
        Ok(count)
    }
    /// These files have no write operation: EINVAL, or EBADF on a
    /// descriptor opened read-only.
    fn write(&self, _: &[u8]) -> Result<usize, Errno> {
        Err(if self.writable {
            Errno::EINVAL
        } else {
            Errno::EBADF
        })
    }
    fn seek(&self, offset: i64, whence: u32) -> Result<u64, Errno> {
        let mut position = self.position.lock().unwrap_or_else(PoisonError::into_inner);
        let base = match whence {
            0 => 0,
            1 => *position as i64,
            2 => self.content.len() as i64,
            _ => return Err(Errno::EINVAL),
        };
        let target = base
            .checked_add(offset)
            .filter(|t| *t >= 0)
            .ok_or(Errno::EINVAL)?;
        *position = usize::try_from(target).map_err(|_| Errno::EINVAL)?;
        Ok(target as u64)
    }
    fn stat(&self) -> Result<FileStat, Errno> {
        Ok(stat(self.content.len()))
    }
    fn truncate(&self, _: u64) -> Result<(), Errno> {
        Err(Errno::EINVAL)
    }
    fn flock(&self, _: u32) -> Result<(), Errno> {
        Ok(())
    }
    fn flags(&self) -> u32 {
        0
    }
    fn set_flags(&self, _: u32) -> Result<(), Errno> {
        Ok(())
    }
}

/// One line of `maps`, as Linux's `show_map_vma` writes it: the header with
/// a space after the inode, then, for a VMA with a name, spaces up to column
/// 72 and one more before it. A newline in a path is octal.
fn map_line(vma: &Vma, start_stack: u64) -> Vec<u8> {
    let flag = |prot: Prot, letter: char| {
        if vma.prot.contains(prot) { letter } else { '-' }
    };
    let (device, inode) = vma.identity;
    let (major, minor) = (
        (device >> 8) & 0xfff,
        (device & 0xff) | ((device >> 12) & !0xff),
    );
    // Shared anonymous memory's file lies on Linux's first device.
    let minor = match &vma.file {
        Some(file) if !file.source => 1,
        _ => minor,
    };
    let mut line = format!(
        "{:08x}-{:08x} {}{}{}{} {:08x} {major:02x}:{minor:02x} {inode} ",
        vma.start,
        vma.end,
        flag(Prot::READ, 'r'),
        flag(Prot::WRITE, 'w'),
        flag(Prot::EXEC, 'x'),
        if vma.shared { 's' } else { 'p' },
        vma.offset,
    )
    .into_bytes();
    let name: &[u8] = match &vma.file {
        Some(file) if file.source => file.name.as_deref().unwrap_or_default(),
        Some(_) => b"/dev/zero (deleted)",
        None if vma.heap => b"[heap]",
        None if vma.start <= start_stack && vma.end >= start_stack => b"[stack]",
        None => b"",
    };
    if !name.is_empty() {
        line.resize(line.len().max(MAPS_NAME_COLUMN), b' ');
        line.push(b' ');
        for &b in name {
            if b == b'\n' {
                line.extend_from_slice(b"\\012");
            } else {
                line.push(b);
            }
        }
    }
    line.push(b'\n');
    line
}
/// The lines `smaps` writes after a VMA's line of `maps`, as Linux's
/// `show_smap` does: its size, what its pages hold ([`Usage`]), and its
/// flags. Pss counts a page `fork` shares as half, as if one other process
/// had it. No page here is huge, swapped or merged by KSM, and the CPU
/// has no protection keys, which leaves out `ProtectionKey`.
fn smap_lines(vma: &Vma, usage: Usage) -> Vec<u8> {
    let kb = |pages: u64| pages * 4;
    let pss = |private: u64, shared: u64| private * 4 + shared * 2;
    let pss_all = pss(
        usage.private_clean + usage.private_dirty,
        usage.shared_clean + usage.shared_dirty,
    );
    let locked = if vma.flags & vm::LOCKED != 0 {
        pss_all
    } else {
        0
    };
    let mut out = String::new();
    for (name, value) in [
        ("Size:           ", (vma.end - vma.start) >> 10),
        ("KernelPageSize: ", 4),
        ("MMUPageSize:    ", 4),
        ("Rss:            ", kb(usage.resident)),
        ("Pss:            ", pss_all),
        (
            "Pss_Dirty:      ",
            pss(usage.private_dirty, usage.shared_dirty),
        ),
        ("Shared_Clean:   ", kb(usage.shared_clean)),
        ("Shared_Dirty:   ", kb(usage.shared_dirty)),
        ("Private_Clean:  ", kb(usage.private_clean)),
        ("Private_Dirty:  ", kb(usage.private_dirty)),
        ("Referenced:     ", kb(usage.resident)),
        ("Anonymous:      ", kb(usage.anonymous)),
        ("KSM:            ", 0),
        ("LazyFree:       ", 0),
        ("AnonHugePages:  ", 0),
        ("ShmemPmdMapped: ", 0),
        ("FilePmdMapped:  ", 0),
        ("Shared_Hugetlb: ", 0),
    ] {
        out.push_str(&format!("{name}{value:8} kB\n"));
    }
    // One column more for the longer name.
    out.push_str(&format!("Private_Hugetlb: {:7} kB\n", 0));
    for (name, value) in [
        ("Swap:           ", 0),
        ("SwapPss:        ", 0),
        ("Locked:         ", locked),
    ] {
        out.push_str(&format!("{name}{value:8} kB\n"));
    }
    out.push_str(&format!("THPeligible:    {:8}\n", 0));
    out.push_str("VmFlags: ");
    for bit in 0..64 {
        if vma.flags & (1 << bit) != 0
            && let Some(name) = VM_FLAG_NAMES.get(bit)
            && !name.is_empty()
        {
            out.push_str(name);
            out.push(' ');
        }
    }
    out.push('\n');
    out.into_bytes()
}
/// The names `smaps` gives the bits of `vm_flags`, by bit, as Linux's
/// `show_smap_vma_flags` has them on x86-64: the protection key's bits
/// have none, and one it does not know is `??`.
const VM_FLAG_NAMES: [&str; 44] = [
    "rd", "wr", "ex", "sh", "mr", "mw", "me", "ms", "gd", "um", "pf", "gu", "uw", "lo", "io", "sr",
    "rr", "dc", "de", "lf", "ac", "nr", "ht", "sf", "ar", "wf", "dd", "sd", "mm", "hg", "nh", "mg",
    "", "", "", "", "", "ss", "??", "??", "dp", "ui", "sl", "ur",
];
/// Where `maps` pads a line to before its name (Linux's width of
/// `25 + sizeof(void *) * 6 - 1`).
const MAPS_NAME_COLUMN: usize = 72;
/// How much a `read` of `maps` gathers: Linux's `seq_file` buffer, one page
/// until a single line needs more.
const MAPS_BUFFER: usize = 4096;
/// Past the last VMA, as Linux's `m_start` is told by its sentinel.
const MAPS_END: u64 = u64::MAX;

/// Where a reader of `maps` has got to, as Linux's `seq_file` keeps it.
struct MapsPosition {
    /// The bytes gathered but not yet read.
    pending: Vec<u8>,
    /// How far into `pending` the reader is.
    from: usize,
    /// The start of the next VMA to gather.
    next: u64,
    /// The file position.
    position: u64,
    /// The size of the buffer, which a long line doubles.
    buffer: usize,
}

/// `/proc/<pid>/maps`, generated as it is read from the VMAs of the address
/// space it was opened on: a read sees the mappings of that moment, from the
/// address it had reached, whatever they were when it was opened.
pub(crate) struct MapsFile {
    memory: MemoryView,
    start_stack: u64,
    /// It is `smaps`, which follows each line with [`smap_lines`].
    smaps: bool,
    writable: bool,
    position: Mutex<MapsPosition>,
}
impl MapsFile {
    pub(crate) fn open(memory: MemoryView, start_stack: u64, flags: u32) -> Self {
        Self::open_as(memory, start_stack, flags, false)
    }
    /// `smaps` rather than `maps` with `smaps`.
    pub(crate) fn open_as(memory: MemoryView, start_stack: u64, flags: u32, smaps: bool) -> Self {
        Self {
            memory,
            start_stack,
            smaps,
            writable: flags & 3 != 0,
            position: Mutex::new(MapsPosition {
                pending: Vec::new(),
                from: 0,
                next: 0,
                position: 0,
                buffer: MAPS_BUFFER,
            }),
        }
    }
    /// The line of the VMA at `next` or after it, and where the next starts.
    fn take_line(&self, next: u64) -> Option<(Vec<u8>, u64)> {
        if next == MAPS_END {
            return None;
        }
        let vma = self.memory.vma_from(next)?;
        let after = self.memory.vma_from(vma.end).map_or(MAPS_END, |v| v.start);
        let mut line = map_line(&vma, self.start_stack);
        if self.smaps {
            let usage = self.memory.usage(vma.start, vma.end).unwrap_or_default();
            line.extend_from_slice(&smap_lines(&vma, usage));
        }
        Some((line, after))
    }
    /// Gathers whole lines until `wanted` bytes are there or one more would
    /// fill the buffer, as `seq_read` does; the first always goes in.
    fn gather(&self, state: &mut MapsPosition, wanted: usize) {
        state.pending.clear();
        state.from = 0;
        while let Some((line, after)) = self.take_line(state.next) {
            if state.pending.is_empty() {
                while line.len() >= state.buffer {
                    state.buffer *= 2;
                }
            } else if state.pending.len() + line.len() >= state.buffer {
                break;
            }
            state.pending.extend_from_slice(&line);
            state.next = after;
            if state.pending.len() >= wanted {
                break;
            }
        }
    }
    /// Starts over and walks to `offset`, as Linux's `traverse`: one past
    /// the end only reads nothing.
    fn walk_to(&self, state: &mut MapsPosition, offset: u64) {
        state.pending.clear();
        state.from = 0;
        state.next = 0;
        if offset == 0 {
            return;
        }
        let mut reached = 0;
        while let Some((line, after)) = self.take_line(state.next) {
            state.next = after;
            let length = line.len() as u64;
            if reached + length > offset {
                state.from = (offset - reached) as usize;
                state.pending = line;
                return;
            }
            reached += length;
            if reached == offset {
                return;
            }
        }
    }
}
impl FileHandle for MapsFile {
    fn as_any(&self) -> Option<&dyn std::any::Any> {
        Some(self)
    }
    fn read(&self, buf: &mut [u8]) -> Result<usize, Errno> {
        let mut state = self.position.lock().unwrap_or_else(PoisonError::into_inner);
        let state = &mut *state;
        let mut copied = 0;
        let waiting = &state.pending[state.from..];
        if !waiting.is_empty() {
            copied = buf.len().min(waiting.len());
            buf[..copied].copy_from_slice(&waiting[..copied]);
            state.from += copied;
            if state.from < state.pending.len() {
                state.position += copied as u64;
                return Ok(copied);
            }
        }
        if copied < buf.len() {
            self.gather(state, buf.len() - copied);
            let count = (buf.len() - copied).min(state.pending.len());
            buf[copied..copied + count].copy_from_slice(&state.pending[..count]);
            state.from = count;
            copied += count;
        }
        state.position += copied as u64;
        Ok(copied)
    }
    /// It has no write operation: EINVAL, or EBADF on a descriptor opened
    /// read-only.
    fn write(&self, _: &[u8]) -> Result<usize, Errno> {
        Err(if self.writable {
            Errno::EINVAL
        } else {
            Errno::EBADF
        })
    }
    /// As Linux's `seq_lseek`: from the start or the current position, never
    /// the end, which it does not know.
    fn seek(&self, offset: i64, whence: u32) -> Result<u64, Errno> {
        let mut state = self.position.lock().unwrap_or_else(PoisonError::into_inner);
        let base = match whence {
            0 => 0,
            1 => state.position,
            _ => return Err(Errno::EINVAL),
        };
        let target = base.checked_add_signed(offset).ok_or(Errno::EINVAL)?;
        if i64::try_from(target).is_err() {
            return Err(Errno::EINVAL);
        }
        if target != state.position {
            self.walk_to(&mut state, target);
            state.position = target;
        }
        Ok(target)
    }
    /// Size 0, as Linux's /proc: a reader goes by what `read` gives.
    fn stat(&self) -> Result<FileStat, Errno> {
        Ok(stat(0))
    }
    fn truncate(&self, _: u64) -> Result<(), Errno> {
        Err(Errno::EINVAL)
    }
    fn flock(&self, _: u32) -> Result<(), Errno> {
        Ok(())
    }
    fn flags(&self) -> u32 {
        0
    }
    fn set_flags(&self, _: u32) -> Result<(), Errno> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use paludarium_mmu::{AddressSpace, MappingKind};
    use paludarium_types::GuestAddr;

    fn read_all(file: &MapsFile, piece: usize) -> Vec<u8> {
        let mut all = Vec::new();
        let mut buf = vec![0; piece];
        loop {
            let count = file.read(&mut buf).unwrap();
            if count == 0 {
                return all;
            }
            all.extend_from_slice(&buf[..count]);
        }
    }

    #[test]
    fn maps_lines_read_as_linux_writes_them() {
        let mut mem = AddressSpace::new();
        let at = |a: u64| Some(GuestAddr(a));
        mem.map(at(0x1000), 0x1000, Prot::READ, MappingKind::ElfSegment)
            .unwrap();
        mem.map(at(0x5000), 0x2000, Prot::READ_WRITE, MappingKind::Anonymous)
            .unwrap();
        mem.map(at(0x7fff0000), 0x1000, Prot::READ_WRITE, MappingKind::Stack)
            .unwrap();
        let file = MapsFile::open(mem.view(), 0x7fff0800, 0);
        assert_eq!(
            String::from_utf8(read_all(&file, 4096)).unwrap(),
            format!(
                "00001000-00002000 r--p 00000000 00:00 0 \n\
                 00005000-00007000 rw-p 00000000 00:00 0 \n\
                 7fff0000-7fff1000 rw-p 00000000 00:00 0 {}[stack]\n",
                " ".repeat(MAPS_NAME_COLUMN - 40 + 1)
            )
        );
    }

    #[test]
    fn smaps_follows_each_line_with_what_the_vma_holds() {
        let mut mem = AddressSpace::new();
        let at = mem
            .map(
                Some(GuestAddr(0x5000)),
                0x3000,
                Prot::READ_WRITE,
                MappingKind::Anonymous,
            )
            .unwrap();
        mem.map(
            Some(GuestAddr(0x7fff0000)),
            0x1000,
            Prot::READ_WRITE,
            MappingKind::Stack,
        )
        .unwrap();
        // A read shows the zero page, which is not counted; writes are.
        let mut byte = [0];
        mem.read(at, &mut byte).unwrap();
        mem.write(GuestAddr(0x6000), b"x").unwrap();
        mem.write(GuestAddr(0x7000), b"x").unwrap();
        mem.lock(
            GuestAddr(0x7000),
            0x8000,
            Some(paludarium_mmu::Lock::OnFault),
        )
        .unwrap();
        let file = MapsFile::open_as(mem.view(), 0x7fff0800, 0, true);
        let text = String::from_utf8(read_all(&file, 4096)).unwrap();
        let blocks: Vec<&str> = text.split_inclusive("VmFlags:").collect();
        assert!(
            text.starts_with(
                "00005000-00007000 rw-p 00000000 00:00 0 \n\
                 Size:                  8 kB\n\
                 KernelPageSize:        4 kB\n\
                 MMUPageSize:           4 kB\n\
                 Rss:                   4 kB\n\
                 Pss:                   4 kB\n\
                 Pss_Dirty:             4 kB\n\
                 Shared_Clean:          0 kB\n\
                 Shared_Dirty:          0 kB\n\
                 Private_Clean:         0 kB\n\
                 Private_Dirty:         4 kB\n\
                 Referenced:            4 kB\n\
                 Anonymous:             4 kB\n\
                 KSM:                   0 kB\n\
                 LazyFree:              0 kB\n\
                 AnonHugePages:         0 kB\n\
                 ShmemPmdMapped:        0 kB\n\
                 FilePmdMapped:         0 kB\n\
                 Shared_Hugetlb:        0 kB\n\
                 Private_Hugetlb:       0 kB\n\
                 Swap:                  0 kB\n\
                 SwapPss:               0 kB\n\
                 Locked:                0 kB\n\
                 THPeligible:           0\n\
                 VmFlags: rd wr mr mw me ac sd \n"
            ),
            "{text}"
        );
        assert_eq!(blocks.len(), 4, "{text}");
        // The locked page is a VMA of its own, and all of it is locked.
        assert!(text.contains("00007000-00008000 rw-p"), "{text}");
        assert!(
            blocks[1].contains("Locked:                4 kB\n"),
            "{text}"
        );
        assert!(
            text.contains("VmFlags: rd wr mr mw me lo lf ac sd \n"),
            "{text}"
        );
        // The initial stack is not soft-dirty.
        assert!(text.ends_with("VmFlags: rd wr mr mw me gd ac \n"), "{text}");
    }

    #[test]
    fn maps_shows_the_break_as_the_heap_once_it_has_grown() {
        let mut mem = AddressSpace::new();
        mem.set_initial_break(GuestAddr(0x10000));
        let view = mem.view();
        assert_eq!(view.vma_from(0), None);
        mem.set_break(GuestAddr(0x11000));
        let vma = view.vma_from(0).unwrap();
        assert!(vma.heap);
        assert!(map_line(&vma, 0).ends_with(b" [heap]\n"));
    }

    #[test]
    fn maps_escapes_only_a_newline_in_a_name() {
        let vma = Vma {
            start: 0x1000,
            end: 0x2000,
            prot: Prot::READ,
            shared: false,
            offset: 0x3000,
            file: Some(paludarium_mmu::MappedFile {
                name: Some(b"/a b\\c\nd".to_vec()),
                source: true,
                offset: 0x3000,
            }),
            identity: (0x0812, 9),
            heap: false,
            flags: 0,
        };
        let line = map_line(&vma, 0);
        let text = std::str::from_utf8(&line).unwrap();
        assert!(text.starts_with("00001000-00002000 r--p 00003000 08:12 9 "));
        assert_eq!(text.find('/'), Some(MAPS_NAME_COLUMN + 1));
        assert!(text.ends_with("/a b\\c\\012d\n"));
    }

    #[test]
    fn maps_names_shared_anonymous_memory_as_linux_does() {
        let mem = AddressSpace::new();
        let at = mem
            .map_shared(None, 0x1000, Prot::READ_WRITE, MappingKind::Anonymous)
            .unwrap();
        mem.mark_shared(at, 0x1000).unwrap();
        let vma = mem.view().vma_from(0).unwrap();
        let line = String::from_utf8(map_line(&vma, 0)).unwrap();
        assert!(line.contains(" rw-s 00000000 00:01 "), "{line}");
        assert!(line.ends_with(" /dev/zero (deleted)\n"), "{line}");
        assert_ne!(vma.identity.1, 0);
    }

    #[test]
    fn maps_is_generated_as_it_is_read() {
        let mem = AddressSpace::new();
        let map = |at: u64| {
            mem.map_shared(
                Some(GuestAddr(at)),
                0x1000,
                Prot::READ,
                MappingKind::Anonymous,
            )
            .unwrap();
        };
        map(0x10000);
        map(0x30000);
        let file = MapsFile::open(mem.view(), 0, 0);
        let mut buf = [0; 10];
        assert_eq!(file.read(&mut buf).unwrap(), 10);
        // The reader goes on from the VMA it found next, as Linux's does:
        // one made before that is passed by, and one after it is seen.
        map(0x20000);
        map(0x40000);
        let lines = String::from_utf8(read_all(&file, 7)).unwrap();
        let starts: Vec<&str> = lines.lines().map(|line| &line[..8]).collect();
        assert_eq!(starts[1..], ["00030000", "00040000"], "{lines}");
        // Going back reads them all.
        assert_eq!(file.seek(0, 0).unwrap(), 0);
        let all = read_all(&file, 4096);
        assert_eq!(String::from_utf8_lossy(&all).lines().count(), 4);
        assert_eq!(&all[..10], &buf);
    }

    #[test]
    fn maps_reads_whole_lines_up_to_a_page_and_seeks_within_them() {
        let mem = AddressSpace::new();
        for i in 0..200u64 {
            mem.map_shared(
                Some(GuestAddr(0x100000 + i * 0x2000)),
                0x1000,
                Prot::READ,
                MappingKind::Anonymous,
            )
            .unwrap();
        }
        let file = MapsFile::open(mem.view(), 0, 0);
        let whole = read_all(&file, 1 << 16);
        assert_eq!(whole.len(), 200 * 41);
        file.seek(0, 0).unwrap();
        let mut big = vec![0; 1 << 16];
        let first = file.read(&mut big).unwrap();
        assert!((MAPS_BUFFER - 41..MAPS_BUFFER).contains(&first), "{first}");
        assert_eq!(big[first - 1], b'\n');
        // Going forward lands within a line, and past the end reads nothing.
        assert_eq!(file.seek(45, 0).unwrap(), 45);
        assert_eq!(read_all(&file, 100), &whole[45..]);
        assert_eq!(file.seek(-5, 1).unwrap(), whole.len() as u64 - 5);
        assert_eq!(read_all(&file, 100), &whole[whole.len() - 5..]);
        assert_eq!(file.seek(1 << 20, 0).unwrap(), 1 << 20);
        assert_eq!(file.read(&mut big).unwrap(), 0);
        assert_eq!(file.seek(0, 2), Err(Errno::EINVAL));
        assert_eq!(file.seek(-1, 0), Err(Errno::EINVAL));
        assert_eq!(file.stat().unwrap().size, 0);
        assert_eq!(file.write(b"x"), Err(Errno::EBADF));
        assert_eq!(
            MapsFile::open(mem.view(), 0, 2).write(b"x"),
            Err(Errno::EINVAL)
        );
    }

    #[test]
    fn maps_reads_nothing_once_its_space_is_gone() {
        let mem = AddressSpace::new();
        mem.map_shared(None, 0x1000, Prot::READ, MappingKind::Anonymous)
            .unwrap();
        let file = MapsFile::open(mem.view(), 0, 0);
        drop(mem);
        assert_eq!(file.read(&mut [0; 16]).unwrap(), 0);
    }

    #[test]
    fn own_entries_are_this_process_only() {
        assert_eq!(own_entry(b"/proc/self", 7), Some(OwnEntry::Directory));
        assert_eq!(own_entry(b"/proc/7/", 7), Some(OwnEntry::Directory));
        assert_eq!(own_entry(b"/proc/self/status", 7), Some(OwnEntry::Status));
        assert_eq!(own_entry(b"/proc/7/status", 7), Some(OwnEntry::Status));
        assert_eq!(own_entry(b"/proc/self/maps", 7), Some(OwnEntry::Maps));
        assert_eq!(own_entry(b"/proc/7/maps", 7), Some(OwnEntry::Maps));
        assert_eq!(own_entry(b"/proc/8/maps", 7), None);
        assert_eq!(own_entry(b"/proc/8/status", 7), None);
        assert_eq!(own_entry(b"/proc/self/statm", 7), None);
        assert_eq!(own_entry(b"/proc/selfish", 7), None);
    }
    #[test]
    fn task_paths_are_other_processes_and_threads() {
        let path = |p: &[u8]| task_path(p, 7, 9);
        let at = |pid, tid, entry| Some(TaskPath { pid, tid, entry });
        assert_eq!(path(b"/proc/8"), at(8, None, TaskEntry::Directory));
        assert_eq!(path(b"/proc/8/"), at(8, None, TaskEntry::Directory));
        assert_eq!(path(b"/proc/./8/."), at(8, None, TaskEntry::Directory));
        assert_eq!(path(b"/proc/8/task/../stat"), at(8, None, TaskEntry::Stat));
        assert_eq!(path(b"/proc/8/stat"), at(8, None, TaskEntry::Stat));
        assert_eq!(path(b"/proc/8/exe"), at(8, None, TaskEntry::Exe));
        assert_eq!(path(b"/proc/8/environ"), at(8, None, TaskEntry::Environ));
        assert_eq!(
            path(b"/proc/thread-self"),
            at(7, Some(9), TaskEntry::ThreadLink)
        );
        assert_eq!(
            path(b"/proc/thread-self/"),
            at(7, Some(9), TaskEntry::Directory)
        );
        assert_eq!(
            path(b"/proc/thread-self/."),
            at(7, Some(9), TaskEntry::Directory)
        );
        assert_eq!(
            path(b"/proc/thread-self/stat"),
            at(7, Some(9), TaskEntry::Stat)
        );
        assert_eq!(path(b"/proc/8/maps"), at(8, None, TaskEntry::Missing));
        assert_eq!(path(b"/proc/8/fd/1"), at(8, None, TaskEntry::Missing));
        assert_eq!(path(b"/proc/8/task"), at(8, None, TaskEntry::Threads));
        assert_eq!(path(b"/proc/self/task/"), at(7, None, TaskEntry::Threads));
        assert_eq!(
            path(b"/proc/7/task/9"),
            at(7, Some(9), TaskEntry::Directory)
        );
        assert_eq!(
            path(b"/proc/self/task/9/comm"),
            at(7, Some(9), TaskEntry::Comm)
        );
        assert_eq!(
            path(b"/proc/8/task/8/task"),
            at(8, Some(8), TaskEntry::Missing)
        );
        // The reader's own directory is own_entry's; names that are no
        // process are not these.
        for none in [
            &b"/proc/7"[..],
            b"/proc/self/stat",
            b"/proc/7/auxv",
            b"/proc/08",
            b"/proc/0",
            b"/proc/loadavg",
            b"/proc/8/task/x",
            b"/proc/8/task/0",
        ] {
            assert_eq!(path(none), None, "{}", String::from_utf8_lossy(none));
        }
    }
    #[test]
    fn status_has_the_fields_parsers_require() {
        // Tasks 3 and 4 in a PID namespace below the first, as 1 and 2.
        let namespaces = crate::namespaces::Namespaces::default()
            .for_child(
                crate::namespaces::CLONE_NEWPID,
                false,
                crate::users::first(),
            )
            .unwrap();
        namespaces.pid.enter(3, &[]).unwrap();
        namespaces.pid.enter(4, &[]).unwrap();
        let text = String::from_utf8(render_status(&Status {
            name: b"a\\b\nc\0\0",
            umask: Some(0o22),
            state: "S (sleeping)",
            tgid: 3,
            pid: 4,
            parent: 1,
            group_id: 3,
            session: 2,
            space: &namespaces.pid,
            descriptors: Some(70),
            locked: Some(3),
            threads: 2,
            queued: 1,
            queue_limit: 4096,
            pending: 1 << 9,
            blocked: 1 << 9,
            ignored: 1 << 12,
            caught: 1,
            no_new_privs: true,
            seccomp: (2, 3),
            credentials: &crate::credentials::Credentials {
                uid: 1,
                euid: 2,
                suid: 3,
                fsuid: 4,
                groups: vec![5, 6],
                effective: 0,
                inheritable: 0x42,
                ..crate::credentials::Credentials::default()
            },
            reader: crate::users::first(),
        }))
        .unwrap();
        for line in [
            "Name:\ta\\\\b\\nc\n",
            "Umask:\t0022\n",
            "State:\tS (sleeping)\n",
            "Tgid:\t3\n",
            "Pid:\t4\n",
            "PPid:\t1\n",
            "FDSize:\t128\n",
            "Threads:\t2\n",
            "SigQ:\t1/4096\n",
            "SigPnd:\t0000000000000200\n",
            "SigIgn:\t0000000000001000\n",
            "Uid:\t1\t2\t3\t4\n",
            "Gid:\t0\t0\t0\t0\n",
            // In Linux's place, the session's leader outside the namespace.
            "Groups:\t5 6 \nNStgid:\t3\t1\nNSpid:\t4\t2\nNSpgid:\t3\t1\nNSsid:\t2\t0\nVmLck:\t      12 kB\nThreads:",
            "CapInh:\t0000000000000042\n",
            "CapPrm:\t000001ffffffffff\n",
            "CapEff:\t0000000000000000\n",
            "CapBnd:\t000001ffffffffff\n",
            "NoNewPrivs:\t1\nSeccomp:\t2\nSeccomp_filters:\t3\n",
        ] {
            assert!(text.contains(line), "{line:?} in {text}");
        }
        assert!(text.starts_with("Name:"));
    }
    #[test]
    fn mount_table_lines_escape_paths() {
        let mounts = [
            MountPoint {
                path: b"/".to_vec(),
                kind: "tmpfs",
            },
            MountPoint {
                path: b"/my dir".to_vec(),
                kind: "hostfs",
            },
        ];
        assert_eq!(
            String::from_utf8(render(&mounts, true)).unwrap(),
            "21 1 0:1 / / rw,relatime - tmpfs tmpfs rw\n\
             22 21 0:2 / /my\\040dir rw,relatime - hostfs hostfs rw\n"
        );
        assert_eq!(
            String::from_utf8(render(&mounts, false)).unwrap(),
            "tmpfs / tmpfs rw,relatime 0 0\nhostfs /my\\040dir hostfs rw,relatime 0 0\n"
        );
        let file = GeneratedFile::open(b"abc".to_vec(), 0);
        let mut buf = [0; 2];
        assert_eq!(file.read(&mut buf), Ok(2));
        assert_eq!(file.read(&mut buf), Ok(1));
        assert_eq!(file.seek(0, 0), Ok(0));
        assert_eq!(file.read(&mut buf), Ok(2));
        assert_eq!(file.write(b"x"), Err(Errno::EBADF));
        assert_eq!(
            GeneratedFile::open(Vec::new(), 1).write(b"x"),
            Err(Errno::EINVAL)
        );
    }
}

#[cfg(test)]
mod descriptor_tests {
    use super::*;
    #[test]
    fn descriptor_names_are_read_as_linux_reads_them() {
        let entry = |path: &[u8]| own_entry(path, 7);
        assert_eq!(entry(b"/proc/self/fd"), Some(OwnEntry::Descriptors));
        assert_eq!(entry(b"/proc/7/fd/"), Some(OwnEntry::Descriptors));
        assert_eq!(entry(b"/proc/self/fd/0"), Some(OwnEntry::Descriptor(0)));
        assert_eq!(entry(b"/proc/7/fd/12/"), Some(OwnEntry::Descriptor(12)));
        for bad in [
            &b"/proc/self/fd/03"[..],
            b"/proc/self/fd/1a",
            b"/proc/self/fd/4294967296",
            b"/proc/8/fd/1",
        ] {
            assert_eq!(entry(bad), None);
        }
        assert_eq!(link_stat(0).mode, 0o120_500);
        assert_eq!(link_stat(2).mode, 0o120_700);
    }
}

#[cfg(test)]
mod generated_tests {
    use super::*;
    #[test]
    fn own_and_system_entries_are_found_by_name() {
        let entry = |path: &[u8]| own_entry(path, 7);
        assert_eq!(entry(b"/proc/self/stat"), Some(OwnEntry::Stat));
        assert_eq!(entry(b"/proc/7/cmdline"), Some(OwnEntry::Cmdline));
        assert_eq!(entry(b"/proc/self/environ"), Some(OwnEntry::Environ));
        assert_eq!(entry(b"/proc/self/comm"), Some(OwnEntry::Comm));
        assert_eq!(entry(b"/proc/self/exe"), Some(OwnEntry::Exe));
        assert_eq!(entry(b"/proc/self/cwd"), Some(OwnEntry::Cwd));
        assert_eq!(entry(b"/proc/8/stat"), None);
        assert_eq!(system_entry(b"/proc/loadavg"), Some(SystemEntry::Loadavg));
        assert_eq!(system_entry(b"/proc/meminfo"), Some(SystemEntry::Meminfo));
        assert_eq!(system_entry(b"/proc/stat"), Some(SystemEntry::Stat));
        assert_eq!(system_entry(b"/proc/uptime"), Some(SystemEntry::Uptime));
        assert_eq!(system_entry(b"/proc/self/uptime"), None);
    }
    #[test]
    fn stat_has_linux_s_52_fields_after_the_name() {
        let line = render_stat(&ProcessStat {
            pid: 5,
            name: b"a b) \xe9\0junk",
            state: 'R',
            waiting: false,
            exit_signal: 17,
            parent: 1,
            group: 5,
            session: 1,
            terminal: (0, -1),
            cpu: 1_230_000_000,
            children_cpu: 20_000_000,
            nice: 3,
            threads: 2,
            virtual_size: 8192,
            rss_limit: u64::MAX,
            start_stack: 0x7fff_0000,
            start_brk: 0x60_0000,
            arguments: (10, 20),
            environment: (20, 30),
            pending: 0,
            blocked: 512,
            ignored: 2048,
            caught: 1,
        });
        // The name's bytes stay as they are, not UTF-8 encoded.
        assert!(line.starts_with(b"5 (a b) \xe9) R 1 5 1 0 -1 "));
        let line = String::from_utf8_lossy(&line);
        // The fields start after the name's last ')'.
        assert!(line.ends_with(" 0\n"));
        let rest = &line[line.rfind(')').unwrap() + 2..];
        let fields: Vec<&str> = rest.split_whitespace().collect();
        assert_eq!(fields.len() + 2, 52);
        // utime and cutime in USER_HZ ticks; priority, nice, threads.
        assert_eq!(fields[11], "123");
        assert_eq!(fields[13], "2");
        assert_eq!(&fields[15..18], ["23", "3", "2"]);
        assert_eq!(fields[22], "18446744073709551615");
        assert_eq!(&fields[28..32], ["0", "512", "2048", "1"]);
        assert_eq!(fields[35], "17");
        assert_eq!(&fields[45..49], ["10", "20", "20", "30"]);
    }
    #[test]
    fn system_files_have_linux_s_formats() {
        assert_eq!(render_loadavg(1, 4, 9), b"0.00 0.00 0.00 1/4 9\n");
        assert_eq!(render_uptime(1_234_567_891), b"1.23 0.00\n");
        assert_eq!(render_uptime(5_000_000), b"0.00 0.00\n");
        let meminfo = String::from_utf8(render_meminfo(4 << 30)).unwrap();
        let lines: Vec<&str> = meminfo.lines().collect();
        assert_eq!(lines[0], "MemTotal:        4194304 kB");
        assert_eq!(lines[2], "MemAvailable:    4194304 kB");
        assert!(lines.contains(&"SwapTotal:             0 kB"));
        assert!(lines.contains(&"HugePages_Total:       0"));
        assert_eq!(lines.last(), Some(&"Hugetlb:               0 kB"));
        assert_eq!(render_comm(b"name\0rest"), b"name\n");
        let stat = render_system_stat(&SystemStat {
            cpus: 2,
            boot_time: 1_700_000_000,
            forks: 9,
            running: 1,
        });
        assert_eq!(
            String::from_utf8(stat).unwrap(),
            "cpu  0 0 0 0 0 0 0 0 0 0\n\
             cpu0 0 0 0 0 0 0 0 0 0 0\n\
             cpu1 0 0 0 0 0 0 0 0 0 0\n\
             intr 0\n\
             ctxt 0\n\
             btime 1700000000\n\
             processes 9\n\
             procs_running 1\n\
             procs_blocked 0\n\
             softirq 0 0 0 0 0 0 0 0 0 0 0\n"
        );
    }
}
