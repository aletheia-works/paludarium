//! The /proc files paludarium has, generated when opened: the mount table
//! (`/proc/self/mountinfo`, `/proc/mounts`) from the filesystem's mounts,
//! `loadavg`, `meminfo`, `stat` and `uptime`, `/proc/sys` ([`crate::sysctl`]),
//! and this process's directory with its
//! `status`, `stat`, `cmdline`, `comm`, the `exe` and `cwd` links, its `fd`
//! directory of links to the open descriptors, its `ns` directory of links
//! to its namespaces, and its `maps`, which is generated as it is read, as
//! `/proc/sysvipc`'s `msg`, `sem` and `shm` are ([`crate::seq`]).
use paludarium_host::{FileHandle, FileStat};
use paludarium_mmu::{MemoryView, Prot, Usage, Vma, vm};
use paludarium_types::Errno;
use paludarium_vfs::MountPoint;
use std::sync::{Arc, Mutex, PoisonError};

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
/// A system-wide file's `stat` (`/proc/loadavg`, `/proc/sysvipc/shm`): a
/// regular 0444 file of size 0, as Linux's `proc_create` makes them.
pub(crate) fn entry_stat() -> FileStat {
    stat(0)
}
/// `environ`'s `stat`: as [`stat`], but 0400, as Linux keeps it to the
/// process's owner.
pub(crate) fn private_stat(length: usize) -> FileStat {
    FileStat {
        mode: 0o100_400,
        ..stat(length)
    }
}
/// `clear_refs`'s `stat`: a regular 0200 file of size 0, as Linux's.
pub(crate) fn write_only_stat() -> FileStat {
    FileStat {
        mode: 0o100_200,
        ..stat(0)
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
    /// The links to the running program, the current directory and the
    /// root.
    Exe,
    Cwd,
    Root,
    Maps,
    /// `smaps`: `maps` with what each VMA holds and its flags.
    Smaps,
    /// `pagemap`: an entry of 8 bytes for each page ([`PagemapFile`]).
    Pagemap,
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
        b"/root" => Some(OwnEntry::Root),
        b"/maps" => Some(OwnEntry::Maps),
        b"/smaps" => Some(OwnEntry::Smaps),
        b"/pagemap" => Some(OwnEntry::Pagemap),
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
pub(crate) const OWN_NAMES: [(&[u8], u8); 28] = [
    (b"task", 4),
    (b"fd", 4),
    (b"fdinfo", 4),
    (b"ns", 4),
    (b"environ", 8),
    (b"auxv", 8),
    (b"status", 8),
    (b"personality", 8),
    (b"limits", 8),
    (b"comm", 8),
    (b"syscall", 8),
    (b"cmdline", 8),
    (b"stat", 8),
    (b"statm", 8),
    (b"maps", 8),
    (b"cwd", 10),
    (b"root", 10),
    (b"exe", 10),
    (b"mounts", 8),
    (b"mountinfo", 8),
    (b"clear_refs", 8),
    (b"smaps", 8),
    (b"pagemap", 8),
    (b"wchan", 8),
    (b"io", 8),
    (b"uid_map", 8),
    (b"gid_map", 8),
    (b"setgroups", 8),
];
/// The names in another process's directory, in the same order.
pub(crate) const TASK_NAMES: [(&[u8], u8); 28] = [
    (b"task", 4),
    (b"fd", 4),
    (b"fdinfo", 4),
    (b"ns", 4),
    (b"environ", 8),
    (b"auxv", 8),
    (b"status", 8),
    (b"personality", 8),
    (b"limits", 8),
    (b"comm", 8),
    (b"syscall", 8),
    (b"cmdline", 8),
    (b"stat", 8),
    (b"statm", 8),
    (b"maps", 8),
    (b"cwd", 10),
    (b"root", 10),
    (b"exe", 10),
    (b"mounts", 8),
    (b"mountinfo", 8),
    (b"clear_refs", 8),
    (b"smaps", 8),
    (b"pagemap", 8),
    (b"wchan", 8),
    (b"io", 8),
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
    /// `auxv`, the auxiliary vector its program was started with.
    Auxv,
    /// `limits`, its resource limits, and `statm`, its memory in pages.
    Limits,
    Statm,
    Comm,
    Exe,
    Cwd,
    /// `root`, the task's root (`chroot`'s).
    Root,
    /// `maps`, and `smaps` (true), of the task's address space.
    Maps(bool),
    /// `pagemap`, the entry of each page of its address space.
    Pagemap,
    /// `clear_refs`, which a write clears its pages' soft-dirty bits with
    /// ([`ClearRefsFile`]).
    ClearRefs,
    /// `io`, the counts of its reads and writes.
    Io,
    /// `personality`, its execution domain and flags.
    Personality,
    /// `wchan`, where it waits in the kernel.
    Wchan,
    /// `syscall`, the call it is in.
    Syscall,
    /// `fd`, and one of its links by descriptor number.
    Descriptors,
    Descriptor(u32),
    /// `fdinfo`, and its file of a descriptor by number.
    DescriptorInfos,
    DescriptorInfo(u32),
    /// `mountinfo` (true) or `mounts`: the mounts of the task's mount
    /// namespace, from its root.
    Mounts(bool),
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
        b"auxv" => TaskEntry::Auxv,
        b"limits" => TaskEntry::Limits,
        b"statm" => TaskEntry::Statm,
        b"comm" => TaskEntry::Comm,
        b"exe" => TaskEntry::Exe,
        b"cwd" => TaskEntry::Cwd,
        b"root" => TaskEntry::Root,
        b"maps" => TaskEntry::Maps(false),
        b"smaps" => TaskEntry::Maps(true),
        b"pagemap" => TaskEntry::Pagemap,
        b"clear_refs" => TaskEntry::ClearRefs,
        b"io" => TaskEntry::Io,
        b"personality" => TaskEntry::Personality,
        b"wchan" => TaskEntry::Wchan,
        b"syscall" => TaskEntry::Syscall,
        b"mounts" => TaskEntry::Mounts(false),
        b"mountinfo" => TaskEntry::Mounts(true),
        b"ns" => TaskEntry::Namespaces,
        b"uid_map" => TaskEntry::IdMap(crate::users::Ids::User),
        b"gid_map" => TaskEntry::IdMap(crate::users::Ids::Group),
        b"setgroups" => TaskEntry::Setgroups,
        _ => TaskEntry::Missing,
    };
    // An entry of the task's directory, a link of its `ns` or `fd`, or a
    // file of its `fdinfo`.
    let entry = |parts: &[&[u8]]| match parts {
        [b"fd"] => TaskEntry::Descriptors,
        [b"fdinfo"] => TaskEntry::DescriptorInfos,
        [name] => file(name),
        [b"ns", name] => {
            crate::namespaces::Entry::named(name).map_or(TaskEntry::Missing, TaskEntry::Namespace)
        }
        [b"fd", name] => descriptor_number(name).map_or(TaskEntry::Missing, TaskEntry::Descriptor),
        [b"fdinfo", name] => {
            descriptor_number(name).map_or(TaskEntry::Missing, TaskEntry::DescriptorInfo)
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
        // The process's own `ns`, user namespace files, mount tables,
        // `auxv`, `limits`, `statm`, `io`, `personality`, `wchan` and
        // `syscall` are here (`/proc/self/mountinfo`
        // and `mounts` are [`mount_table`]'s); the rest of its own directory
        // is `own_entry`'s.
        [b"ns", ..]
        | [
            b"uid_map" | b"gid_map" | b"setgroups" | b"mounts" | b"mountinfo" | b"auxv" | b"limits"
            | b"statm" | b"io" | b"clear_refs" | b"personality" | b"wchan" | b"syscall",
        ] => (None, entry(&parts)),
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
    /// `/proc/sysvipc`'s `msg`, `sem` and `shm`.
    SysvipcMsg,
    SysvipcSem,
    SysvipcShm,
}
pub(crate) fn system_entry(path: &[u8]) -> Option<SystemEntry> {
    match path {
        b"/proc/loadavg" => Some(SystemEntry::Loadavg),
        b"/proc/meminfo" => Some(SystemEntry::Meminfo),
        b"/proc/stat" => Some(SystemEntry::Stat),
        b"/proc/uptime" => Some(SystemEntry::Uptime),
        _ => match path.strip_prefix(b"/proc/sysvipc/".as_slice())? {
            b"msg" => Some(SystemEntry::SysvipcMsg),
            b"sem" => Some(SystemEntry::SysvipcSem),
            b"shm" => Some(SystemEntry::SysvipcShm),
            _ => None,
        },
    }
}
/// Whether `path` goes on past a system-wide file, as `/proc/loadavg/` or
/// `/proc/sysvipc/msg/x` do, which Linux's walk finds `ENOTDIR`.
pub(crate) fn below_system_entry(path: &[u8]) -> bool {
    path.iter()
        .enumerate()
        .any(|(at, &byte)| byte == b'/' && system_entry(&path[..at]).is_some())
}
/// Whether `path` is `/proc/sysvipc`, the directory of the System V IPC
/// files, which Linux's `ipc_init` makes.
pub(crate) fn is_sysvipc(path: &[u8]) -> bool {
    matches!(path, b"/proc/sysvipc" | b"/proc/sysvipc/")
}
/// The entries of `/proc/sysvipc` after `.` and `..`, in the order Linux's
/// `proc_readdir_de` lists them: by the length of their names, then by
/// name (`proc_match`).
pub(crate) fn sysvipc_entries() -> Vec<paludarium_host::DirectoryEntry> {
    const DT_DIR: u8 = 4;
    const DT_REG: u8 = 8;
    [
        (&b"."[..], DT_DIR),
        (b"..", DT_DIR),
        (b"msg", DT_REG),
        (b"sem", DT_REG),
        (b"shm", DT_REG),
    ]
    .into_iter()
    .enumerate()
    .map(|(i, (name, kind))| paludarium_host::DirectoryEntry {
        name: name.to_vec(),
        inode: i as u64 + 1,
        kind,
    })
    .collect()
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
    /// Whether it has memory, which a zombie no longer has.
    pub memory: bool,
    /// Whether the reader may see where its memory is, as Linux's
    /// `ptrace_may_access(PTRACE_MODE_READ_FSCREDS)` decides.
    pub permitted: bool,
    /// `start_code` and `end_code`, the program's code.
    pub code: (u64, u64),
    /// `start_data` and `end_data`, the program's data.
    pub data: (u64, u64),
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
/// 0 for what nothing measures (page faults, resident memory, start time
/// and the scheduler's figures). A reader that may not see the task's
/// memory gets 1 for `start_code` and `end_code` and 0 for `start_stack`,
/// `wchan` and the addresses from `start_data` on, as Linux hides them;
/// without memory they are all 0.
pub(crate) fn render_stat(s: &ProcessStat<'_>) -> Vec<u8> {
    /// USER_HZ, the unit of the times, as on x86-64 Linux.
    const TICKS: u64 = 100;
    let ticks = |ns: u64| ns / (1_000_000_000 / TICKS);
    let seen = s.memory && s.permitted;
    let code = |at: u64| match (s.memory, s.permitted) {
        (false, _) => 0,
        (true, false) => 1,
        (true, true) => at,
    };
    let address = |at: u64| if seen { at } else { 0 };
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
        code(s.code.0).to_string(),
        code(s.code.1).to_string(),
        address(s.start_stack).to_string(),
        "0".into(), // kstkesp
        "0".into(), // kstkeip
        s.pending.to_string(),
        s.blocked.to_string(),
        s.ignored.to_string(),
        s.caught.to_string(),
        u8::from(s.waiting && s.permitted).to_string(), // wchan
        "0".into(),                                     // nswap
        "0".into(),                                     // cnswap
        s.exit_signal.to_string(),
        "0".into(), // processor
        "0".into(), // rt_priority
        "0".into(), // policy: SCHED_OTHER
        "0".into(), // delayacct_blkio_ticks
        "0".into(), // guest_time
        "0".into(), // cguest_time
        address(s.data.0).to_string(),
        address(s.data.1).to_string(),
        address(s.start_brk).to_string(),
        address(s.arguments.0).to_string(),
        address(s.arguments.1).to_string(),
        address(s.environment.0).to_string(),
        address(s.environment.1).to_string(),
        "0".into(), // exit_code
    ];
    // The name's bytes as they are, as `comm` gives them.
    let mut line = format!("{} (", s.pid).into_bytes();
    line.extend(s.name.iter().take_while(|&&b| b != 0));
    line.extend(format!(") {}\n", fields.join(" ")).into_bytes());
    line
}
/// `/proc/<pid>/statm`, as Linux's `proc_pid_statm` writes `task_statm`'s
/// counts, in pages: the size of the mappings, the resident pages, those of
/// them a file's or shared memory's, the pages of the program's `code`
/// range, 0, the private writable mappings and the stack (`data_vm` and
/// `stack_vm`), and 0; all 0 without memory, as a zombie's.
pub(crate) fn render_statm(memory: Option<&MemoryView>, code: (u64, u64)) -> Vec<u8> {
    const PAGE: u64 = 4096;
    let Some(memory) = memory else {
        return b"0 0 0 0 0 0 0\n".to_vec();
    };
    let (mut size, mut resident, mut shared, mut data) = (0, 0, 0, 0);
    let mut next = 0;
    while let Some(vma) = memory.vma_from(next) {
        let pages = (vma.end - vma.start) / PAGE;
        let usage = memory.usage(vma.start, vma.end).unwrap_or_default();
        size += pages;
        resident += usage.resident;
        shared += usage.resident.saturating_sub(usage.anonymous);
        // Linux's `is_data_mapping` and `is_stack_mapping`.
        let stack = vma.flags & vm::GROWSDOWN != 0;
        if stack || vma.flags & (vm::WRITE | vm::SHARED) == vm::WRITE {
            data += pages;
        }
        next = vma.end;
    }
    // As Linux's `task_statm`, in unsigned arithmetic:
    // `PAGE_ALIGN(end_code) - (start_code & PAGE_MASK)`, in pages.
    let text =
        (code.1.wrapping_add(PAGE - 1) & !(PAGE - 1)).wrapping_sub(code.0 & !(PAGE - 1)) / PAGE;
    format!("{size} {resident} {shared} {text} 0 {data} 0\n").into_bytes()
}
/// `/proc/<pid>/limits`, as Linux's `proc_pid_limits` writes the soft and
/// hard limits, from `RLIMIT_CPU` to `RLIMIT_RTTIME`.
pub(crate) fn render_limits(limits: &[(u64, u64); crate::processes::RLIMITS]) -> Vec<u8> {
    const NAMES: [(&str, &str); crate::processes::RLIMITS] = [
        ("Max cpu time", "seconds"),
        ("Max file size", "bytes"),
        ("Max data size", "bytes"),
        ("Max stack size", "bytes"),
        ("Max core file size", "bytes"),
        ("Max resident set", "bytes"),
        ("Max processes", "processes"),
        ("Max open files", "files"),
        ("Max locked memory", "bytes"),
        ("Max address space", "bytes"),
        ("Max file locks", "locks"),
        ("Max pending signals", "signals"),
        ("Max msgqueue size", "bytes"),
        ("Max nice priority", ""),
        ("Max realtime priority", ""),
        ("Max realtime timeout", "us"),
    ];
    let value = |limit: u64| {
        if limit == u64::MAX {
            "unlimited".to_owned()
        } else {
            limit.to_string()
        }
    };
    let mut text = String::from(
        "Limit                     Soft Limit           Hard Limit           Units     \n",
    );
    for (&(soft, hard), (name, unit)) in limits.iter().zip(NAMES) {
        text.push_str(&format!(
            "{name:<25} {:<20} {:<20} ",
            value(soft),
            value(hard)
        ));
        if unit.is_empty() {
            text.push('\n');
        } else {
            text.push_str(&format!("{unit:<10}\n"));
        }
    }
    text.into_bytes()
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
    /// The process of the tracer, 0 for none.
    pub tracer: u32,
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
         Pid:\t{pid}\nPPid:\t{}\nTracerPid:\t{}\nUid:\t{}\t{}\t{}\t{}\nGid:\t{}\t{}\t{}\t{}\n\
         FDSize:\t{fd_size}\nGroups:\t{groups} \n{numbers}{memory}Threads:\t{}\nSigQ:\t{}/{}\n\
         SigPnd:\t{:016x}\nShdPnd:\t{:016x}\nSigBlk:\t{:016x}\nSigIgn:\t{:016x}\n\
         SigCgt:\t{:016x}\nCapInh:\t{:016x}\nCapPrm:\t{:016x}\n\
         CapEff:\t{:016x}\nCapBnd:\t{:016x}\nCapAmb:\t{:016x}\n\
         NoNewPrivs:\t{}\nSeccomp:\t{}\nSeccomp_filters:\t{}\n\
         voluntary_ctxt_switches:\t0\nnonvoluntary_ctxt_switches:\t0\n",
        s.parent,
        s.tracer,
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
        c.bounding,
        c.ambient,
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
    /// Who owns it at each `fstat`, for a process's directory, as Linux's
    /// `pid_getattr` asks `task_dump_owner` then.
    owner: Option<LiveOwner>,
}
/// The owner of a process's directory as it is now.
pub(crate) type LiveOwner = Arc<dyn Fn() -> (u32, u32) + Send + Sync>;
impl OwnDirectory {
    pub(crate) fn new(stat: FileStat) -> Self {
        Self {
            stat,
            position: Mutex::new(0),
            owner: None,
        }
    }
    /// The same, owned at each `fstat` by whom `owner` gives.
    pub(crate) fn owned_by(self, owner: LiveOwner) -> Self {
        Self {
            owner: Some(owner),
            ..self
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
        Ok(match &self.owner {
            Some(owner) => {
                let (uid, gid) = owner();
                FileStat {
                    uid,
                    gid,
                    ..self.stat
                }
            }
            None => self.stat,
        })
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

/// `mountinfo` or `mounts` lines for `mounts`, as Linux's `show_mountinfo`
/// and `show_vfsmnt` print them; a mount from start-up has its filesystem
/// type as its source, so host paths are not shown. Mount points are shown
/// from `root`, the process's root, and those not under it are left out, as
/// Linux's `seq_path_root` skips them.
pub(crate) fn render(mounts: &[MountPoint], mountinfo: bool, root: &[u8]) -> Vec<u8> {
    let mut out = String::new();
    for mount in mounts {
        let Some(path) = crate::files::seen_from(root, &mount.path) else {
            continue;
        };
        let path = escape(&path);
        let root = escape(&mount.root);
        let source = escape(&mount.source);
        let (kind, options) = (mount.kind, &mount.options);
        let (common, fs) = (&mount.common_options, &mount.super_options);
        let state = |read_only: bool| if read_only { "ro" } else { "rw" };
        if mountinfo {
            let device = mount.device;
            let major = (device >> 8) & 0xfff | (device >> 32) & !0xfff;
            let minor = device & 0xff | (device >> 12) & !0xff;
            let (own, sb) = (state(mount.read_only), state(mount.super_read_only));
            let tags = &mount.tags;
            out.push_str(&format!(
                "{} {} {major}:{minor} {root} {path} {own}{options}{tags} - {kind} {source} {sb}{common}{fs}\n",
                mount.id, mount.parent
            ));
        } else {
            // `show_vfsmnt`: read-only when the mount or its superblock is.
            let both = state(mount.read_only || mount.super_read_only);
            out.push_str(&format!(
                "{source} {path} {kind} {both}{common}{options}{fs} 0 0\n"
            ));
        }
    }
    out.into_bytes()
}

/// The owner a file of a process's `/proc` directory has: Linux's inode's
/// `i_uid` and `i_gid`, which `fstat` of an open one shows.
pub(crate) type Owner = Arc<Mutex<(u32, u32)>>;
/// `stat` with `owner`'s user and group.
pub(crate) fn owned(stat: FileStat, owner: &Owner) -> FileStat {
    let (uid, gid) = *owner.lock().unwrap_or_else(PoisonError::into_inner);
    FileStat { uid, gid, ..stat }
}
/// A file of a process's `/proc` directory as Linux's dentry names it: the
/// process, the thread for one under `task/<tid>` or `thread-self`, and the
/// path below.
pub(crate) type Dentry = (u32, Option<u32>, Vec<u8>);
/// The owners of the open files in the processes' `/proc` directories, one
/// for each [`Dentry`] while a file of it is open, as Linux keeps an inode
/// for the dentry an open file pins: each lookup of the path gives it the
/// owner of that moment (`pid_revalidate`), which `fstat` of every open
/// file of it then shows, until the next.
#[derive(Default)]
pub(crate) struct Owners(Mutex<std::collections::HashMap<Dentry, Inode>>);
/// The owner cell of an open file's inode, gone once no file holds it.
type Inode = std::sync::Weak<Mutex<(u32, u32)>>;
impl Owners {
    /// A lookup of `dentry`, whose owner is now `owner`: the owner of its
    /// inode, the open files' if there are any.
    pub(crate) fn lookup(&self, dentry: Dentry, owner: (u32, u32)) -> Owner {
        let mut inodes = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(inode) = inodes.get(&dentry).and_then(std::sync::Weak::upgrade) {
            *inode.lock().unwrap_or_else(PoisonError::into_inner) = owner;
            return inode;
        }
        inodes.retain(|_, inode| inode.strong_count() > 0);
        let inode = Arc::new(Mutex::new(owner));
        inodes.insert(dentry, Arc::downgrade(&inode));
        inode
    }
}
/// The [`Dentry`] of `path`, under `/proc/<pid>`, `/proc/self` or
/// `/proc/thread-self` (the reading process `own` and thread `own_tid`).
pub(crate) fn dentry(path: &[u8], own: u32, own_tid: u32) -> Option<Dentry> {
    let path = paludarium_vfs::normalize_path(path).ok()?;
    let mut parts = path.strip_prefix(b"/proc/")?.split(|&b| b == b'/');
    let (pid, mut tid) = match parts.next()? {
        b"self" => (own, None),
        b"thread-self" => (own, Some(own_tid)),
        head => (descriptor_number(head).filter(|&pid| pid != 0)?, None),
    };
    let mut rest: Vec<&[u8]> = parts.filter(|part| !part.is_empty()).collect();
    if tid.is_none() && rest.len() >= 2 && rest[0] == b"task" {
        tid = Some(descriptor_number(rest[1])?);
        rest.drain(..2);
    }
    Some((pid, tid, rest.join(&b'/')))
}

thread_local! {
    /// The process and thread whose system call runs on this host thread,
    /// which a write to `comm` and a read of `io` ask of their caller
    /// (Linux's `current`).
    static CALLER: std::cell::Cell<(u32, u32)> = const { std::cell::Cell::new((0, 0)) };
}
/// Records, as a system call starts, the process `pid` and thread `tid` it
/// is of.
pub(crate) fn enter(pid: u32, tid: u32) {
    CALLER.with(|caller| caller.set((pid, tid)));
}
/// The process and thread of the system call running ([`enter`]).
pub(crate) fn caller() -> (u32, u32) {
    CALLER.with(std::cell::Cell::get)
}

/// A file whose contents were fixed when it was opened.
pub(crate) struct GeneratedFile {
    content: Vec<u8>,
    position: Mutex<usize>,
    /// What a write gives on a descriptor opened for writing.
    write_error: Option<Errno>,
    /// A system-wide file, of size 0 as Linux's `proc_create` files are,
    /// whose reads go to the end of its content.
    entry: bool,
    /// The mode and owner `fstat` gives with the content's size, those of
    /// the file it was opened as ([`Self::with_stat`]); a plain 0444 file of
    /// root's without.
    stat: Option<FileStat>,
    /// The owner its inode has now ([`Owners`]), over `stat`'s.
    owner: Option<Owner>,
    /// The thread a write renames, for `comm` ([`Self::renaming`]).
    comm: Option<Comm>,
}
/// The thread whose `comm` a file is.
struct Comm {
    group: Arc<crate::threads::ThreadGroup>,
    pid: u32,
    tid: u32,
}
impl GeneratedFile {
    /// The files are 0444, but the guest is root, which may open them for
    /// writing anyway; the write itself then fails, as on Linux: `EINVAL`
    /// for a process's own file, which has no write operation at all.
    pub(crate) fn open(content: Vec<u8>, flags: u32) -> Self {
        Self::failing_writes(content, flags, Errno::EINVAL, false)
    }
    /// A system-wide file, which Linux makes with `proc_create`: of size 0
    /// ([`entry_stat`]), and its writes go through `proc_reg_write` to
    /// `pde_write`, `EIO` without a `proc_write`.
    pub(crate) fn open_entry(content: Vec<u8>, flags: u32) -> Self {
        Self::failing_writes(content, flags, Errno::EIO, true)
    }
    fn failing_writes(content: Vec<u8>, flags: u32, error: Errno, entry: bool) -> Self {
        Self {
            content,
            position: Mutex::new(0),
            write_error: (flags & 3 != 0).then_some(error),
            entry,
            stat: None,
            owner: None,
            comm: None,
        }
    }
    /// The same, owned by whom its inode's `owner` says when `fstat` asks.
    pub(crate) fn with_owner(self, owner: Owner) -> Self {
        Self {
            owner: Some(owner),
            ..self
        }
    }
    /// `comm` of thread `tid` of process `pid`, of `group`: a write renames
    /// that thread, as Linux's `comm_write`.
    pub(crate) fn renaming(
        self,
        group: Arc<crate::threads::ThreadGroup>,
        pid: u32,
        tid: u32,
    ) -> Self {
        Self {
            comm: Some(Comm { group, pid, tid }),
            ..self
        }
    }
    /// The same, with the mode and owner of `stat`, the file it is
    /// (a process's own file is its owner's, as Linux's `task_dump_owner`).
    pub(crate) fn with_stat(self, stat: FileStat) -> Self {
        Self {
            stat: Some(stat),
            ..self
        }
    }
    /// Whether it is a system-wide file, which reads go to the end of
    /// rather than to its size.
    pub(crate) fn is_entry(&self) -> bool {
        self.entry
    }
}
impl FileHandle for GeneratedFile {
    fn as_any(&self) -> Option<&dyn std::any::Any> {
        Some(self)
    }
    fn read(&self, buf: &mut [u8]) -> Result<usize, Errno> {
        let mut position = self.position.lock().unwrap_or_else(PoisonError::into_inner);
        let rest = self.content.get(*position..).unwrap_or(&[]);
        let count = buf.len().min(rest.len());
        buf[..count].copy_from_slice(&rest[..count]);
        *position += count;
        Ok(count)
    }
    /// These files cannot be written: their error, or EBADF on a
    /// descriptor opened read-only.
    /// `comm` opened for writing renames its thread as Linux's `comm_write`
    /// does: to the first 15 bytes, up to a NUL, when the writer is of the
    /// thread's process, `EINVAL` from any other and `ESRCH` once the thread
    /// is gone; the whole count is taken.
    fn write(&self, b: &[u8]) -> Result<usize, Errno> {
        let error = self.write_error.ok_or(Errno::EBADF)?;
        let Some(comm) = &self.comm else {
            return Err(error);
        };
        if !comm.group.threads().iter().any(|&(tid, _)| tid == comm.tid) {
            return Err(Errno(3)); // ESRCH
        }
        if caller().0 != comm.pid {
            return Err(Errno::EINVAL);
        }
        let mut name = [0; 16];
        for (to, &from) in name
            .iter_mut()
            .zip(b.iter().take(15).take_while(|&&byte| byte != 0))
        {
            *to = from;
        }
        comm.group.rename(comm.tid, name);
        Ok(b.len())
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
        let stat = match self.stat {
            Some(file) => FileStat {
                size: self.content.len() as u64,
                ..file
            },
            None if self.entry => entry_stat(),
            None => stat(self.content.len()),
        };
        Ok(match &self.owner {
            Some(owner) => owned(stat, owner),
            None => stat,
        })
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
fn map_line(vma: &Vma, start_stack: u64, root: &[u8]) -> Vec<u8> {
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
    // A file's name as `d_path` gives it: from the root when it is under
    // it, else from the machine's root.
    let seen;
    let name: &[u8] = match &vma.file {
        Some(file) if file.source => {
            let name = file.name.as_deref().unwrap_or_default();
            seen = crate::files::seen_from(root, name);
            seen.as_deref().unwrap_or(name)
        }
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
/// flags. Pss counts each page for its share of the entries that map it.
/// No page here is huge, swapped or merged by KSM, and the CPU
/// has no protection keys, which leaves out `ProtectionKey`.
fn smap_lines(vma: &Vma, usage: Usage) -> Vec<u8> {
    let kb = |pages: u64| pages * 4;
    let pss = |sum: u64| sum >> Usage::PSS_SHIFT >> 10;
    let pss_all = pss(usage.pss);
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
        ("Pss_Dirty:      ", pss(usage.pss_dirty)),
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
/// Past the last VMA, as Linux's `m_start` is told by its sentinel.
const MAPS_END: u64 = u64::MAX;

/// The lines of `/proc/<pid>/maps` ([`maps_file`]), one for each VMA of the
/// address space it was opened on, by the address it starts at: a read sees
/// the mappings of that moment, from the address it had reached, whatever
/// they were when it was opened.
struct Maps {
    memory: MemoryView,
    start_stack: u64,
    /// It is `smaps`, which follows each line with [`smap_lines`].
    smaps: bool,
    /// The opener's root, from which file names are shown.
    root: Vec<u8>,
}
impl crate::seq::Records for Maps {
    /// The line of the VMA at `next` or after it, and where the next starts.
    fn record(&self, next: u64) -> Result<Option<(Vec<u8>, u64)>, Errno> {
        if next == MAPS_END {
            return Ok(None);
        }
        let Some(vma) = self.memory.vma_from(next) else {
            return Ok(None);
        };
        let after = self.memory.vma_from(vma.end).map_or(MAPS_END, |v| v.start);
        let mut line = map_line(&vma, self.start_stack, &self.root);
        if self.smaps {
            let usage = self.memory.usage(vma.start, vma.end).unwrap_or_default();
            line.extend_from_slice(&smap_lines(&vma, usage));
        }
        Ok(Some((line, after)))
    }
}
/// `/proc/<pid>/maps`, or `smaps` with `smaps`, of `memory`, opened with
/// `flags` and its files named from the opener's `root`: a `seq_file` of
/// [`Maps`], of size 0 and owned by whom its inode's `owner` says when
/// `fstat` asks.
pub(crate) fn maps_file(
    memory: MemoryView,
    start_stack: u64,
    flags: u32,
    root: Vec<u8>,
    smaps: bool,
    owner: Owner,
) -> crate::seq::SeqFile {
    let maps = Maps {
        memory,
        start_stack,
        smaps,
        root,
    };
    crate::seq::SeqFile::of_task(Box::new(maps), flags, stat(0), owner)
}

/// Linux's `TASK_SIZE` with 4-level page tables: where `pagemap` ends.
const PAGEMAP_END: u64 = (1 << 47) - 4096;

/// `/proc/<pid>/pagemap`, as Linux's `pagemap_read` serves it: the entry of
/// each page ([`MemoryView::pagemap`]) at 8 bytes a page, read from the
/// address space it was opened on as it is at that moment. A position and
/// a count must both be whole entries (`EINVAL`), and nothing is read once
/// the space is gone or past the end of user space.
pub(crate) struct PagemapFile {
    memory: MemoryView,
    writable: bool,
    position: Mutex<u64>,
    /// Its inode's owner, as `fstat` shows it.
    owner: Owner,
}
impl PagemapFile {
    pub(crate) fn open(memory: MemoryView, flags: u32, owner: Owner) -> Self {
        Self {
            memory,
            writable: flags & 3 != 0,
            position: Mutex::new(0),
            owner,
        }
    }
}
impl FileHandle for PagemapFile {
    fn as_any(&self) -> Option<&dyn std::any::Any> {
        Some(self)
    }
    fn read(&self, buf: &mut [u8]) -> Result<usize, Errno> {
        let mut position = self.position.lock().unwrap_or_else(PoisonError::into_inner);
        let count = self.read_at(*position, buf)?;
        *position += count as u64;
        Ok(count)
    }
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, Errno> {
        // A position past `i64::MAX` is a negative one, which the VFS
        // refuses (`rw_verify_area`).
        if i64::try_from(offset).is_err() {
            return Err(Errno::EINVAL);
        }
        // Gone: `mmget_not_zero` fails before any check.
        if self.memory.pagemap(0, 0).is_none() {
            return Ok(0);
        }
        if !offset.is_multiple_of(8) || !buf.len().is_multiple_of(8) {
            return Err(Errno::EINVAL);
        }
        let start = (offset / 8).saturating_mul(4096);
        if buf.is_empty() || start >= PAGEMAP_END {
            return Ok(0);
        }
        let end = start
            .checked_add(buf.len() as u64 / 8 * 4096)
            .filter(|&end| end < PAGEMAP_END)
            .unwrap_or(PAGEMAP_END);
        let Some(entries) = self.memory.pagemap(start, (end - start) / 4096) else {
            return Ok(0);
        };
        for (slot, entry) in buf.as_chunks_mut::<8>().0.iter_mut().zip(&entries) {
            *slot = entry.to_le_bytes();
        }
        Ok(entries.len() * 8)
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
    /// As Linux's `mem_lseek`: from the start or the current position, to
    /// any position, a negative one too, never from the end.
    fn seek(&self, offset: i64, whence: u32) -> Result<u64, Errno> {
        let mut position = self.position.lock().unwrap_or_else(PoisonError::into_inner);
        *position = match whence {
            0 => offset as u64,
            1 => position.wrapping_add_signed(offset),
            _ => return Err(Errno::EINVAL),
        };
        Ok(*position)
    }
    /// Size 0 and only its owner may read it, as Linux's (0400).
    fn stat(&self) -> Result<FileStat, Errno> {
        Ok(owned(private_stat(0), &self.owner))
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

/// The address space `clear_refs` acts on at a write: the task's then,
/// `None` once it has none (a zombie), or `ESRCH` once it is gone.
pub(crate) type CurrentMemory = Arc<dyn Fn() -> Result<Option<MemoryView>, Errno> + Send + Sync>;
/// `/proc/<pid>/clear_refs`, as Linux's `clear_refs_write` takes a write:
/// at most 12 bytes of it (`PROC_NUMBUF` less one), which is what it
/// returns, are a number as `kstrtoint` reads one, from 1 to 5 (`EINVAL`
/// otherwise); then the task, which must still be there (`ESRCH`), has
/// its address space changed if it has one. Only 4
/// (`CLEAR_REFS_SOFT_DIRTY`) changes what can be seen here
/// ([`MemoryView::clear_soft_dirty`]); 1 to 3 clear referenced bits, which
/// are not kept, and 5 the peak resident size, which is not shown. It has
/// no read operation.
pub(crate) struct ClearRefsFile {
    memory: CurrentMemory,
    /// The access mode it was opened with (`O_ACCMODE`).
    access: u32,
    readable: bool,
    writable: bool,
    /// Its inode's owner, as `fstat` shows it.
    owner: Owner,
}
impl ClearRefsFile {
    pub(crate) fn open(memory: CurrentMemory, flags: u32, owner: Owner) -> Self {
        Self {
            memory,
            access: flags & 3,
            readable: flags & 3 != 1,
            writable: flags & 3 != 0,
            owner,
        }
    }
}
/// The kernel's `isspace`, which takes the Latin-1 no-break space too.
fn kernel_space(b: u8) -> bool {
    matches!(b, b' ' | b'\t'..=b'\r' | 0xa0)
}
/// `kstrtoint` in base 10 of `text` with its spaces stripped (`strstrip`):
/// a sign and digits; `EINVAL` for anything else, and
/// `ERANGE` for a number past an `int`.
fn clear_refs_number(text: &[u8]) -> Result<i64, Errno> {
    let end = text
        .iter()
        .rposition(|&b| !kernel_space(b))
        .map_or(0, |at| at + 1);
    let start = text[..end]
        .iter()
        .position(|&b| !kernel_space(b))
        .unwrap_or(end);
    let text = &text[start..end];
    let (negative, digits) = match text {
        [b'-', rest @ ..] => (true, rest),
        [b'+', rest @ ..] => (false, rest),
        _ => (false, text),
    };
    let count = digits.iter().take_while(|b| b.is_ascii_digit()).count();
    // `kstrtoint`'s one newline is gone with the spaces.
    if count == 0 || count != digits.len() {
        return Err(Errno::EINVAL);
    }
    // At most 12 digits, which an `i64` holds.
    let value = digits[..count]
        .iter()
        .fold(0i64, |value, &b| value * 10 + i64::from(b - b'0'));
    let value = if negative { -value } else { value };
    i32::try_from(value).map_err(|_| Errno(34))?; // ERANGE
    Ok(value)
}
impl FileHandle for ClearRefsFile {
    fn as_any(&self) -> Option<&dyn std::any::Any> {
        Some(self)
    }
    fn read(&self, _: &mut [u8]) -> Result<usize, Errno> {
        Err(if self.readable {
            Errno::EINVAL
        } else {
            Errno::EBADF
        })
    }
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, Errno> {
        let _ = offset;
        self.read(buf)
    }
    fn write(&self, buf: &[u8]) -> Result<usize, Errno> {
        if !self.writable {
            return Err(Errno::EBADF);
        }
        let count = buf.len().min(12);
        let text = &buf[..count];
        // The bytes are a C string in a zeroed buffer.
        let text = &text[..text.iter().position(|&b| b == 0).unwrap_or(count)];
        let kind = clear_refs_number(text)?;
        if !(1..=5).contains(&kind) {
            return Err(Errno::EINVAL);
        }
        if let Some(memory) = (self.memory)()?
            && kind == 4
        {
            memory.clear_soft_dirty();
        }
        Ok(count)
    }
    fn write_at(&self, _: u64, buf: &[u8]) -> Result<usize, Errno> {
        self.write(buf)
    }
    /// Linux's `noop_llseek`: the position stays 0.
    fn seek(&self, _: i64, _: u32) -> Result<u64, Errno> {
        Ok(0)
    }
    /// Size 0, and only its owner may write it, as Linux's (0200).
    fn stat(&self) -> Result<FileStat, Errno> {
        Ok(owned(write_only_stat(), &self.owner))
    }
    fn truncate(&self, _: u64) -> Result<(), Errno> {
        Err(Errno::EINVAL)
    }
    fn flock(&self, _: u32) -> Result<(), Errno> {
        Ok(())
    }
    fn flags(&self) -> u32 {
        self.access
    }
    fn set_flags(&self, _: u32) -> Result<(), Errno> {
        Ok(())
    }
}

/// What makes a file's text when it is read ([`single_file`]).
pub(crate) type Text = Arc<dyn Fn() -> Result<Vec<u8>, Errno> + Send + Sync>;
/// The one record of a [`single_file`].
struct Single(Text);
impl crate::seq::Records for Single {
    fn record(&self, index: u64) -> Result<Option<(Vec<u8>, u64)>, Errno> {
        if index > 0 {
            return Ok(None);
        }
        (self.0)().map(|text| Some((text, 1)))
    }
}
/// A file whose text `text` makes when it is first read, and again after a
/// seek to another place, as Linux's `seq_file` of one record
/// (`single_open`) makes it then, with what its checks say at that moment:
/// `io`, `personality`, `wchan` and `syscall`, of size 0 and with the mode
/// of `stat`.
pub(crate) fn single_file(
    text: Text,
    flags: u32,
    stat: FileStat,
    owner: Owner,
) -> crate::seq::SeqFile {
    crate::seq::SeqFile::of_task(Box::new(Single(text)), flags, stat, owner)
}

#[cfg(test)]
mod tests {
    use super::*;
    use paludarium_mmu::{AddressSpace, MappingKind};
    use paludarium_types::GuestAddr;

    fn read_all(file: &crate::seq::SeqFile, piece: usize) -> Vec<u8> {
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
        let file = maps_file(
            mem.view(),
            0x7fff0800,
            0,
            b"/".to_vec(),
            false,
            Owner::default(),
        );
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

    /// The entries `file` gives from the page at `addr`, `count` of them.
    fn pagemap_entries(file: &PagemapFile, addr: u64, count: usize) -> Vec<u64> {
        let mut buf = vec![0; count * 8];
        let n = file.read_at(addr / 4096 * 8, &mut buf).unwrap();
        buf[..n]
            .as_chunks::<8>()
            .0
            .iter()
            .map(|b| u64::from_le_bytes(*b))
            .collect()
    }

    #[test]
    fn pagemap_says_what_each_page_table_entry_holds() {
        use paludarium_mmu::pagemap::{EXCLUSIVE, GUARD_REGION, PRESENT, SOFT_DIRTY, SWAP};
        let mut mem = AddressSpace::new();
        let at = mem
            .map(
                Some(GuestAddr(0x10000)),
                0x5000,
                Prot::READ_WRITE,
                MappingKind::Anonymous,
            )
            .unwrap();
        let mut byte = [0];
        mem.read(GuestAddr(0x11000), &mut byte).unwrap();
        mem.write(GuestAddr(0x12000), b"x").unwrap();
        mem.guard(GuestAddr(0x13000), 0x14000, true).unwrap();
        let file = PagemapFile::open(mem.view(), 0, Arc::default());
        assert_eq!(
            pagemap_entries(&file, at.0 - 0x1000, 7),
            [
                0,
                SOFT_DIRTY,
                SOFT_DIRTY | PRESENT,
                SOFT_DIRTY | PRESENT | EXCLUSIVE,
                SOFT_DIRTY | SWAP | GUARD_REGION,
                SOFT_DIRTY,
                0,
            ]
        );
        // `fork` shares the written page until either writes it.
        let child = mem.fork();
        assert_eq!(pagemap_entries(&file, 0x12000, 1), [SOFT_DIRTY | PRESENT]);
        let theirs = PagemapFile::open(child.view(), 0, Arc::default());
        assert_eq!(pagemap_entries(&theirs, 0x12000, 1), [SOFT_DIRTY | PRESENT]);
        child.write(GuestAddr(0x12000), b"y").unwrap();
        assert_eq!(
            pagemap_entries(&theirs, 0x12000, 1),
            [SOFT_DIRTY | PRESENT | EXCLUSIVE]
        );
    }

    #[test]
    fn clear_refs_cleans_every_page_until_its_next_write() {
        use paludarium_mmu::pagemap::{EXCLUSIVE, PRESENT, SOFT_DIRTY};
        let mut mem = AddressSpace::new();
        mem.map(
            Some(GuestAddr(0x10000)),
            0x4000,
            Prot::READ_WRITE,
            MappingKind::Anonymous,
        )
        .unwrap();
        let mut byte = [0];
        mem.read(GuestAddr(0x10000), &mut byte).unwrap();
        mem.write(GuestAddr(0x11000), b"x").unwrap();
        mem.write(GuestAddr(0x12000), b"x").unwrap();
        let view = mem.view();
        let current: CurrentMemory = Arc::new(move || Ok(Some(view.clone())));
        let clear = ClearRefsFile::open(current, 1, Arc::default());
        let file = PagemapFile::open(mem.view(), 0, Arc::default());
        assert_eq!(clear.write(b"4\n"), Ok(2));
        let written = PRESENT | EXCLUSIVE;
        assert_eq!(
            pagemap_entries(&file, 0x10000, 4),
            [PRESENT, written, written, 0]
        );
        // The next write sets it again, the one this thread's TLB held the
        // page for too.
        mem.write(GuestAddr(0x12000), b"y").unwrap();
        mem.write(GuestAddr(0x10000), b"y").unwrap();
        let dirty = SOFT_DIRTY | written;
        assert_eq!(
            pagemap_entries(&file, 0x10000, 4),
            [dirty, written, dirty, 0]
        );
        // A new mapping merges with it: the VMA is soft-dirty, and stays so
        // when the new part goes again.
        mem.map(
            Some(GuestAddr(0x14000)),
            0x1000,
            Prot::READ_WRITE,
            MappingKind::Anonymous,
        )
        .unwrap();
        mem.mapped(GuestAddr(0x14000), 0x15000);
        mem.unmap(GuestAddr(0x14000), 0x1000).unwrap();
        assert_eq!(
            pagemap_entries(&file, 0x11000, 3),
            [dirty, dirty, SOFT_DIRTY]
        );
        // Each page `fork` copies keeps its bit.
        assert_eq!(clear.write(b"4"), Ok(1));
        mem.write(GuestAddr(0x11000), b"z").unwrap();
        let child = mem.fork();
        let theirs = PagemapFile::open(child.view(), 0, Arc::default());
        assert_eq!(
            pagemap_entries(&theirs, 0x10000, 3)
                .iter()
                .map(|e| e & SOFT_DIRTY)
                .collect::<Vec<_>>(),
            [0, SOFT_DIRTY, 0]
        );
    }

    #[test]
    fn clear_refs_takes_a_number_as_kstrtoint_reads_one() {
        let mem = AddressSpace::new();
        let view = mem.view();
        let current: CurrentMemory = Arc::new(move || Ok(Some(view.clone())));
        let clear = ClearRefsFile::open(current, 1, Arc::default());
        assert_eq!(clear.write(b" +4 \n"), Ok(5));
        assert_eq!(clear.write(b"\xa05\0junk"), Ok(7));
        assert_eq!(clear.write(b"1           and more"), Ok(12));
        for bad in [&b""[..], b"0", b"6", b"-1", b"4x", b"0x4", b"--4", b" "] {
            assert_eq!(clear.write(bad), Err(Errno::EINVAL), "{bad:?}");
        }
        assert_eq!(clear.write(b"99999999999"), Err(Errno(34)));
        assert_eq!(clear.write(b"-2147483649"), Err(Errno(34)));
        assert_eq!(clear.write(b"-2147483648"), Err(Errno::EINVAL));
        let mut buf = [0; 4];
        assert_eq!(clear.read(&mut buf), Err(Errno::EBADF));
        // The number is read before the task is looked for.
        let gone: CurrentMemory = Arc::new(|| Err(Errno(3)));
        let gone = ClearRefsFile::open(gone, 2, Arc::default());
        assert_eq!(gone.write(b"7"), Err(Errno::EINVAL));
        assert_eq!(gone.write(b"4"), Err(Errno(3)));
        assert_eq!(gone.read(&mut buf), Err(Errno::EINVAL));
        assert_eq!(gone.stat().map(|s| s.mode), Ok(0o100_200));
        let read_only = ClearRefsFile::open(Arc::new(|| Ok(None)), 0, Arc::default());
        assert_eq!(read_only.write(b"4"), Err(Errno::EBADF));
    }

    #[test]
    fn pagemap_reads_whole_entries_up_to_the_end_of_user_space() {
        let mem = AddressSpace::new();
        let file = PagemapFile::open(mem.view(), 0, Arc::default());
        let mut buf = [0xffu8; 16];
        assert_eq!(file.read_at(4, &mut buf[..8]), Err(Errno::EINVAL));
        assert_eq!(file.read_at(8, &mut buf[..12]), Err(Errno::EINVAL));
        assert_eq!(file.read_at(8, &mut buf[..0]), Ok(0));
        assert_eq!(file.read_at(8, &mut buf), Ok(16));
        assert_eq!(buf, [0; 16]);
        // The last page of user space, and nothing after it.
        let last = (PAGEMAP_END / 4096 - 1) * 8;
        assert_eq!(file.read_at(last, &mut buf), Ok(8));
        assert_eq!(file.read_at(last + 8, &mut buf), Ok(0));
        assert_eq!(file.read_at(u64::MAX / 16 * 8, &mut buf), Ok(0));
        // A negative position is taken, and is no position to read from.
        assert_eq!(file.seek(-8, 0), Ok((-8i64) as u64));
        assert_eq!(file.read(&mut buf), Err(Errno::EINVAL));
        assert_eq!(file.seek(16, 1), Ok(8));
        assert_eq!(file.read(&mut buf), Ok(16));
        assert_eq!(file.seek(0, 1), Ok(24));
        assert_eq!(file.seek(0, 2), Err(Errno::EINVAL));
        // Nothing once the space is gone.
        drop(mem);
        assert_eq!(file.read_at(4, &mut buf), Ok(0));
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
        let file = maps_file(
            mem.view(),
            0x7fff0800,
            0,
            b"/".to_vec(),
            true,
            Owner::default(),
        );
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
        assert!(map_line(&vma, 0, b"/").ends_with(b" [heap]\n"));
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
        let line = map_line(&vma, 0, b"/");
        let text = std::str::from_utf8(&line).unwrap();
        assert!(text.starts_with("00001000-00002000 r--p 00003000 08:12 9 "));
        assert_eq!(text.find('/'), Some(MAPS_NAME_COLUMN + 1));
        assert!(text.ends_with("/a b\\c\\012d\n"));
        // Under a root, from there; elsewhere, from the machine's root.
        assert!(map_line(&vma, 0, b"/a b").ends_with(b" /a b\\c\\012d\n"));
        let mut inside = vma.clone();
        inside.file.as_mut().unwrap().name = Some(b"/jail/lib/x".to_vec());
        assert!(map_line(&inside, 0, b"/jail").ends_with(b" /lib/x\n"));
        assert!(map_line(&inside, 0, b"/jai").ends_with(b" /jail/lib/x\n"));
    }

    #[test]
    fn maps_names_shared_anonymous_memory_as_linux_does() {
        let mem = AddressSpace::new();
        let at = mem
            .map_shared(None, 0x1000, Prot::READ_WRITE, MappingKind::Anonymous)
            .unwrap();
        mem.mark_shared(at, 0x1000).unwrap();
        let vma = mem.view().vma_from(0).unwrap();
        let line = String::from_utf8(map_line(&vma, 0, b"/")).unwrap();
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
        let file = maps_file(mem.view(), 0, 0, b"/".to_vec(), false, Owner::default());
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
        let file = maps_file(mem.view(), 0, 0, b"/".to_vec(), false, Owner::default());
        let whole = read_all(&file, 1 << 16);
        assert_eq!(whole.len(), 200 * 41);
        file.seek(0, 0).unwrap();
        let mut big = vec![0; 1 << 16];
        let first = file.read(&mut big).unwrap();
        assert!((4096 - 41..4096).contains(&first), "{first}");
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
            maps_file(mem.view(), 0, 2, b"/".to_vec(), false, Owner::default()).write(b"x"),
            Err(Errno::EINVAL)
        );
    }

    #[test]
    fn maps_reads_nothing_once_its_space_is_gone() {
        let mem = AddressSpace::new();
        mem.map_shared(None, 0x1000, Prot::READ, MappingKind::Anonymous)
            .unwrap();
        let file = maps_file(mem.view(), 0, 0, b"/".to_vec(), false, Owner::default());
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
    fn dentries_name_a_file_of_a_process_or_thread() {
        let at = |path: &[u8]| dentry(path, 7, 9);
        assert_eq!(
            at(b"/proc/self/status"),
            Some((7, None, b"status".to_vec()))
        );
        assert_eq!(at(b"/proc/7/status"), at(b"/proc/self/status"));
        assert_eq!(
            at(b"/proc/thread-self/comm"),
            Some((7, Some(9), b"comm".to_vec()))
        );
        assert_eq!(at(b"/proc/7/task/9/comm"), at(b"/proc/thread-self/comm"));
        assert_eq!(at(b"/proc/8/fd/3"), Some((8, None, b"fd/3".to_vec())));
        assert_eq!(at(b"/proc/8/"), Some((8, None, Vec::new())));
        assert_eq!(at(b"/proc/loadavg"), None);
        assert_eq!(at(b"/proc/0/status"), None);
    }
    #[test]
    fn a_lookup_gives_the_open_files_inode_its_owner() {
        let owners = Owners::default();
        let key = || (8, None, b"status".to_vec());
        let open = owners.lookup(key(), (1000, 1000));
        // Another lookup of the path, after the task changed its IDs, while
        // the file is open: the same inode, with the owner of that moment.
        let again = owners.lookup(key(), (0, 0));
        assert!(Arc::ptr_eq(&open, &again));
        assert_eq!(*open.lock().unwrap(), (0, 0));
        // Once no file holds it, a lookup makes a new one.
        drop((open, again));
        assert_eq!(*owners.lookup(key(), (5, 5)).lock().unwrap(), (5, 5));
    }
    #[test]
    fn limits_are_as_linux_writes_them() {
        let mut limits = [(u64::MAX, u64::MAX); crate::processes::RLIMITS];
        limits[7] = (1024, 4096);
        limits[13] = (0, 0);
        let text = String::from_utf8(render_limits(&limits)).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 17);
        assert_eq!(
            lines[0],
            "Limit                     Soft Limit           Hard Limit           Units     "
        );
        assert_eq!(
            lines[1],
            "Max cpu time              unlimited            unlimited            seconds   "
        );
        assert_eq!(
            lines[8],
            "Max open files            1024                 4096                 files     "
        );
        assert_eq!(
            lines[14],
            "Max nice priority         0                    0                    "
        );
        assert!(text.ends_with("us        \n"), "{text}");
    }
    #[test]
    fn statm_counts_pages() {
        use paludarium_mmu::{AddressSpace, MappingKind};
        assert_eq!(render_statm(None, (0x1000, 0x2000)), b"0 0 0 0 0 0 0\n");
        let mut mem = AddressSpace::new();
        let at = mem
            .map(None, 3 * 4096, Prot::READ_WRITE, MappingKind::Anonymous)
            .unwrap();
        mem.map(None, 4096, Prot::READ, MappingKind::Anonymous)
            .unwrap();
        mem.write(at, &[1]).unwrap();
        mem.write(GuestAddr(at.0 + 4096), &[1]).unwrap();
        assert_eq!(render_statm(Some(&mem.view()), (0, 0)), b"4 2 0 0 0 3 0\n");
        // The code's pages, from the page of its start to its end's.
        assert_eq!(
            render_statm(Some(&mem.view()), (0x40_1000, 0x40_5abc)),
            b"4 2 0 5 0 3 0\n"
        );
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
        assert_eq!(path(b"/proc/8/root"), at(8, None, TaskEntry::Root));
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
        // Every task's mount tables, the reader's own too.
        assert_eq!(
            path(b"/proc/8/mountinfo"),
            at(8, None, TaskEntry::Mounts(true))
        );
        assert_eq!(
            path(b"/proc/7/mounts"),
            at(7, None, TaskEntry::Mounts(false))
        );
        assert_eq!(
            path(b"/proc/thread-self/mountinfo"),
            at(7, Some(9), TaskEntry::Mounts(true))
        );
        assert_eq!(
            path(b"/proc/8/task/8/mounts"),
            at(8, Some(8), TaskEntry::Mounts(false))
        );
        assert_eq!(path(b"/proc/8/maps"), at(8, None, TaskEntry::Maps(false)));
        assert_eq!(
            path(b"/proc/7/task/9/smaps"),
            at(7, Some(9), TaskEntry::Maps(true))
        );
        assert_eq!(path(b"/proc/8/pagemap"), at(8, None, TaskEntry::Pagemap));
        assert_eq!(
            path(b"/proc/thread-self/pagemap"),
            at(7, Some(9), TaskEntry::Pagemap)
        );
        // `auxv`, `limits` and `statm` of every task, the reader's own too.
        assert_eq!(path(b"/proc/8/statm"), at(8, None, TaskEntry::Statm));
        assert_eq!(path(b"/proc/7/auxv"), at(7, None, TaskEntry::Auxv));
        assert_eq!(path(b"/proc/self/limits"), at(7, None, TaskEntry::Limits));
        assert_eq!(
            path(b"/proc/8/task/8/auxv"),
            at(8, Some(8), TaskEntry::Auxv)
        );
        assert_eq!(path(b"/proc/8/stack"), at(8, None, TaskEntry::Missing));
        assert_eq!(
            path(b"/proc/8/personality"),
            at(8, None, TaskEntry::Personality)
        );
        assert_eq!(path(b"/proc/self/wchan"), at(7, None, TaskEntry::Wchan));
        assert_eq!(
            path(b"/proc/8/task/9/syscall"),
            at(8, Some(9), TaskEntry::Syscall)
        );
        assert_eq!(path(b"/proc/8/fd/1"), at(8, None, TaskEntry::Descriptor(1)));
        assert_eq!(path(b"/proc/8/fd/"), at(8, None, TaskEntry::Descriptors));
        assert_eq!(
            path(b"/proc/8/fdinfo/12"),
            at(8, None, TaskEntry::DescriptorInfo(12))
        );
        assert_eq!(
            path(b"/proc/thread-self/fdinfo"),
            at(7, Some(9), TaskEntry::DescriptorInfos)
        );
        assert_eq!(path(b"/proc/8/fd/01"), at(8, None, TaskEntry::Missing));
        assert_eq!(path(b"/proc/8/fd/1/x"), at(8, None, TaskEntry::Missing));
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
            b"/proc/7/stack",
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
            tracer: 0,
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
                bounding: 0xfff,
                ambient: 0x2,
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
            "CapBnd:\t0000000000000fff\n",
            "CapAmb:\t0000000000000002\n",
            "NoNewPrivs:\t1\nSeccomp:\t2\nSeccomp_filters:\t3\n",
        ] {
            assert!(text.contains(line), "{line:?} in {text}");
        }
        assert!(text.starts_with("Name:"));
    }
    #[test]
    fn mount_table_lines_escape_paths() {
        let mounts = [
            MountPoint::boot(0, b"/".to_vec(), "tmpfs"),
            MountPoint::boot(1, b"/my dir".to_vec(), "hostfs"),
        ];
        assert_eq!(
            String::from_utf8(render(&mounts, true, b"/")).unwrap(),
            "21 1 0:1 / / rw,relatime - tmpfs tmpfs rw\n\
             22 21 0:2 / /my\\040dir rw,relatime - hostfs hostfs rw\n"
        );
        assert_eq!(
            String::from_utf8(render(&mounts, false, b"/")).unwrap(),
            "tmpfs / tmpfs rw,relatime 0 0\nhostfs /my\\040dir hostfs rw,relatime 0 0\n"
        );
        // From a root, only the mounts at or under it, from there.
        assert_eq!(
            String::from_utf8(render(&mounts, true, b"/my dir")).unwrap(),
            "22 21 0:2 / / rw,relatime - hostfs hostfs rw\n"
        );
        assert_eq!(render(&mounts, false, b"/my"), b"");
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
        assert_eq!(entry(b"/proc/self/root"), Some(OwnEntry::Root));
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
            memory: true,
            permitted: true,
            code: (0x40_1000, 0x40_5abc),
            data: (0x40_6000, 0x40_7010),
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
        assert_eq!(&fields[23..25], ["4198400", "4217532"]);
        assert_eq!(&fields[28..32], ["0", "512", "2048", "1"]);
        assert_eq!(fields[35], "17");
        assert_eq!(&fields[42..44], ["4218880", "4222992"]);
        assert_eq!(&fields[45..49], ["10", "20", "20", "30"]);
    }
    #[test]
    fn stat_hides_where_the_memory_is_from_a_reader_that_may_not_see_it() {
        let stat = |memory, permitted| {
            let line = render_stat(&ProcessStat {
                pid: 5,
                name: b"a",
                state: 'S',
                waiting: true,
                exit_signal: 17,
                parent: 1,
                group: 5,
                session: 1,
                terminal: (0, -1),
                cpu: 0,
                children_cpu: 0,
                nice: 0,
                threads: 1,
                virtual_size: 8192,
                rss_limit: 0,
                memory,
                permitted,
                code: (2, 3),
                data: (4, 5),
                start_stack: 6,
                start_brk: 7,
                arguments: (8, 9),
                environment: (10, 11),
                pending: 0,
                blocked: 0,
                ignored: 0,
                caught: 0,
            });
            let line = String::from_utf8(line).unwrap();
            let fields: Vec<String> = line.split_whitespace().map(String::from).collect();
            // start_code, end_code, start_stack; wchan; 45 to 51.
            let mut shown = fields[25..28].to_vec();
            shown.push(fields[34].clone());
            shown.extend_from_slice(&fields[44..51]);
            shown.join(" ")
        };
        assert_eq!(stat(true, true), "2 3 6 1 4 5 7 8 9 10 11");
        assert_eq!(stat(true, false), "1 1 0 0 0 0 0 0 0 0 0");
        assert_eq!(stat(false, true), "0 0 0 1 0 0 0 0 0 0 0");
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
