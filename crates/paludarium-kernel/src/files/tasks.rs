//! The /proc directories of other processes, the `task` directories of
//! threads, and the listing of /proc itself, as Linux's `fs/proc/base.c`
//! and `array.c` show them to root: generated from what each thread
//! publishes at its checkpoints ([`crate::threads::PublicThread`]).
use super::{BLOCK_SIZE, SMALL_BLOCK_SIZE, device};
use crate::proc::{TaskEntry, TaskPath};
use crate::processes::ProcessView;
use crate::syscalls::Context;
use crate::threads::PublicThread;
use paludarium_host::{DirectoryEntry, FileStat};
use paludarium_types::Errno;

const DT_DIR: u8 = 4;
const DT_REG: u8 = 8;
const DT_LNK: u8 = 10;

/// The thread a [`TaskPath`] names, the leader for a process's own entries,
/// with what /proc shows of it.
pub(super) struct Task {
    pid: u32,
    tid: u32,
    /// The path is under `task`, naming the thread rather than the process.
    thread: bool,
    view: ProcessView,
    public: PublicThread,
    /// The state's letter and its name in `status`.
    state: (char, &'static str),
}

/// The thread of `path`: ENOENT for a process that is not there (reaped,
/// or never was) and for a thread not in it. A thread's ID other than its
/// process's names a directory too, which /proc does not list, as on Linux:
/// that of the process, as the thread sees it.
pub(super) fn find(c: &Context<'_>, path: &TaskPath) -> Result<Task, Errno> {
    let (view, pid) = match c.processes.view(path.pid) {
        Some(view) => (view, path.pid),
        None => {
            let pid = c.processes.thread_leader(path.pid).ok_or(Errno::ENOENT)?;
            (c.processes.view(pid).ok_or(Errno::ENOENT)?, pid)
        }
    };
    let threads = view.group.threads();
    let tid = path.tid.unwrap_or(path.pid);
    let member = threads.iter().find(|&&(t, _)| t == tid).copied();
    if path.tid.is_some() && member.is_none() && !(view.zombie && tid == pid) {
        return Err(Errno::ENOENT);
    }
    let public = view
        .group
        .public(tid)
        .or_else(|| view.group.public(pid))
        .unwrap_or_default();
    // A thread is shown asleep while it is in a system call, where it waits
    // if it waits, and running otherwise; the reader is running, reading.
    let state = match member {
        _ if view.zombie => ('Z', "Z (zombie)"),
        // A leader that ended before its other threads.
        None => ('Z', "Z (zombie)"),
        Some(_) if view.group.is_stopped() => ('T', "T (stopped)"),
        Some((_, in_call)) if in_call && tid != c.tid => ('S', "S (sleeping)"),
        Some(_) => ('R', "R (running)"),
    };
    Ok(Task {
        pid,
        tid,
        // Only under `task`: a thread's own ID names a directory of
        // Linux's `tgid_base_stuff`, whose `stat` is the whole process's
        // (`proc_tgid_stat`), as `/proc/<pid>/stat` is.
        thread: path.tid.is_some(),
        view,
        public,
        state,
    })
}

impl Task {
    fn live(&self) -> bool {
        !self.view.zombie
    }
    /// The memory a live process has, which a zombie no longer does.
    fn memory(&self) -> Option<&paludarium_mmu::MemoryView> {
        self.public.memory.as_ref().filter(|_| self.live())
    }
    fn read(&self, at: u64, buf: &mut [u8]) -> bool {
        self.memory().is_some_and(|memory| memory.read(at, buf))
    }
    fn start_stack(&self) -> u64 {
        if self.live() {
            self.view.group.start_stack()
        } else {
            0
        }
    }
    fn string_ranges(&self) -> ((u64, u64), (u64, u64)) {
        if self.memory().is_none() {
            return ((0, 0), (0, 0));
        }
        crate::coredump::string_ranges_in(&|at, buf| self.read(at, buf), self.start_stack())
    }
    /// The threads Linux counts for a process: a zombie still counts as one.
    fn threads(&self) -> usize {
        if self.live() {
            self.view.group.active_threads().max(1)
        } else {
            1
        }
    }
    /// The ignored and the caught signals, from the process's dispositions.
    fn handled(&self) -> (u64, u64) {
        let actions = self.view.group.shared_actions();
        let actions = actions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        actions.iter().filter(|(n, _)| (1..=64).contains(*n)).fold(
            (0, 0),
            |(ignored, caught), (&n, action)| match action.handler {
                0 => (ignored, caught),
                1 => (ignored | 1 << (n - 1), caught),
                _ => (ignored, caught | 1 << (n - 1)),
            },
        )
    }
    /// Its files' owner: the task's effective IDs, as Linux's
    /// `task_dump_owner` gives a dumpable task's, and root an undumpable
    /// one's.
    /// The user namespace of the task's credentials.
    pub(super) fn user(&self) -> std::sync::Arc<crate::namespaces::Namespace> {
        std::sync::Arc::clone(&self.public.credentials.user.0)
    }
    fn owned(&self, stat: FileStat) -> FileStat {
        let ids = &self.public.credentials;
        let (uid, gid) = if self.view.dumpable {
            (ids.euid, ids.egid)
        } else {
            (0, 0)
        };
        FileStat { uid, gid, ..stat }
    }
    /// Whether the reader may see the task's memory and links, as Linux's
    /// `ptrace_may_access` in read mode decides: its own process, or what
    /// [`crate::credentials::Credentials::may_read_task`] allows, `real`
    /// being `environ`'s `PTRACE_MODE_REALCREDS`.
    fn may_access(&self, c: &Context<'_>, real: bool) -> bool {
        self.pid == c.process.pid
            || c.process.credentials.may_read_task(
                &self.public.credentials,
                self.view.dumpable,
                real,
            )
    }
}

/// Refuses what the reader may not see of the task: `environ`, `exe`,
/// `cwd` and the links of `ns` (`EACCES`), as Linux's `proc_mem_open`,
/// `proc_fd_access_allowed` and `proc_ns_get_link` do.
pub(super) fn check(c: &Context<'_>, task: &Task, entry: TaskEntry) -> Result<(), Errno> {
    match entry {
        TaskEntry::Environ if !task.may_access(c, true) => Err(Errno::EACCES),
        TaskEntry::Exe | TaskEntry::Cwd | TaskEntry::Namespace(_) if !task.may_access(c, false) => {
            Err(Errno::EACCES)
        }
        _ => Ok(()),
    }
}

/// The contents of `status`, `stat`, `cmdline` or `comm`; `None` for any
/// other entry.
pub(super) fn content(
    task: &Task,
    entry: TaskEntry,
    reader: &crate::namespaces::Namespace,
) -> Option<Vec<u8>> {
    let public = &task.public;
    let (ignored, caught) = task.handled();
    Some(match entry {
        TaskEntry::Comm => crate::proc::render_comm(&public.name),
        TaskEntry::IdMap(ids) => public.credentials.user.map_text(ids, reader),
        TaskEntry::Setgroups => public.credentials.user.setgroups_text().to_vec(),
        // The argument or environment strings as they are in its memory now;
        // nothing for a zombie.
        TaskEntry::Cmdline | TaskEntry::Environ => {
            let (arguments, environment) = task.string_ranges();
            let (start, end) = if entry == TaskEntry::Cmdline {
                arguments
            } else {
                environment
            };
            let length = usize::try_from(end - start).unwrap_or(0);
            let mut bytes = vec![0; length];
            if !task.read(start, &mut bytes) {
                bytes.clear();
            }
            bytes
        }
        TaskEntry::Stat => {
            let (arguments, environment) = task.string_ranges();
            let (virtual_size, start_brk) = task
                .memory()
                .and_then(paludarium_mmu::MemoryView::size_and_break)
                .unwrap_or((0, 0));
            let threads = task.threads();
            crate::proc::render_stat(&crate::proc::ProcessStat {
                pid: task.tid,
                name: &public.name,
                state: task.state.0,
                // As root sees it: whether the task sleeps, though not for a
                // process of more than one thread as a whole.
                waiting: task.state.0 != 'R' && (task.thread || threads < 2),
                exit_signal: task.view.exit_signal,
                parent: task.view.parent,
                group: task.view.group_id,
                session: task.view.session,
                terminal: crate::pty::stat_fields(task.view.terminal.as_deref()),
                cpu: task.view.group.process_cpu(),
                children_cpu: task.view.children_cpu,
                nice: task.view.group.nice(task.tid).unwrap_or(0),
                threads,
                virtual_size,
                rss_limit: task.view.rss_limit,
                start_stack: task.start_stack(),
                start_brk,
                arguments,
                environment,
                pending: public.pending,
                blocked: public.blocked,
                ignored,
                caught,
            })
        }
        TaskEntry::Status => crate::proc::render_status(&crate::proc::Status {
            name: &public.name,
            umask: task.live().then(|| public.files.umask()),
            state: task.state.1,
            tgid: task.pid,
            pid: task.tid,
            parent: task.view.parent,
            group_id: task.view.group_id,
            session: task.view.session,
            space: &task.view.space,
            descriptors: task.live().then(|| public.files.descriptors()),
            locked: task.memory().and_then(|memory| memory.locked_pages()),
            threads: task.threads(),
            queued: public.queued,
            queue_limit: task.view.queue_limit,
            pending: public.pending,
            blocked: public.blocked,
            ignored,
            caught,
            no_new_privs: task.view.no_new_privs,
            seccomp: public.seccomp,
            credentials: &public.credentials,
            reader,
        }),
        _ => return None,
    })
}

/// Where `exe` or `cwd` leads: the program and the current directory, or
/// ENOENT once the process has ended; `thread-self`, the thread's
/// directory, relative to /proc as Linux's link reads; and what a link of
/// `ns` reads, such as `uts:[4026531838]`. `None` for any other entry.
pub(super) fn link(task: &Task, entry: TaskEntry) -> Option<Result<Vec<u8>, Errno>> {
    let target = match entry {
        TaskEntry::ThreadLink => Some(format!("{}/task/{}", task.pid, task.tid).into_bytes()),
        TaskEntry::Exe => task.live().then(|| task.view.group.executable()),
        TaskEntry::Cwd => task.live().then(|| task.public.files.cwd()).flatten(),
        TaskEntry::Namespace(entry) => namespace(task, entry).map(|namespace| namespace.link()),
        _ => return None,
    };
    Some(target.ok_or(Errno::ENOENT))
}
/// The namespace a link of the task's `ns` names; none once it has ended,
/// as Linux's task then has no `nsproxy`, and none for `pid_for_children`
/// while that PID namespace has no init yet (`pidns_for_children_get`).
pub(super) fn namespace(
    task: &Task,
    entry: crate::namespaces::Entry,
) -> Option<std::sync::Arc<crate::namespaces::Namespace>> {
    task.live()
        .then(|| task.view.group.namespaces(task.tid).entry(entry).clone())
        .filter(|namespace| {
            entry != crate::namespaces::Entry::PidForChildren || namespace.init().is_some()
        })
}

/// The `stat` of the entry, with its device and block size; a link is
/// followed to its file when `follow` is set. `None` for a missing entry.
pub(super) fn stat(
    c: &Context<'_>,
    path: &[u8],
    task: &Task,
    entry: TaskEntry,
    follow: bool,
) -> Result<(FileStat, u64, u32), Errno> {
    let stat = match entry {
        TaskEntry::Directory | TaskEntry::Threads => crate::proc::directory_stat(),
        TaskEntry::ThreadLink if follow => crate::proc::directory_stat(),
        TaskEntry::ThreadLink => crate::proc::self_link_stat(),
        TaskEntry::Exe | TaskEntry::Cwd if follow => {
            check(c, task, entry)?;
            let target = link(task, entry).ok_or(Errno::ENOENT)??;
            let stat = c.files.fs.metadata(&target, true)?;
            return Ok((stat, device(c, &target), BLOCK_SIZE));
        }
        TaskEntry::Exe | TaskEntry::Cwd => crate::proc::self_link_stat(),
        TaskEntry::Namespaces => crate::proc::namespaces_stat(),
        TaskEntry::Namespace(entry) if follow => {
            check(c, task, TaskEntry::Namespace(entry))?;
            let namespace = namespace(task, entry).ok_or(Errno::ENOENT)?;
            return Ok((
                crate::namespaces::file_stat(&namespace),
                crate::namespaces::DEVICE,
                BLOCK_SIZE,
            ));
        }
        TaskEntry::Namespace(_) => crate::proc::self_link_stat(),
        TaskEntry::Missing => return Err(Errno::ENOENT),
        // 0644, which their owner may write.
        TaskEntry::IdMap(_) | TaskEntry::Setgroups => {
            let length = content(task, entry, &c.process.credentials.user).map_or(0, |c| c.len());
            FileStat {
                mode: 0o100_644,
                ..crate::proc::stat(length)
            }
        }
        TaskEntry::Environ => crate::proc::private_stat(
            content(task, entry, &c.process.credentials.user).map_or(0, |content| content.len()),
        ),
        _ => crate::proc::stat(
            content(task, entry, &c.process.credentials.user).map_or(0, |content| content.len()),
        ),
    };
    Ok((task.owned(stat), device(c, path), SMALL_BLOCK_SIZE))
}

/// Numbered entries after `.` and `..`, as `getdents` returns them.
fn listing(names: impl IntoIterator<Item = (Vec<u8>, u8)>) -> Vec<DirectoryEntry> {
    [(b".".to_vec(), DT_DIR), (b"..".to_vec(), DT_DIR)]
        .into_iter()
        .chain(names)
        .enumerate()
        .map(|(i, (name, kind))| DirectoryEntry {
            name,
            inode: i as u64 + 1,
            kind,
        })
        .collect()
}

/// The entries of a process's or a thread's directory, of `task`, or of
/// `ns`.
pub(super) fn entries(task: &Task, entry: TaskEntry) -> Vec<DirectoryEntry> {
    match entry {
        TaskEntry::Namespaces => listing(
            crate::namespaces::ENTRIES
                .into_iter()
                .map(|entry| (entry.name().to_vec(), DT_LNK)),
        ),
        TaskEntry::Threads => {
            let mut threads: Vec<u32> = task
                .view
                .group
                .threads()
                .into_iter()
                .map(|(tid, _)| tid)
                .collect();
            // A zombie's task directory still has its leader.
            if threads.is_empty() {
                threads.push(task.pid);
            }
            listing(
                threads
                    .into_iter()
                    .map(|tid| (tid.to_string().into_bytes(), DT_DIR)),
            )
        }
        _ => listing(
            crate::proc::TASK_NAMES
                .into_iter()
                .filter(|(name, _)| !task.thread || *name != b"task")
                .map(|(name, kind)| (name.to_vec(), kind)),
        ),
    }
}

/// The names /proc generates at its top, with their types.
const ROOT_NAMES: [(&[u8], u8); 8] = [
    (b"self", DT_LNK),
    (b"thread-self", DT_LNK),
    (b"mounts", DT_LNK),
    (b"loadavg", DT_REG),
    (b"meminfo", DT_REG),
    (b"stat", DT_REG),
    (b"uptime", DT_REG),
    (b"sys", DT_DIR),
];

/// The entries of /proc: what the filesystem has there that is not a
/// process (a mounted host's own processes are not the guest's), the files
/// paludarium generates, and then a directory for every process, zombies
/// too, as Linux's `proc_pid_readdir` lists them after the rest.
pub(super) fn root_entries(c: &Context<'_>) -> Vec<DirectoryEntry> {
    let mut names: Vec<(Vec<u8>, u8)> = c
        .files
        .fs
        .read_dir(b"/proc")
        .unwrap_or_default()
        .into_iter()
        .filter(|e| {
            !matches!(&e.name[..], b"." | b".." | b"thread-self")
                && !e.name.iter().all(u8::is_ascii_digit)
        })
        .map(|e| (e.name, e.kind))
        .collect();
    for (name, kind) in ROOT_NAMES {
        if !names.iter().any(|(other, _)| other == name) {
            names.push((name.to_vec(), kind));
        }
    }
    names.extend(
        c.processes
            .pids()
            .into_iter()
            .map(|pid| (pid.to_string().into_bytes(), DT_DIR)),
    );
    listing(names)
}

/// Whether `path` is /proc itself.
pub(super) fn is_root(path: &[u8]) -> bool {
    path.starts_with(b"/proc")
        && paludarium_vfs::normalize_path(path).is_ok_and(|path| path == b"/proc")
}
