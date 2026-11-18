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
/// `S_IFDIR | S_IRUGO | S_IXUGO`, the mode of the directories whose owner
/// `task_dump_owner` takes whether or not the task is dumpable.
pub(super) const OPEN_DIRECTORY: u32 = 0o040_555;
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
    /// The process tracing it, 0 for none (`TracerPid`).
    tracer: u32,
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
        Some(_) if c.processes.traces.in_stop(tid) => ('t', "t (tracing stop)"),
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
        tracer: c.processes.traces.tracer_of(tid).unwrap_or(0),
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
    /// Its program's code range, which a zombie no longer has.
    fn code(&self) -> (u64, u64) {
        if self.live() {
            self.view.group.code()
        } else {
            (0, 0)
        }
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
    /// The user namespace of the task's credentials.
    pub(super) fn user(&self) -> std::sync::Arc<crate::namespaces::Namespace> {
        std::sync::Arc::clone(&self.public.credentials.user.0)
    }
    /// Its files' owner: the task's effective IDs, as Linux's
    /// `task_dump_owner` gives a dumpable task's, and root an undumpable
    /// one's but for a directory any reader may read and look in (0555),
    /// which is always the task's.
    pub(super) fn owned(&self, stat: FileStat) -> FileStat {
        let ids = &self.public.credentials;
        let (uid, gid) = if self.view.dumpable || stat.mode == OPEN_DIRECTORY {
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

/// Refuses what the reader may not see of the task: `environ`, `auxv`, `maps`,
/// `smaps`, `pagemap`, `exe`, `cwd`, the links of `ns` and `fd`, and `fdinfo`
/// (`EACCES`), as Linux's `proc_mem_open`, `proc_fd_access_allowed`,
/// `proc_ns_get_link` and `proc_fdinfo_permission` do; and `fd` itself, read or
/// looked in, as its mode lets (`proc_fd_permission`). `environ`, `auxv` and
/// `pagemap` of a task with no memory left are `ESRCH` for anyone, as Linux's
/// `__mem_open` and `pagemap_open` refuse them before they check the reader,
/// while `maps` and `smaps` (`proc_maps_open`) then open for anyone and read
/// nothing.
pub(super) fn check(c: &Context<'_>, task: &Task, entry: TaskEntry) -> Result<(), Errno> {
    match entry {
        TaskEntry::Environ | TaskEntry::Auxv | TaskEntry::Pagemap if task.memory().is_none() => {
            Err(Errno(3)) // ESRCH
        }
        TaskEntry::Environ if !task.may_access(c, true) => Err(Errno::EACCES),
        TaskEntry::Auxv if !task.may_access(c, false) => Err(Errno::EACCES),
        TaskEntry::Descriptors => descriptors_permission(c, task, crate::permissions::MAY_READ),
        TaskEntry::Descriptor(_) => {
            descriptors_permission(c, task, crate::permissions::MAY_EXEC)?;
            if task.may_access(c, false) {
                Ok(())
            } else {
                Err(Errno::EACCES)
            }
        }
        TaskEntry::DescriptorInfos | TaskEntry::DescriptorInfo(_) if !task.may_access(c, false) => {
            Err(Errno::EACCES)
        }
        // Without memory, `proc_mem_open` has no mm and checks nothing.
        TaskEntry::Maps(_) if task.memory().is_some() && !task.may_access(c, false) => {
            Err(Errno::EACCES)
        }
        TaskEntry::Pagemap if !task.may_access(c, false) => Err(Errno::EACCES),
        TaskEntry::Exe | TaskEntry::Cwd | TaskEntry::Root | TaskEntry::Namespace(_)
            if !task.may_access(c, false) =>
        {
            Err(Errno::EACCES)
        }
        _ => Ok(()),
    }
}

/// Whether the reader may read (`MAY_READ`) or look in (`MAY_EXEC`) the
/// task's `fd`, 0500 and its owner's, as Linux's `proc_fd_permission`
/// decides: by its mode, and always in the reader's own process.
fn descriptors_permission(c: &Context<'_>, task: &Task, mask: u32) -> Result<(), Errno> {
    if task.pid == c.process.pid {
        return Ok(());
    }
    let stat = task.owned(crate::proc::descriptors_stat());
    crate::permissions::permission(&c.process.credentials, &stat, mask)
}
/// Whose the task's descriptors are ([`super::Holder`]); `None` once it has
/// ended.
pub(super) fn holder(task: &Task) -> Option<super::Holder> {
    task.live()
        .then(|| task.public.files.holder(task.pid))
        .flatten()
}
/// Descriptor `n` of the task while it is open; none once it has ended.
pub(super) fn descriptor(task: &Task, n: u32) -> Option<super::Descriptor> {
    task.live()
        .then(|| task.public.files.descriptor(n))
        .flatten()
}
/// The task's open descriptors, none once it has ended.
pub(super) fn descriptors(task: &Task) -> Vec<(u32, super::Descriptor)> {
    if task.live() {
        task.public.files.all()
    } else {
        Vec::new()
    }
}

/// The contents of `status`, `stat`, `statm`, `limits`, `auxv`, `cmdline`
/// or `comm`, and the others made when opened; `None` for any other entry.
pub(super) fn content(
    task: &Task,
    entry: TaskEntry,
    reader: &crate::namespaces::Namespace,
) -> Option<Vec<u8>> {
    let public = &task.public;
    let (ignored, caught) = task.handled();
    Some(match entry {
        TaskEntry::Comm => crate::proc::render_comm(&public.name),
        TaskEntry::Statm => crate::proc::render_statm(task.memory(), task.code()),
        TaskEntry::Limits => crate::proc::render_limits(&task.view.limits),
        // What its exec saved, as Linux's `auxv_read`; nothing once its
        // memory is gone, when it no longer opens.
        TaskEntry::Auxv if task.memory().is_some() => task.view.group.auxv(),
        TaskEntry::Auxv => Vec::new(),
        TaskEntry::IdMap(ids) => public.credentials.user.map_text(ids, reader),
        TaskEntry::Setgroups => public.credentials.user.setgroups_text().to_vec(),
        // Nothing once it has ended, whose open is `EINVAL` ([`mounts`]).
        TaskEntry::Mounts(mountinfo) => mounts(task).map_or_else(Vec::new, |(mounts, root)| {
            crate::proc::render(&mounts, mountinfo, &root)
        }),
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
                code: task.code(),
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
            tracer: task.tracer,
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

/// The mounts of the task's mount namespace and its root, which
/// `mountinfo` and `mounts` show; `None` for a task that has ended, whose
/// open Linux's `mounts_open_common` refuses (`EINVAL`) as it has no
/// `nsproxy`, the leader of live threads too.
pub(super) fn mounts(task: &Task) -> Option<(Vec<paludarium_vfs::MountPoint>, Vec<u8>)> {
    if task.state.0 == 'Z' {
        return None;
    }
    task.public.files.mounts()
}

/// `maps` or `smaps` (`smaps` set) of the task, opened with `flags`, its
/// files named from the reader's `root` as Linux's `seq_file_path` names
/// them; empty once it has ended, as Linux's `m_start` finds no `mm`.
pub(super) fn maps(
    task: &Task,
    smaps: bool,
    flags: u32,
    root: Vec<u8>,
    owner: crate::proc::Owner,
) -> std::sync::Arc<dyn paludarium_host::FileHandle> {
    match task.memory() {
        Some(memory) => std::sync::Arc::new(crate::proc::maps_file(
            memory.clone(),
            task.start_stack(),
            flags,
            root,
            smaps,
            owner,
        )),
        None => std::sync::Arc::new(
            crate::proc::GeneratedFile::open(Vec::new(), flags)
                .with_stat(crate::proc::stat(0))
                .with_owner(owner),
        ),
    }
}
/// `pagemap` of the task, opened with `flags`: its pages' entries;
/// `ESRCH` once it has no memory, as Linux's `pagemap_open`.
pub(super) fn pagemap(
    task: &Task,
    flags: u32,
    owner: crate::proc::Owner,
) -> Result<std::sync::Arc<dyn paludarium_host::FileHandle>, Errno> {
    let memory = task.memory().ok_or(Errno(3))?; // ESRCH
    Ok(std::sync::Arc::new(crate::proc::PagemapFile::open(
        memory.clone(),
        flags,
        owner,
    )))
}
/// `clear_refs` of the task, opened with `flags`: a write acts on the
/// address space the task has then (`get_task_mm`), as Linux's
/// `clear_refs_write`, and is `ESRCH` once it is gone.
pub(super) fn clear_refs(
    processes: &std::sync::Arc<crate::processes::Processes>,
    task: &Task,
    flags: u32,
    owner: crate::proc::Owner,
) -> std::sync::Arc<dyn paludarium_host::FileHandle> {
    // Weak, as the file that holds it sits in a descriptor table of theirs.
    let processes = std::sync::Arc::downgrade(processes);
    let (pid, tid, thread) = (task.pid, task.tid, task.thread);
    let memory: crate::proc::CurrentMemory = std::sync::Arc::new(move || {
        let processes = processes.upgrade().ok_or(Errno(3))?; // ESRCH
        let view = processes.view(pid).ok_or(Errno(3))?;
        let member = view.group.threads().iter().any(|&(t, _)| t == tid);
        if thread && !member && !(view.zombie && tid == pid) {
            return Err(Errno(3));
        }
        if view.zombie {
            return Ok(None);
        }
        Ok(view
            .group
            .public(tid)
            .or_else(|| view.group.public(pid))
            .and_then(|public| public.memory))
    });
    std::sync::Arc::new(crate::proc::ClearRefsFile::open(memory, flags, owner))
}
/// Who owns, at each `fstat`, the task's directory, or its `ns` (`open`
/// false), as Linux's `pid_getattr` asks `task_dump_owner` then: root once
/// the task is gone.
pub(super) fn live_owner(
    processes: &std::sync::Arc<crate::processes::Processes>,
    task: &Task,
    open: bool,
) -> crate::proc::LiveOwner {
    own_live_owner(processes, task.pid, task.tid, open)
}
/// [`live_owner`] of thread `tid` of process `pid`.
pub(crate) fn own_live_owner(
    processes: &std::sync::Arc<crate::processes::Processes>,
    pid: u32,
    tid: u32,
    open: bool,
) -> crate::proc::LiveOwner {
    // Weak, as the file that holds it sits in a descriptor table of theirs.
    let processes = std::sync::Arc::downgrade(processes);
    std::sync::Arc::new(move || {
        let Some(view) = processes
            .upgrade()
            .and_then(|processes| processes.view(pid))
        else {
            return (0, 0);
        };
        let public = view.group.public(tid);
        match public {
            Some(public) if open || view.dumpable => {
                (public.credentials.euid, public.credentials.egid)
            }
            _ => (0, 0),
        }
    })
}
/// `io` of the task: its counts, of the thread or of the whole process,
/// made when it is read, as Linux's `do_io_accounting`. The reader then must
/// be of its process or one `ptrace_may_access` lets read it with its file
/// system IDs (`EACCES`), and a task that has been reaped is `ESRCH`. A
/// zombie's memory is gone, so its dumpable flag no longer matters.
pub(super) fn io(
    processes: &std::sync::Arc<crate::processes::Processes>,
    task: &Task,
    flags: u32,
    owner: crate::proc::Owner,
) -> std::sync::Arc<dyn paludarium_host::FileHandle> {
    // Weak, as the file that holds it sits in a descriptor table of theirs.
    let processes = std::sync::Arc::downgrade(processes);
    let (pid, tid, thread) = (task.pid, task.tid, task.thread);
    let text: crate::proc::Text = std::sync::Arc::new(move || {
        let processes = processes.upgrade().ok_or(Errno(3))?; // ESRCH
        let view = processes.view(pid).ok_or(Errno(3))?;
        let member = view.group.threads().iter().any(|&(t, _)| t == tid);
        if thread && !member && !(view.zombie && tid == pid) {
            return Err(Errno(3));
        }
        let (reader_pid, reader_tid) = crate::proc::caller();
        if reader_pid != pid {
            let target = view
                .group
                .public(tid)
                .or_else(|| view.group.public(pid))
                .unwrap_or_default();
            let reader = processes
                .view(reader_pid)
                .and_then(|reader| reader.group.public(reader_tid))
                .ok_or(Errno::EACCES)?;
            if !reader.credentials.may_read_task(
                &target.credentials,
                view.dumpable || view.zombie,
                false,
            ) {
                return Err(Errno::EACCES);
            }
        }
        Ok(crate::io_accounting::render(
            view.group.io(thread.then_some(tid)),
        ))
    });
    std::sync::Arc::new(crate::proc::single_file(text, flags, owner))
}
/// The group of the task and the thread a write to its `comm` renames.
pub(super) fn comm(task: &Task) -> (std::sync::Arc<crate::threads::ThreadGroup>, u32, u32) {
    (std::sync::Arc::clone(&task.view.group), task.pid, task.tid)
}

/// Where `exe` or `cwd` leads: the program and the current directory, or
/// ENOENT once the process has ended; `thread-self`, the thread's
/// directory, relative to /proc as Linux's link reads; what a link of
/// `ns` reads, such as `uts:[4026531838]`; and a link of `fd`, ENOENT
/// once its descriptor is closed. `None` for any other entry.
pub(super) fn link(task: &Task, entry: TaskEntry) -> Option<Result<Vec<u8>, Errno>> {
    let target = match entry {
        // What the descriptor's file is, as this process's own `fd` names
        // it.
        TaskEntry::Descriptor(n) => {
            return Some(
                descriptor(task, n)
                    .ok_or(Errno::ENOENT)
                    .and_then(|d| super::link_target(&holder(task).ok_or(Errno::ENOENT)?, &d)),
            );
        }
        TaskEntry::ThreadLink => Some(format!("{}/task/{}", task.pid, task.tid).into_bytes()),
        TaskEntry::Exe => task.live().then(|| task.view.group.executable()),
        TaskEntry::Cwd => task.live().then(|| task.public.files.cwd()).flatten(),
        TaskEntry::Root => task.live().then(|| task.public.files.root()).flatten(),
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
        TaskEntry::Exe | TaskEntry::Cwd | TaskEntry::Root if follow => {
            check(c, task, entry)?;
            let target = link(task, entry).ok_or(Errno::ENOENT)??;
            let stat = c.files.fs().metadata(&target, true)?;
            return Ok((stat, device(c, &target), BLOCK_SIZE));
        }
        TaskEntry::Exe | TaskEntry::Cwd | TaskEntry::Root => crate::proc::self_link_stat(),
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
        // As Linux's `proc_fd_getattr`: its size is the number of open
        // descriptors.
        TaskEntry::Descriptors => FileStat {
            size: descriptors(task).len() as u64,
            ..crate::proc::descriptors_stat()
        },
        TaskEntry::DescriptorInfos => FileStat {
            mode: 0o040_555,
            ..crate::proc::directory_stat()
        },
        // Looked up in `fd`, which its mode lets the reader look in, while
        // the descriptor is open; followed, the file it leads to.
        TaskEntry::Descriptor(n) => {
            if follow {
                check(c, task, entry)?;
            } else {
                descriptors_permission(c, task, crate::permissions::MAY_EXEC)?;
            }
            let d = descriptor(task, n).ok_or(Errno::ENOENT)?;
            if follow {
                let holder = holder(task).ok_or(Errno::ENOENT)?;
                return Ok((
                    d.file.stat()?,
                    holder.device(&d),
                    super::descriptor_block_size(c, &d),
                ));
            }
            crate::proc::link_stat(d.file.flags() & 3)
        }
        // Of size 0, as Linux's, in `fdinfo`, which only a reader that may
        // read the task looks in.
        TaskEntry::DescriptorInfo(n) => {
            check(c, task, entry)?;
            descriptor(task, n).ok_or(Errno::ENOENT)?;
            crate::proc::stat(0)
        }
        // As Linux's, of size 0, as they are made as they are read.
        TaskEntry::Maps(_) => crate::proc::stat(0),
        // 0400, as Linux's.
        TaskEntry::Pagemap | TaskEntry::Io => crate::proc::private_stat(0),
        // 0200, as Linux's.
        TaskEntry::ClearRefs => crate::proc::write_only_stat(),
        // 0644, which their owner may write.
        TaskEntry::IdMap(_) | TaskEntry::Setgroups | TaskEntry::Comm => {
            let length = content(task, entry, &c.process.credentials.user).map_or(0, |c| c.len());
            FileStat {
                mode: 0o100_644,
                ..crate::proc::stat(length)
            }
        }
        TaskEntry::Environ | TaskEntry::Auxv => crate::proc::private_stat(
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
        TaskEntry::Descriptors | TaskEntry::DescriptorInfos => {
            let kind = if entry == TaskEntry::Descriptors {
                DT_LNK
            } else {
                DT_REG
            };
            listing(
                descriptors(task)
                    .into_iter()
                    .map(|(n, _)| (n.to_string().into_bytes(), kind)),
            )
        }
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
const ROOT_NAMES: [(&[u8], u8); 9] = [
    (b"self", DT_LNK),
    (b"thread-self", DT_LNK),
    (b"mounts", DT_LNK),
    (b"loadavg", DT_REG),
    (b"meminfo", DT_REG),
    (b"stat", DT_REG),
    (b"uptime", DT_REG),
    (b"sys", DT_DIR),
    (b"sysvipc", DT_DIR),
];

/// The entries of /proc: what the filesystem has there that is not a
/// process (a mounted host's own processes are not the guest's), the files
/// paludarium generates, and then a directory for every process, zombies
/// too, as Linux's `proc_pid_readdir` lists them after the rest.
pub(super) fn root_entries(c: &Context<'_>) -> Vec<DirectoryEntry> {
    let mut names: Vec<(Vec<u8>, u8)> = c
        .files
        .fs()
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
