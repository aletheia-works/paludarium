//! Signal-driven I/O, as Linux's `fcntl.c` and `kill_fasync` have it: the
//! owner (`F_SETOWN`, `F_SETOWN_EX`) and signal (`F_SETSIG`) of an open file,
//! and the signal a pipe, socket, pseudo-terminal, inotify instance or the
//! host's standard stream with `O_ASYNC` sends its owner when it changes.
use crate::processes::Processes;
use crate::syscalls::Context;
use paludarium_host::FileHandle;
use paludarium_types::{Errno, GuestAddr};
use std::sync::{Arc, Weak};

/// `O_ASYNC` (`FASYNC`): only pipes, sockets, pseudo-terminals, inotify
/// instances and a standard stream that is one or a terminal keep it, the
/// files that have Linux's `fasync` ([`has_fasync`]); on any other `F_SETFL`
/// drops it.
pub(crate) const O_ASYNC: u32 = 0o20000;

/// Whom a file's signals go to, as `F_OWNER_TID`, `F_OWNER_PID` and
/// `F_OWNER_PGRP` name it: a thread, the process of a process or thread
/// ID, or a process group.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum OwnerKind {
    /// A file no `F_SETOWN` has touched reports type 0, as on Linux.
    #[default]
    Thread,
    Process,
    Group,
}

/// The owner of an open file and its `F_SETSIG` signal; an ID of 0 is none.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct FileOwner {
    pub kind: OwnerKind,
    pub id: u32,
    pub signal: i32,
    /// Who made it the owner, which decides whom its signals reach.
    pub setter: Setter,
}

/// What a file's signals carry of whoever last named its owner: their real
/// and effective user IDs (kernel IDs), their Landlock domain and their
/// process. Naming no owner, or changing only the signal, keeps it. With
/// none of this kept, as for an owner no call named, root's IDs and no
/// domain stand, which reach everything.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Setter {
    uid: u32,
    euid: u32,
    landlock: crate::landlock::Landlock,
    process: u32,
}
impl Setter {
    /// The calling thread, as it names an owner.
    pub(crate) fn of(c: &Context<'_>) -> Self {
        let credentials = &c.process.credentials;
        Self {
            uid: credentials.uid,
            euid: credentials.euid,
            landlock: credentials.landlock.clone(),
            process: c.process.pid,
        }
    }
    /// Whether the file's signal may reach the thread of `target`'s IDs in
    /// process `pid`. Root's effective ID reaches any; otherwise one of the
    /// kept IDs must be the target's real or saved one. Then a domain the
    /// setter had that scopes signals keeps them inside it, though never
    /// from the setter's own process.
    pub(crate) fn reaches(&self, pid: u32, target: &crate::credentials::TaskIds) -> bool {
        let by_ids = self.euid == 0
            || [target.uid, target.suid]
                .iter()
                .any(|&id| id == self.uid || id == self.euid);
        by_ids
            && (pid == self.process
                || !crate::landlock::scoped(
                    &self.landlock,
                    &target.landlock,
                    crate::landlock::SCOPE_SIGNAL,
                ))
    }
}

/// Why a file signals: the `si_code` (`POLL_IN`, ...) of an `F_SETSIG`
/// signal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Reason {
    In = 1,
    Out = 2,
    /// `POLL_MSG`, which dnotify gives (`dnotify_handle_event`).
    Message = 3,
    Error = 4,
    Priority = 5,
    HangUp = 6,
}
impl Reason {
    /// `si_band`, as Linux's `band_table` gives it.
    fn band(self) -> i64 {
        match self {
            Self::In => 0x41,
            Self::Out => 0x304,
            Self::Message => 0x441,
            Self::Error => 0x8,
            Self::Priority => 0x82,
            Self::HangUp => 0x18,
        }
    }
}

/// What `F_SETFL` with `O_ASYNC` registers: the descriptor it was set
/// through, which `si_fd` names even after that descriptor is closed.
#[derive(Clone, Debug)]
pub(crate) struct Registration {
    pub processes: Weak<Processes>,
    pub fd: i32,
}

/// A signal a pipe or socket owes its owner, sent once its lock is released.
pub(crate) struct Notice {
    pub to: Registration,
    pub owner: FileOwner,
    pub reason: Reason,
}
impl Notice {
    pub(crate) fn send(self) {
        if let Some(processes) = self.to.processes.upgrade() {
            processes.send_io(&self.owner, self.to.fd, self.reason);
        }
    }
}

/// The siginfo of an `F_SETSIG` signal: `si_code` the reason, then
/// `si_band` and `si_fd`, as Linux's `send_sigio_to_task` fills them.
pub(crate) fn siginfo(signal: i32, fd: i32, reason: Reason) -> [u8; 48] {
    let mut info = [0; 48];
    info[0..4].copy_from_slice(&signal.to_le_bytes());
    info[8..12].copy_from_slice(&(reason as i32).to_le_bytes());
    info[16..24].copy_from_slice(&reason.band().to_le_bytes());
    info[24..28].copy_from_slice(&fd.to_le_bytes());
    info
}

/// Whether `file` has Linux's `fasync`: a pipe, a socket, a pseudo-terminal
/// or an inotify instance (`fsnotify_fasync`), or a host's standard stream
/// when that is a pipe, a socket or a terminal.
pub(crate) fn has_fasync(file: &Arc<dyn FileHandle>) -> bool {
    crate::sockets::endpoint(file).is_some()
        || crate::inet::of(file).is_some()
        || crate::inotify::of(file).is_some()
        || crate::perf::is_event(file)
        || crate::pty::is_terminal(file)
        || crate::files::standard(file).is_some_and(crate::files::StandardFile::signals)
}

fn owner(c: &Context<'_>, file: &Arc<dyn FileHandle>) -> FileOwner {
    if let Some(socket) = crate::inet::of(file) {
        return socket.file_owner();
    }
    if let Some(pipe) = crate::sockets::pipe(file) {
        return pipe.file_owner();
    }
    if let Some(instance) = crate::inotify::of(file) {
        return instance.file_owner();
    }
    match crate::sockets::endpoint(file) {
        Some(endpoint) => endpoint.file_owner(),
        None => c.processes.file_owner(file),
    }
}

fn set_owner(c: &Context<'_>, file: &Arc<dyn FileHandle>, owner: FileOwner) {
    if let Some(socket) = crate::inet::of(file) {
        return socket.set_file_owner(owner, c.processes);
    }
    if let Some(pipe) = crate::sockets::pipe(file) {
        return pipe.set_file_owner(owner);
    }
    if let Some(instance) = crate::inotify::of(file) {
        return instance.set_file_owner(owner);
    }
    match crate::sockets::endpoint(file) {
        Some(endpoint) => endpoint.set_file_owner(owner),
        None => c.processes.set_file_owner(file, owner),
    }
}

/// Makes `kind` and `id` the owner, ESRCH (and the owner as it was) when
/// nothing has the ID, as Linux's `f_setown` finds the pid in the caller's
/// PID namespace.
fn take_owner(
    c: &Context<'_>,
    file: &Arc<dyn FileHandle>,
    kind: OwnerKind,
    id: u32,
) -> Result<u64, Errno> {
    let id = if id == 0 { 0 } else { c.named(id) };
    let current = owner(c, file);
    // Naming no owner keeps who named the last one.
    let setter = if id == 0 {
        current.setter.clone()
    } else {
        Setter::of(c)
    };
    let owner = FileOwner {
        kind,
        id,
        setter,
        ..current
    };
    if id != 0 && !c.processes.owner_exists(&owner) {
        return Err(Errno(3));
    }
    set_owner(c, file, owner);
    Ok(0)
}

/// Gives `file`, open as descriptor `fd`, the status `flags` of `F_SETFL`.
/// Only the files with `fasync` ([`has_fasync`]) keep `O_ASYNC`, and
/// changing it registers or drops the descriptor, as Linux's `fasync` does.
/// `direct` is whether its description may have `O_DIRECT`
/// ([`crate::files::direct_io`]).
pub(crate) fn set_flags(
    c: &Context<'_>,
    file: &Arc<dyn FileHandle>,
    fd: u64,
    flags: u32,
    direct: bool,
) -> Result<(), Errno> {
    let flags = if has_fasync(file) {
        flags
    } else {
        flags & !O_ASYNC
    };
    let before = file.flags();
    // `setfl`: O_APPEND stays on an append-only file (EPERM).
    if (before ^ flags) & 0o2000 != 0
        && file
            .stat()
            .is_ok_and(|stat| crate::files::attributes::append_only(&stat))
    {
        return Err(Errno::EPERM);
    }
    // `setfl`: `O_NOATIME`, newly set, only by the file's owner or with
    // `CAP_FOWNER` (EPERM), then `O_DIRECT` only where the description may
    // have it, or on a FIFO, where it is a pipe's packet mode (EINVAL).
    // Either flag already set passed these when it was, so `FIOASYNC`,
    // which keeps them as they are, never meets them, as Linux's does not.
    let added = flags & !before;
    if added & crate::files::O_NOATIME != 0
        && !file
            .stat()
            .is_ok_and(|stat| crate::permissions::owner_or_capable(&c.process.credentials, &stat))
    {
        return Err(Errno::EPERM);
    }
    if added & crate::files::O_DIRECT != 0
        && !direct
        && !file
            .stat()
            .is_ok_and(|stat| stat.mode & 0o170000 == 0o010000)
    {
        return Err(Errno::EINVAL);
    }
    // A hung-up terminal's `fasync` refuses, and nothing changes.
    if (before ^ flags) & O_ASYNC != 0 && crate::pty::hung_up(file) {
        return Err(Errno::ENOTTY);
    }
    file.set_flags(flags)?;
    if (before ^ flags) & O_ASYNC != 0 {
        let registration = (flags & O_ASYNC != 0).then(|| Registration {
            processes: Arc::downgrade(c.processes),
            fd: fd as i32,
        });
        if let Some(pipe) = crate::sockets::pipe(file) {
            pipe.set_async(registration);
        } else if let Some(endpoint) = crate::sockets::endpoint(file) {
            endpoint.set_async(registration);
        } else if let Some(socket) = crate::inet::of(file) {
            socket.set_async(registration);
        } else if let Some(instance) = crate::inotify::of(file) {
            instance.set_async(registration);
        } else if crate::perf::is_event(file) {
            crate::perf::set_async(file, registration);
        } else if crate::pty::is_terminal(file) {
            crate::pty::set_async(c, file, registration);
        } else if let Some(stdin) = crate::files::standard(file) {
            stdin.set_async(file, registration);
        }
    }
    Ok(())
}

/// `fcntl`'s `F_SETOWN` (8), `F_GETOWN` (9), `F_SETSIG` (10), `F_GETSIG`
/// (11), `F_SETOWN_EX` (15) and `F_GETOWN_EX` (16), for any file.
pub(crate) fn fcntl(
    c: &mut Context<'_>,
    file: &Arc<dyn FileHandle>,
    command: u64,
    arg: u64,
) -> Result<u64, Errno> {
    let current = owner(c, file);
    match command {
        8 => match arg as i32 {
            i32::MIN => Err(Errno::EINVAL),
            who if who < 0 => take_owner(c, file, OwnerKind::Group, who.unsigned_abs()),
            who => take_owner(c, file, OwnerKind::Process, who as u32),
        },
        9 => {
            let id = shown_id(c, &current) as i32;
            let id = if current.kind == OwnerKind::Group {
                -id
            } else {
                id
            };
            Ok(i64::from(id).cast_unsigned())
        }
        10 => {
            if arg > 64 {
                return Err(Errno::EINVAL);
            }
            set_owner(
                c,
                file,
                FileOwner {
                    signal: arg as i32,
                    ..current
                },
            );
            Ok(0)
        }
        11 => Ok(current.signal as u64),
        15 => {
            let mut bytes = [0; 8];
            c.mem
                .read(GuestAddr(arg), &mut bytes)
                .map_err(|_| Errno::EFAULT)?;
            let [kind, id] = [0, 4]
                .map(|at| i32::from_le_bytes(bytes[at..at + 4].try_into().unwrap_or_default()));
            let kind = match kind {
                0 => OwnerKind::Thread,
                1 => OwnerKind::Process,
                2 => OwnerKind::Group,
                _ => return Err(Errno::EINVAL),
            };
            // A negative ID names no process.
            if id < 0 {
                return Err(Errno(3));
            }
            take_owner(c, file, kind, id as u32)
        }
        16 => {
            let kind = current.kind as i32;
            let id = shown_id(c, &current);
            let bytes = [kind.to_le_bytes(), id.to_le_bytes()].concat();
            c.mem
                .write(GuestAddr(arg), &bytes)
                .map_err(|_| Errno::EFAULT)?;
            Ok(0)
        }
        _ => Err(Errno::EINVAL),
    }
}

/// The owner's ID as `F_GETOWN` and `F_GETOWN_EX` read it back: 0 while
/// nothing it names is there, as Linux's `f_getown` gives an ID only while
/// a task has it in the owner's role (`pid_task`), such as a group's ID
/// when no process is in that group, and as the caller's PID namespace
/// numbers it (`pid_vnr`).
fn shown_id(c: &Context<'_>, owner: &FileOwner) -> u32 {
    if owner.id != 0 && c.processes.owner_present(owner) {
        c.pid_space().number(owner.id)
    } else {
        0
    }
}

/// The owners `F_SETOWN` gives files other than pipes and sockets (which
/// keep theirs themselves), by open file description, for `F_GETOWN`. Each
/// look drops the entries of the descriptions closed since.
#[derive(Default)]
pub(crate) struct Owners(Vec<(Weak<dyn FileHandle>, FileOwner)>);
impl Owners {
    fn same(entry: &Weak<dyn FileHandle>, file: &Arc<dyn FileHandle>) -> bool {
        entry.strong_count() != 0 && std::ptr::addr_eq(entry.as_ptr(), Arc::as_ptr(file))
    }
    pub(crate) fn get(&mut self, file: &Arc<dyn FileHandle>) -> FileOwner {
        self.0.retain(|(entry, _)| entry.strong_count() != 0);
        self.0
            .iter()
            .find(|(entry, _)| Self::same(entry, file))
            .map(|(_, owner)| owner.clone())
            .unwrap_or_default()
    }
    /// The owner of the description at address `file`, while it is open.
    pub(crate) fn at(&mut self, file: usize) -> Option<&mut FileOwner> {
        self.0
            .iter_mut()
            .find(|(entry, _)| {
                entry.strong_count() != 0 && entry.as_ptr().cast::<()>().addr() == file
            })
            .map(|(_, owner)| owner)
    }
    pub(crate) fn set(&mut self, file: &Arc<dyn FileHandle>, owner: FileOwner) {
        self.0.retain(|(entry, _)| entry.strong_count() != 0);
        match self.0.iter_mut().find(|(entry, _)| Self::same(entry, file)) {
            Some((_, kept)) => *kept = owner,
            None => self.0.push((Arc::downgrade(file), owner)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credentials::TaskIds;
    use crate::landlock::{SCOPE_SIGNAL, scoping};

    /// A thread of real, effective and saved user IDs `ids`, in `landlock`.
    fn thread([uid, euid, suid]: [u32; 3], landlock: &crate::landlock::Landlock) -> TaskIds {
        TaskIds {
            uid,
            euid,
            suid,
            landlock: landlock.clone(),
            ..TaskIds::default()
        }
    }

    #[test]
    fn a_setters_ids_reach_a_real_or_saved_id() {
        let none = crate::landlock::Landlock::default();
        let setter = |uid, euid| Setter {
            uid,
            euid,
            landlock: none.clone(),
            process: 1,
        };
        let target = thread([2000, 1000, 3000], &none);
        // Either kept ID, as the target's real or saved one.
        assert!(setter(2000, 1000).reaches(5, &target));
        assert!(setter(1000, 2000).reaches(5, &target));
        assert!(setter(3000, 1000).reaches(5, &target));
        assert!(setter(1000, 3000).reaches(5, &target));
        // The target's effective ID does not count.
        assert!(!setter(1000, 1000).reaches(5, &target));
        // Root's effective ID reaches anyone; its real one alone does not.
        assert!(setter(1000, 0).reaches(5, &target));
        assert!(!setter(0, 1000).reaches(5, &target));
        // Nothing kept is root's, which reaches anyone.
        assert!(Setter::default().reaches(5, &target));
    }

    #[test]
    fn a_setters_scoped_domain_keeps_its_signals_inside_but_for_its_process() {
        let none = crate::landlock::Landlock::default();
        let domain = scoping(&[SCOPE_SIGNAL], &[1]);
        let inner = scoping(&[SCOPE_SIGNAL, 0], &[1, 2]);
        let setter = Setter {
            uid: 0,
            euid: 0,
            landlock: domain.clone(),
            process: 4,
        };
        assert!(!setter.reaches(5, &thread([0; 3], &none)));
        assert!(setter.reaches(5, &thread([0; 3], &domain)));
        assert!(setter.reaches(5, &thread([0; 3], &inner)));
        // Its own process, whatever its domain is now.
        assert!(setter.reaches(4, &thread([0; 3], &none)));
        // A domain that scopes no signal does not keep them in.
        let unscoped = Setter {
            landlock: scoping(&[0], &[3]),
            ..setter.clone()
        };
        assert!(unscoped.reaches(5, &thread([0; 3], &none)));
        // The IDs still count in its own process.
        let other = Setter {
            uid: 1000,
            euid: 1000,
            ..setter
        };
        assert!(!other.reaches(4, &thread([2000; 3], &none)));
    }
    #[test]
    fn owners_drop_the_files_closed_since() {
        let mut owners = Owners::default();
        let file = || -> Arc<dyn FileHandle> {
            let [reader, _] = crate::sockets::PipeEnd::pair(0, Arc::default()).unwrap();
            reader
        };
        let first = file();
        let owner = FileOwner {
            kind: OwnerKind::Process,
            id: 7,
            ..FileOwner::default()
        };
        owners.set(&first, owner.clone());
        assert_eq!(owners.get(&first), owner);
        let address = Arc::as_ptr(&first).cast::<()>().addr();
        owners.at(address).unwrap().id = 8;
        assert_eq!(owners.get(&first).id, 8);
        drop(first);
        assert!(owners.at(address).is_none());
        let other = file();
        assert_eq!(owners.get(&other), FileOwner::default());
        assert!(owners.0.is_empty());
    }
}
