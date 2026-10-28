//! Signal-driven I/O, as Linux's `fcntl.c` and `kill_fasync` have it: the
//! owner (`F_SETOWN`, `F_SETOWN_EX`) and signal (`F_SETSIG`) of an open file,
//! and the signal a pipe or socket with `O_ASYNC` sends its owner when it
//! changes.
use crate::processes::Processes;
use crate::syscalls::Context;
use paludarium_host::FileHandle;
use paludarium_types::{Errno, GuestAddr};
use std::sync::{Arc, Weak};

/// `O_ASYNC` (`FASYNC`): only pipes and sockets keep it, the files that
/// have Linux's `fasync` ([`has_fasync`]); on any other `F_SETFL` drops it.
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
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct FileOwner {
    pub kind: OwnerKind,
    pub id: u32,
    pub signal: i32,
}

/// Why a file signals: the `si_code` (`POLL_IN`, ...) of an `F_SETSIG`
/// signal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Reason {
    In = 1,
    Out = 2,
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
            processes.send_io(self.owner, self.to.fd, self.reason);
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

/// Whether `file` has Linux's `fasync`: a pipe or a socket.
pub(crate) fn has_fasync(file: &Arc<dyn FileHandle>) -> bool {
    crate::sockets::endpoint(file).is_some() || crate::inet::of(file).is_some()
}

fn owner(c: &Context<'_>, file: &Arc<dyn FileHandle>) -> FileOwner {
    if let Some(socket) = crate::inet::of(file) {
        return socket.file_owner();
    }
    match crate::sockets::endpoint(file) {
        Some(endpoint) => endpoint.file_owner(),
        None => c.processes.file_owner(file),
    }
}

fn set_owner(c: &Context<'_>, file: &Arc<dyn FileHandle>, owner: FileOwner) {
    if let Some(socket) = crate::inet::of(file) {
        return socket.set_file_owner(owner);
    }
    match crate::sockets::endpoint(file) {
        Some(endpoint) => endpoint.set_file_owner(owner),
        None => c.processes.set_file_owner(file, owner),
    }
}

/// Makes `kind` and `id` the owner, ESRCH (and the owner as it was) when
/// nothing has the ID, as Linux's `f_setown` finds the pid.
fn take_owner(
    c: &Context<'_>,
    file: &Arc<dyn FileHandle>,
    kind: OwnerKind,
    id: u32,
) -> Result<u64, Errno> {
    let owner = FileOwner {
        kind,
        id,
        ..owner(c, file)
    };
    if id != 0 && !c.processes.owner_exists(owner) {
        return Err(Errno(3));
    }
    set_owner(c, file, owner);
    Ok(0)
}

/// Gives `file`, open as descriptor `fd`, the status `flags` of `F_SETFL`.
/// Only pipes and sockets keep `O_ASYNC`, and changing it registers or
/// drops the descriptor, as Linux's `fasync` does.
pub(crate) fn set_flags(
    c: &Context<'_>,
    file: &Arc<dyn FileHandle>,
    fd: u64,
    flags: u32,
) -> Result<(), Errno> {
    let flags = if has_fasync(file) {
        flags
    } else {
        flags & !O_ASYNC
    };
    let before = file.flags();
    file.set_flags(flags)?;
    if (before ^ flags) & O_ASYNC != 0 {
        let registration = (flags & O_ASYNC != 0).then(|| Registration {
            processes: Arc::downgrade(c.processes),
            fd: fd as i32,
        });
        if let Some(endpoint) = crate::sockets::endpoint(file) {
            endpoint.set_async(registration);
        } else if let Some(socket) = crate::inet::of(file) {
            socket.set_async(registration);
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
            let id = current.id as i32;
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
            let bytes = [kind.to_le_bytes(), current.id.to_le_bytes()].concat();
            c.mem
                .write(GuestAddr(arg), &bytes)
                .map_err(|_| Errno::EFAULT)?;
            Ok(0)
        }
        _ => Err(Errno::EINVAL),
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
            .map(|&(_, owner)| owner)
            .unwrap_or_default()
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
            signal: 0,
        };
        owners.set(&first, owner);
        assert_eq!(owners.get(&first), owner);
        drop(first);
        let other = file();
        assert_eq!(owners.get(&other), FileOwner::default());
        assert!(owners.0.is_empty());
    }
}
