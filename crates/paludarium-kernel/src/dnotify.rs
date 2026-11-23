//! Directory notifications (dnotify), as Linux's `fs/notify/dnotify/dnotify.c`
//! has them: `fcntl`'s `F_NOTIFY` asks for the owner of a directory's open
//! file to be signalled (`send_sigio` with `POLL_MSG`) when the directory
//! or a file in it changes, once or (`DN_MULTISHOT`) every time, until a
//! close of a descriptor of that file through the table that asked
//! (`dnotify_flush`).
use crate::fasync::{OwnerKind, Reason};
use crate::files::Descriptor;
use crate::page_cache::Key;
use crate::processes::Processes;
use crate::syscalls::Context;
use paludarium_host::FileHandle;
use paludarium_types::Errno;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError, Weak};

const DN_ACCESS: u32 = 0x1;
const DN_MODIFY: u32 = 0x2;
const DN_CREATE: u32 = 0x4;
const DN_DELETE: u32 = 0x8;
const DN_RENAME: u32 = 0x10;
const DN_ATTRIB: u32 = 0x20;
const DN_MULTISHOT: u32 = 0x8000_0000;

// The fsnotify events `convert_arg` turns them into.
const FS_ACCESS: u32 = 0x1;
const FS_MODIFY: u32 = 0x2;
const FS_ATTRIB: u32 = 0x4;
const FS_MOVED_FROM: u32 = 0x40;
const FS_MOVED_TO: u32 = 0x80;
const FS_CREATE: u32 = 0x100;
const FS_DELETE: u32 = 0x200;
const FS_DN_MULTISHOT: u32 = 0x2000_0000;
const FS_EVENT_ON_CHILD: u32 = 0x0800_0000;
const FS_RENAME: u32 = 0x1000_0000;
const FS_ISDIR: u32 = 0x4000_0000;

/// Whom a watch signals through: the machine's processes, behind a trait
/// object so that the notifier holding watches does not take in their
/// whole type.
pub(crate) trait Signaller: Send + Sync {
    /// `send_sigio` of the owner of `file` for descriptor `fd`.
    fn signal_owner(&self, file: &Arc<dyn FileHandle>, fd: i32);
}
impl Signaller for Processes {
    fn signal_owner(&self, file: &Arc<dyn FileHandle>, fd: i32) {
        self.send_io(self.file_owner(file), fd, Reason::Message);
    }
}

/// One `dnotify_struct`: what a table (`dn_owner`, Linux's `files_struct`)
/// asked of one open file of a directory, and the descriptor it asked
/// through (`dn_fd`), which `si_fd` names.
struct Watch {
    directory: Key,
    table: u64,
    file: Weak<dyn FileHandle>,
    fd: i32,
    mask: u32,
    processes: Weak<dyn Signaller>,
}

/// The watches of the machine. Within a directory's (its mark's chain),
/// the newest comes first, as `attach_dn` puts each new one at the head.
#[derive(Default)]
pub(crate) struct Watches {
    list: Mutex<Vec<Watch>>,
    count: AtomicUsize,
}

/// `convert_arg`: the fsnotify events of `F_NOTIFY`'s `arg`.
fn convert(arg: u32) -> u32 {
    let mut mask = FS_EVENT_ON_CHILD;
    if arg & DN_MULTISHOT != 0 {
        mask |= FS_DN_MULTISHOT;
    }
    if arg & DN_DELETE != 0 {
        mask |= FS_DELETE | FS_MOVED_FROM;
    }
    if arg & DN_MODIFY != 0 {
        mask |= FS_MODIFY;
    }
    if arg & DN_ACCESS != 0 {
        mask |= FS_ACCESS;
    }
    if arg & DN_ATTRIB != 0 {
        mask |= FS_ATTRIB;
    }
    if arg & DN_RENAME != 0 {
        mask |= FS_RENAME;
    }
    if arg & DN_CREATE != 0 {
        mask |= FS_CREATE | FS_MOVED_TO;
    }
    mask
}

fn same(file: &Weak<dyn FileHandle>, other: &Arc<dyn FileHandle>) -> bool {
    std::ptr::addr_eq(file.as_ptr(), Arc::as_ptr(other))
}

impl Watches {
    /// Whether any watch is there, which a change must be told to.
    pub(crate) fn active(&self) -> bool {
        self.count.load(Ordering::SeqCst) != 0
    }
    fn list(&self) -> std::sync::MutexGuard<'_, Vec<Watch>> {
        self.list.lock().unwrap_or_else(PoisonError::into_inner)
    }
    fn recount(&self, list: &[Watch]) {
        self.count.store(list.len(), Ordering::SeqCst);
    }
    /// `dnotify_flush`: a close of `file` through `table` drops what that
    /// table asked of it. A watch whose open file is gone goes too: only a
    /// close missed on its way could leave one.
    pub(crate) fn flush(&self, table: u64, file: &Arc<dyn FileHandle>) {
        if !self.active() {
            return;
        }
        let mut list = self.list();
        list.retain(|w| w.file.strong_count() != 0 && !(w.table == table && same(&w.file, file)));
        self.recount(&list);
    }
    /// Every watch of `table`, which no task uses any more: its files'
    /// closes as it goes (`put_files_struct`) flush them all.
    pub(crate) fn release_table(&self, table: u64) {
        if !self.active() {
            return;
        }
        let mut list = self.list();
        list.retain(|w| w.table != table);
        self.recount(&list);
    }
    /// `attach_dn`: a table that already asked of the file adds the events
    /// to its watch, which now names `fd`; otherwise a new watch comes
    /// first.
    fn attach(&self, watch: Watch) {
        let mut list = self.list();
        let found = list.iter_mut().find(|w| {
            w.table == watch.table
                && w.file
                    .upgrade()
                    .is_some_and(|file| same(&watch.file, &file))
        });
        match found {
            Some(old) => {
                old.fd = watch.fd;
                old.mask |= watch.mask;
            }
            None => list.push(watch),
        }
        self.recount(&list);
    }
    /// `dnotify_handle_event`: an event `mask` of `directory` itself
    /// (`in_directory` false) or of a file in it. Only a directory hears of
    /// its own events. Each watch that wants it, the newest first, signals
    /// its file's owner, and goes unless it is `DN_MULTISHOT`.
    pub(crate) fn event(&self, directory: Key, mask: u32, in_directory: bool) {
        if !self.active() || !in_directory && mask & FS_ISDIR == 0 {
            return;
        }
        let test = mask & !FS_EVENT_ON_CHILD & !FS_ISDIR;
        let mut signals = Vec::new();
        {
            let mut list = self.list();
            let mut at = list.len();
            while at > 0 {
                at -= 1;
                let w = &list[at];
                if w.directory != directory || w.mask & test == 0 {
                    continue;
                }
                signals.push((w.file.clone(), w.fd, w.processes.clone()));
                if w.mask & FS_DN_MULTISHOT == 0 {
                    list.remove(at);
                }
            }
            self.recount(&list);
        }
        for (file, fd, processes) in signals {
            let (Some(file), Some(processes)) = (file.upgrade(), processes.upgrade()) else {
                continue;
            };
            processes.signal_owner(&file, fd);
        }
    }
}

/// `fcntl_dirnotify`: `fcntl(fd, F_NOTIFY, arg)` on descriptor `d`.
pub(crate) fn fcntl(c: &Context<'_>, d: &Descriptor, fd: u64, arg: u32) -> Result<u64, Errno> {
    let watches = &c.files.caches.notify.dn;
    let table = c.files.table();
    // No events: the watch is taken back.
    if arg & !DN_MULTISHOT == 0 {
        watches.flush(table, &d.file);
        return Ok(0);
    }
    let stat = d.file.stat()?;
    if stat.mode & 0o170000 != 0o040000 {
        return Err(Errno::ENOTDIR);
    }
    let directory = (crate::files::descriptor_device(c, d), stat.inode);
    // `__f_setown` without force: the caller's process owns a file that has
    // no owner yet.
    let owner = c.processes.file_owner(&d.file);
    if owner.id == 0 {
        c.processes.set_file_owner(
            &d.file,
            crate::fasync::FileOwner {
                kind: OwnerKind::Process,
                id: c.process.pid,
                ..owner
            },
        );
    }
    watches.attach(Watch {
        directory,
        table,
        file: Arc::downgrade(&d.file),
        fd: fd as i32,
        mask: convert(arg),
        processes: Arc::downgrade(c.processes) as Weak<dyn Signaller>,
    });
    Ok(0)
}

/// After a close of `d` through this task's table (`filp_flush`).
pub(crate) fn closed(c: &Context<'_>, d: &Descriptor) {
    c.files.caches.notify.dn.flush(c.files.table(), &d.file);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn convert_gives_linux_events() {
        assert_eq!(convert(DN_ACCESS), FS_EVENT_ON_CHILD | FS_ACCESS);
        assert_eq!(
            convert(DN_DELETE | DN_CREATE | DN_MULTISHOT),
            FS_EVENT_ON_CHILD
                | FS_DELETE
                | FS_MOVED_FROM
                | FS_CREATE
                | FS_MOVED_TO
                | FS_DN_MULTISHOT
        );
        assert_eq!(
            convert(DN_RENAME | DN_ATTRIB | DN_MODIFY),
            FS_EVENT_ON_CHILD | FS_RENAME | FS_ATTRIB | FS_MODIFY
        );
    }
}
