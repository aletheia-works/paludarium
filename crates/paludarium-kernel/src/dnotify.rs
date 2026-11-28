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
    /// The directories with dnotify's mark. As Linux's, the mark stays
    /// after a one-shot watch's signal took the last watch off
    /// (`dnotify_handle_event`), and goes at a flush of the directory that
    /// finds none (`dnotify_flush`): a close of any of its files.
    marked: Mutex<Vec<Key>>,
    /// How many entries `marked` holds.
    marks: AtomicUsize,
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
    /// Whether any directory has a mark, which a close then looks at.
    pub(crate) fn marking(&self) -> bool {
        self.marks.load(Ordering::SeqCst) != 0
    }
    fn list(&self) -> std::sync::MutexGuard<'_, Vec<Watch>> {
        self.list.lock().unwrap_or_else(PoisonError::into_inner)
    }
    fn marked(&self) -> std::sync::MutexGuard<'_, Vec<Key>> {
        self.marked.lock().unwrap_or_else(PoisonError::into_inner)
    }
    fn recount(&self, list: &[Watch]) {
        self.count.store(list.len(), Ordering::SeqCst);
    }
    /// Takes the mark off each of `directories`, which a flush reached,
    /// that has no watch left in `list`.
    fn unmark(
        &self,
        list: &[Watch],
        directories: impl IntoIterator<Item = Key>,
        connectors: &crate::fanotify::Registry,
    ) {
        let mut marked = self.marked();
        for directory in directories {
            if list.iter().any(|w| w.directory == directory) {
                continue;
            }
            if let Some(at) = marked.iter().position(|&key| key == directory) {
                marked.remove(at);
                connectors.connector_removed(directory);
            }
        }
        self.marks.store(marked.len(), Ordering::SeqCst);
    }
    /// `dnotify_flush`: a close of `file` through `table` drops what that
    /// table asked of it, and the mark of the directory it is, `directory`,
    /// once no watch is left. A watch whose open file is gone goes too
    /// (only a close missed on its way could leave one), with its
    /// directory's mark when none is left.
    pub(crate) fn flush(
        &self,
        table: u64,
        file: &Arc<dyn FileHandle>,
        directory: Option<Key>,
        connectors: &crate::fanotify::Registry,
    ) {
        if !self.active() && !self.marking() {
            return;
        }
        let mut list = self.list();
        let mut touched: Vec<Key> = directory.into_iter().collect();
        list.retain(|w| {
            let gone = w.file.strong_count() == 0 || w.table == table && same(&w.file, file);
            if gone {
                touched.push(w.directory);
            }
            !gone
        });
        self.unmark(&list, touched, connectors);
        self.recount(&list);
    }
    /// Every watch of `table`, which no task uses any more: its files'
    /// closes as it goes (`put_files_struct`) flush them all. Each closed
    /// file of a directory, `directories`, takes off that directory's mark
    /// with no watch left (`dnotify_flush`), whether or not it is a file
    /// that asked for a watch: a one-shot watch's signal may have left the
    /// mark with none. The directory of each watch it ends is flushed too,
    /// as its file is one of that directory's.
    pub(crate) fn release_table(
        &self,
        table: u64,
        directories: &[Key],
        connectors: &crate::fanotify::Registry,
    ) {
        if !self.active() && !self.marking() {
            return;
        }
        let mut list = self.list();
        let mut flushed = directories.to_vec();
        list.retain(|w| {
            let ends = w.table == table;
            if ends {
                flushed.push(w.directory);
            }
            !ends
        });
        self.unmark(&list, flushed, connectors);
        self.recount(&list);
    }
    /// `attach_dn`: a table that already asked of the file adds the events
    /// to its watch, which now names `fd`; otherwise a new watch comes
    /// first. The directory's first watch gives it dnotify's mark.
    fn attach(&self, watch: Watch, connectors: &crate::fanotify::Registry) {
        let mut list = self.list();
        {
            let mut marked = self.marked();
            if !marked.contains(&watch.directory) {
                connectors.connector_added(watch.directory);
                marked.push(watch.directory);
            }
            self.marks.store(marked.len(), Ordering::SeqCst);
        }
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

/// `fcntl_dirnotify`: `fcntl(fd, F_NOTIFY, arg)` on descriptor `d`, `EINVAL`
/// for every `arg` while `/proc/sys/fs/dir-notify-enable` is 0.
pub(crate) fn fcntl(c: &Context<'_>, d: &Descriptor, fd: u64, arg: u32) -> Result<u64, Errno> {
    if !c.processes.sysctls.dir_notify_enable() {
        return Err(Errno::EINVAL);
    }
    let notify = &c.files.caches.notify;
    let watches = &notify.dn;
    let table = c.files.table();
    // No events: the watch is taken back.
    if arg & !DN_MULTISHOT == 0 {
        watches.flush(table, &d.file, directory_of(c, d), &notify.fan);
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
    watches.attach(
        Watch {
            directory,
            table,
            file: Arc::downgrade(&d.file),
            fd: fd as i32,
            mask: convert(arg),
            processes: Arc::downgrade(c.processes) as Weak<dyn Signaller>,
        },
        &notify.fan,
    );
    Ok(0)
}

/// The directory the open file of `d` is, which a flush takes the mark of.
fn directory_of(c: &Context<'_>, d: &Descriptor) -> Option<Key> {
    directory_in(&*c.files.fs(), d)
}
/// [`directory_of`] for a descriptor of a table seen through `fs`.
pub(crate) fn directory_in(fs: &dyn paludarium_vfs::FileSystem, d: &Descriptor) -> Option<Key> {
    let stat = d.file.stat().ok()?;
    (stat.mode & 0o170000 == 0o040000)
        .then(|| (crate::files::descriptor_device_in(fs, d), stat.inode))
}

/// After a close of `d` through this task's table (`filp_flush`).
pub(crate) fn closed(c: &Context<'_>, d: &Descriptor) {
    let notify = &c.files.caches.notify;
    if !notify.dn.active() && !notify.dn.marking() {
        return;
    }
    notify
        .dn
        .flush(c.files.table(), &d.file, directory_of(c, d), &notify.fan);
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

    /// A one-shot watch of `directory` that `table` asked for, through a
    /// file and processes long gone, so that its signal goes nowhere.
    fn one_shot(directory: Key, table: u64) -> Watch {
        Watch {
            directory,
            table,
            file: Weak::<crate::events::EventCounter>::new() as Weak<dyn FileHandle>,
            fd: 3,
            mask: convert(DN_CREATE),
            processes: Weak::<Processes>::new() as Weak<dyn Signaller>,
        }
    }

    #[test]
    fn a_tables_end_takes_off_an_empty_mark_through_any_file_of_the_directory() {
        let watches = Watches::default();
        let connectors = crate::fanotify::Registry::default();
        let (directory, other) = ((1, 10), (1, 11));
        watches.attach(one_shot(directory, 1), &connectors);
        // The signal takes the one-shot watch off and leaves the mark.
        watches.event(directory, FS_CREATE, true);
        assert!(!watches.active());
        assert!(watches.marking());
        // Another table's end that closes no file of the directory keeps it.
        watches.release_table(2, &[other], &connectors);
        assert!(watches.marking());
        // One that closes a file of it that asked for nothing takes it off,
        // as each close's `dnotify_flush` does.
        watches.release_table(3, &[directory], &connectors);
        assert!(!watches.marking());
    }

    #[test]
    fn a_tables_end_flushes_the_directory_of_each_watch_it_ends() {
        let watches = Watches::default();
        let connectors = crate::fanotify::Registry::default();
        let directory = (1, 10);
        watches.attach(one_shot(directory, 1), &connectors);
        watches.release_table(1, &[], &connectors);
        assert!(!watches.active());
        assert!(!watches.marking());
    }

    #[test]
    fn a_tables_end_keeps_a_mark_another_tables_watch_holds() {
        let watches = Watches::default();
        let connectors = crate::fanotify::Registry::default();
        let directory = (1, 10);
        watches.attach(one_shot(directory, 1), &connectors);
        watches.attach(one_shot(directory, 2), &connectors);
        watches.release_table(2, &[directory], &connectors);
        assert!(watches.active());
        assert!(watches.marking());
        watches.release_table(1, &[directory], &connectors);
        assert!(!watches.active());
        assert!(!watches.marking());
    }
}
