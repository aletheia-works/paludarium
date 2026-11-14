//! Linux x86-64 file ABI and descriptor table. All guest memory is checked.
use crate::syscalls::{Context, Outcome};
pub(crate) mod attributes;
mod splice;
mod tasks;
mod xattrs;
use paludarium_host::{ClockId, FileHandle, FileStat};
use paludarium_mmu::AddressSpace;
use paludarium_types::{Errno, GuestAddr};
use paludarium_vfs::{FileSystem, HostFs, MemFs};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
pub const NUMBERS: &[u64] = &[
    0, 2, 3, 4, 5, 6, 8, 17, 18, 19, 20, 21, 22, 32, 33, 40, 72, 73, 74, 75, 76, 77, 78, 79, 80,
    81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 132, 133, 136, 137, 138, 162, 187,
    188, 189, 190, 191, 192, 193, 194, 195, 196, 197, 198, 199, 217, 221, 235, 257, 258, 259, 260,
    261, 262, 263, 264, 265, 266, 267, 268, 269, 275, 276, 277, 278, 280, 285, 292, 293, 295, 296,
    303, 304, 306, 316, 319, 326, 327, 328, 332, 436, 437, 439, 447, 451, 452, 463, 464, 465, 466,
    468, 469,
];
#[derive(Clone)]
pub(crate) struct Descriptor {
    pub(crate) file: Arc<dyn FileHandle>,
    path: Vec<u8>,
    cloexec: bool,
    /// Its open file description came from an open by path, which gives
    /// it `O_LARGEFILE` ([`status_flags`]); a `dup` or `SCM_RIGHTS` copy
    /// shares that, as it shares Linux's description.
    opened: bool,
    /// What `getdents64` has returned from it, shared as the position is.
    listed: Arc<Mutex<Listed>>,
    /// The Landlock rights its open file description keeps
    /// (`LANDLOCK_ACCESS_FS_TRUNCATE`), all of them unless a Landlock domain
    /// opened it ([`crate::landlock::open`]).
    pub(crate) landlock: u64,
}
/// The names a directory's position has passed, in the order they came. The
/// position counts these and not places in the listing, which a later call
/// reads anew: an unlink must not make it pass an entry that was not returned.
#[derive(Default)]
struct Listed {
    order: Vec<Vec<u8>>,
    names: BTreeSet<Vec<u8>>,
    /// Where the last call left the position: past the end of the listing
    /// it is more than `order` holds.
    position: usize,
}
impl Listed {
    /// Follows a position that `lseek` moved: back forgets the names after
    /// it, and ahead passes the next ones in `entries`.
    fn seek(&mut self, position: usize, entries: &[paludarium_host::DirectoryEntry]) {
        if position == self.position {
            return;
        }
        self.position = position;
        while self.order.len() > position {
            if let Some(name) = self.order.pop() {
                self.names.remove(&name);
            }
        }
        for e in entries {
            if self.order.len() >= position {
                break;
            }
            self.pass(&e.name);
        }
    }
    fn pass(&mut self, name: &[u8]) {
        if self.names.insert(name.to_vec()) {
            self.order.push(name.to_vec());
        }
    }
    /// The call returned `names`, which moved the position past them.
    fn returned(&mut self, names: &[&Vec<u8>]) {
        for name in names {
            self.pass(name);
        }
        self.position += names.len();
    }
}
impl Descriptor {
    /// A descriptor of `file`, which has no path, as a socket's.
    pub(crate) fn unnamed(file: Arc<dyn FileHandle>, cloexec: bool) -> Self {
        Self {
            file,
            path: Vec::new(),
            cloexec,
            opened: false,
            listed: Arc::default(),
            landlock: crate::landlock::FS,
        }
    }
    /// The descriptor a process gets for this one's open file over
    /// `SCM_RIGHTS`: the same file and path, with its own close-on-exec flag.
    pub(crate) fn received(self, cloexec: bool) -> Self {
        Self { cloexec, ..self }
    }
}
#[derive(Clone)]
pub struct Files {
    pub(crate) readiness: Arc<crate::events::ReadinessHub>,
    pub terminal_size: Option<(u16, u16)>,
    /// The session's network, when it has one.
    pub(crate) network: Option<Arc<crate::inet::Network>>,
    /// The machine's AF_UNIX abstract names.
    pub(crate) unix: Arc<crate::unix::Names>,
    /// The machine's pseudo-terminals.
    pub(crate) devpts: Arc<crate::pty::Devpts>,
    pub fs: Arc<dyn FileSystem>,
    pub(crate) fds: Arc<Mutex<BTreeMap<u32, Descriptor>>>,
    /// The table's number, shared exactly as `fds` is: the owner of the POSIX
    /// record locks set through it (Linux's `files_struct` as `flc_owner`).
    table: Arc<Table>,
    /// Numbers an unfinished open has taken, as Linux's alloc_fd marks them
    /// before the file exists: no allocation gets them and no lookup sees
    /// them. Shared exactly as `fds` is; locked after it.
    reserved: Arc<Mutex<BTreeSet<u32>>>,
    cwd: Arc<Mutex<Vec<u8>>>,
    /// The working directory's hold on its file, as `fs->pwd` holds its
    /// dentry; shared with the cwd.
    home: Arc<Mutex<Option<crate::page_cache::Hold>>>,
    /// Shared with the cwd: `CLONE_FS` shares both, as on Linux.
    umask: Arc<AtomicU32>,
    /// The page caches of the files mapped shared, which `fs` keeps its
    /// files in step with; one for the whole machine.
    pub(crate) caches: Arc<crate::page_cache::PageCaches>,
}
impl Default for Files {
    fn default() -> Self {
        let fs = MemFs::new();
        let _ = fs.mkdir(b"/tmp", 0o1777);
        let caches = Arc::default();
        Self {
            readiness: Arc::default(),
            terminal_size: None,
            network: None,
            unix: Arc::default(),
            devpts: Arc::default(),
            fs: Arc::new(crate::page_cache::CoherentFs::new(
                Arc::new(fs),
                Arc::clone(&caches),
            )),
            fds: Arc::new(Mutex::new(BTreeMap::new())),
            table: Arc::new(Table::new()),
            reserved: Arc::default(),
            cwd: Arc::new(Mutex::new(b"/".to_vec())),
            home: Arc::default(),
            umask: Arc::new(AtomicU32::new(0o022)),
            caches,
        }
    }
}
/// What another process's `/proc/<pid>` shows of a process's files: its
/// current directory, umask and descriptor table, as long as they last.
#[derive(Clone, Default)]
pub(crate) struct FilesView {
    cwd: std::sync::Weak<Mutex<Vec<u8>>>,
    umask: std::sync::Weak<AtomicU32>,
    fds: std::sync::Weak<Mutex<BTreeMap<u32, Descriptor>>>,
}
impl FilesView {
    pub(crate) fn cwd(&self) -> Option<Vec<u8>> {
        let cwd = self.cwd.upgrade()?;
        Some(cwd.lock().unwrap_or_else(PoisonError::into_inner).clone())
    }
    pub(crate) fn umask(&self) -> u32 {
        self.umask
            .upgrade()
            .map_or(0o022, |umask| umask.load(Ordering::SeqCst))
    }
    /// What tells the descriptor table apart, while it lives (Linux's
    /// `files_struct` for `kcmp`).
    pub(crate) fn table(&self) -> Option<usize> {
        let fds = self.fds.upgrade()?;
        Some(Arc::as_ptr(&fds) as *const () as usize)
    }
    /// What tells the working directory and umask apart, which `CLONE_FS`
    /// shares, while they live (Linux's `fs_struct`).
    pub(crate) fn fs(&self) -> Option<usize> {
        let umask = self.umask.upgrade()?;
        Some(Arc::as_ptr(&umask) as *const () as usize)
    }
    /// The open file description of descriptor `fd`, `O_PATH` ones included
    /// (Linux's `fget_task`).
    pub(crate) fn file(&self, fd: u32) -> Option<Arc<dyn FileHandle>> {
        let fds = self.fds.upgrade()?;
        let fds = fds.lock().unwrap_or_else(PoisonError::into_inner);
        fds.get(&fd).map(|descriptor| Arc::clone(&descriptor.file))
    }
    /// Descriptor `fd`, which `pidfd_getfd` copies with its open file
    /// description and path.
    pub(crate) fn descriptor(&self, fd: u32) -> Option<Descriptor> {
        let fds = self.fds.upgrade()?;
        let fds = fds.lock().unwrap_or_else(PoisonError::into_inner);
        fds.get(&fd).cloned()
    }
    /// One past the highest open descriptor.
    pub(crate) fn descriptors(&self) -> usize {
        self.fds.upgrade().map_or(0, |fds| {
            fds.lock()
                .unwrap_or_else(PoisonError::into_inner)
                .keys()
                .next_back()
                .map_or(0, |&fd| fd as usize + 1)
        })
    }
}
impl Files {
    /// This process's files as [`FilesView`] shows them to others.
    pub(crate) fn view(&self) -> FilesView {
        FilesView {
            cwd: Arc::downgrade(&self.cwd),
            umask: Arc::downgrade(&self.umask),
            fds: Arc::downgrade(&self.fds),
        }
    }
    /// What [`Self::view`] holds, to tell when it changes.
    pub(crate) fn identity(&self) -> [usize; 3] {
        [
            Arc::as_ptr(&self.cwd).addr(),
            Arc::as_ptr(&self.umask).addr(),
            Arc::as_ptr(&self.fds).addr(),
        ]
    }
    /// Uses `fs`, keeping its files in step with their page caches.
    pub(crate) fn set_file_system(&mut self, fs: Arc<dyn FileSystem>) {
        self.fs = Arc::new(crate::page_cache::CoherentFs::new(
            fs,
            Arc::clone(&self.caches),
        ));
    }
    pub(crate) fn set_current_directory(&mut self, path: &[u8]) -> Result<(), Errno> {
        let path = paludarium_vfs::normalize_path(path)?;
        if self.fs.metadata(&path, true)?.mode & 0o170000 != 0o040000 {
            return Err(Errno::ENOTDIR);
        }
        self.change_directory(path);
        Ok(())
    }
    /// Makes the directory at `path` the working directory, holding its
    /// file instead of the last one (`set_fs_pwd`).
    fn change_directory(&self, path: Vec<u8>) {
        let home = self.caches.hold(&*self.fs, &path);
        *self.cwd.lock().unwrap_or_else(PoisonError::into_inner) = path;
        let last = std::mem::replace(
            &mut *self.home.lock().unwrap_or_else(PoisonError::into_inner),
            home,
        );
        drop(last);
    }
    /// What the mappings of the ELF interpreter at `path` keep: a hold on
    /// its file, as each of Linux's mappings holds its file (`vm_file`).
    pub(crate) fn interpreter_keep(&self, path: &[u8]) -> Option<paludarium_loader::Keep> {
        let hold = self.caches.hold(&*self.fs, path)?;
        Some(Arc::new(hold))
    }
    /// Lets go of the working directory, as an exiting task's `exit_fs`
    /// does: the last task sharing it ends its hold on the directory.
    pub(crate) fn release_home(&mut self) {
        self.home = Arc::default();
    }
    /// Detaches this worker's table reference without closing a table still
    /// shared by live CLONE_FILES siblings; the last task to let go gets the
    /// files the table held (`put_files_struct`), deciding that with the
    /// release itself so that two tasks ending together cannot both miss it.
    /// That last task also gets the table's number, whose record locks then
    /// go (`locks_remove_posix` of each file `close_files` closes).
    pub(crate) fn release_descriptors(&mut self) -> (Option<u64>, Vec<Arc<dyn FileHandle>>) {
        let fds = std::mem::replace(&mut self.fds, Arc::new(Mutex::new(BTreeMap::new())));
        let table = std::mem::replace(&mut self.table, Arc::new(Table::new()));
        self.reserved = Arc::default();
        Arc::into_inner(fds).map_or_else(
            || (None, Vec::new()),
            |fds| {
                let files = fds
                    .into_inner()
                    .unwrap_or_else(PoisonError::into_inner)
                    .into_values()
                    .map(|descriptor| descriptor.file)
                    .collect();
                (Some(table.0), files)
            },
        )
    }
    /// The number of this task's descriptor table, which owns the POSIX
    /// record locks set through it.
    pub(crate) fn table(&self) -> u64 {
        self.table.0
    }
    /// The table itself, for a record lock to go once no task uses it.
    pub(crate) fn table_token(&self) -> std::sync::Weak<Table> {
        Arc::downgrade(&self.table)
    }
    pub(crate) fn umask(&self) -> u32 {
        self.umask.load(Ordering::SeqCst)
    }
    /// Whether descriptor `fd` is open and closes on exec.
    pub(crate) fn is_cloexec(&self, fd: u64) -> bool {
        u32::try_from(fd).is_ok_and(|fd| {
            self.fds
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .get(&fd)
                .is_some_and(|d| d.cloexec)
        })
    }
    pub(crate) fn exec_path(&self, path: Vec<u8>) -> Result<Vec<u8>, Errno> {
        self.path((-100i32) as u64, path)
    }
    /// Takes out the descriptors marked close-on-exec, for exec to close,
    /// when no other task shares this table; one that does keeps the files
    /// open in it, as Linux's `unshare_files` gives exec a copy first.
    pub(crate) fn take_close_on_exec(&self) -> Vec<Descriptor> {
        if Arc::strong_count(&self.fds) != 1 {
            return Vec::new();
        }
        self.fds
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .extract_if(.., |_, descriptor| descriptor.cloexec)
            .map(|(_, descriptor)| descriptor)
            .collect()
    }
    pub(crate) fn for_exec(&self) -> Self {
        let child = self.unshared(false);
        child
            .fds
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|_, descriptor| !descriptor.cloexec);
        child
    }
    pub(crate) fn install(
        &mut self,
        file: Arc<dyn FileHandle>,
        cloexec: bool,
        limit: u64,
    ) -> Result<u32, Errno> {
        self.allocate(
            Descriptor {
                file,
                path: Vec::new(),
                cloexec,
                opened: false,
                listed: Arc::default(),
                landlock: crate::landlock::FS,
            },
            0,
            limit,
        )
    }
    /// Installs a pair, as pipe and socketpair do: both descriptors or, with
    /// fewer than two free below `limit`, neither (EMFILE). One lock covers
    /// both, so no other thread sees only the first.
    pub(crate) fn install_pair(
        &mut self,
        files: [Arc<dyn FileHandle>; 2],
        cloexec: bool,
        limit: u64,
    ) -> Result<[u32; 2], Errno> {
        let mut fds = self.fds.lock().unwrap_or_else(PoisonError::into_inner);
        let reserved = self.reserved.lock().unwrap_or_else(PoisonError::into_inner);
        let one = lowest_free(&fds, &reserved, 0, limit)?;
        let two = lowest_free(&fds, &reserved, one + 1, limit)?;
        for (n, file) in [one, two].into_iter().zip(files) {
            let path = Vec::new();
            fds.insert(
                n,
                Descriptor {
                    file,
                    path,
                    cloexec,
                    opened: false,
                    listed: Arc::default(),
                    landlock: crate::landlock::FS,
                },
            );
        }
        Ok([one, two])
    }
    /// Takes the lowest free number below `limit` (EMFILE otherwise) before
    /// a call such as open has any effect, as Linux's get_unused_fd_flags;
    /// [`Self::fill`] or [`Self::unreserve`] ends the reservation.
    pub(crate) fn reserve(&self, limit: u64) -> Result<u32, Errno> {
        let fds = self.fds.lock().unwrap_or_else(PoisonError::into_inner);
        let mut reserved = self.reserved.lock().unwrap_or_else(PoisonError::into_inner);
        let n = lowest_free(&fds, &reserved, 0, limit)?;
        reserved.insert(n);
        Ok(n)
    }
    pub(crate) fn fill(&self, n: u32, d: Descriptor) {
        let mut fds = self.fds.lock().unwrap_or_else(PoisonError::into_inner);
        fds.insert(n, d);
        self.unreserve(n);
    }
    /// [`Self::fill`] with a description opened as `path`.
    pub(crate) fn fill_opened(
        &self,
        n: u32,
        file: Arc<dyn FileHandle>,
        path: Vec<u8>,
        cloexec: bool,
    ) {
        self.fill(
            n,
            Descriptor {
                file,
                path,
                cloexec,
                opened: false,
                listed: Arc::default(),
                landlock: crate::landlock::FS,
            },
        );
    }
    pub(crate) fn unreserve(&self, n: u32) {
        self.reserved
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&n);
    }
    /// Puts `d` at `n`, as dup2 does, and returns what was there for the
    /// caller to close; EBUSY when an unfinished open of another thread has
    /// taken `n`, as in Linux.
    pub(crate) fn replace(&self, n: u32, d: Descriptor) -> Result<Option<Descriptor>, Errno> {
        let mut fds = self.fds.lock().unwrap_or_else(PoisonError::into_inner);
        let reserved = self.reserved.lock().unwrap_or_else(PoisonError::into_inner);
        if reserved.contains(&n) {
            return Err(Errno(16));
        }
        Ok(fds.insert(n, d))
    }
    pub fn with_host(host: Arc<dyn paludarium_host::Host>) -> Self {
        let files = Self::default();
        for channel in 0..3 {
            files
                .fds
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .insert(
                    channel,
                    Descriptor {
                        file: Arc::new(StandardFile::new(&host, channel)),
                        path: Vec::new(),
                        cloexec: false,
                        opened: false,
                        listed: Arc::default(),
                        landlock: crate::landlock::FS,
                    },
                );
        }
        files
    }
    pub(crate) fn stdio_channel(&self, fd: u64) -> Result<Option<u32>, Errno> {
        Ok(self.descriptor(fd)?.file.stdio_channel())
    }
    pub fn uses_original_stdio(&self, fd: u64) -> bool {
        self.descriptor(fd)
            .ok()
            .and_then(|d| d.file.stdio_channel())
            == Some(fd as u32)
    }
    /// Gives `d` the lowest free number from `min`, which must be below the
    /// RLIMIT_NOFILE soft limit `limit` (EMFILE).
    pub(crate) fn allocate(&mut self, d: Descriptor, min: u32, limit: u64) -> Result<u32, Errno> {
        let mut fds = self.fds.lock().unwrap_or_else(PoisonError::into_inner);
        let reserved = self.reserved.lock().unwrap_or_else(PoisonError::into_inner);
        let n = lowest_free(&fds, &reserved, min, limit)?;
        fds.insert(n, d);
        Ok(n)
    }
    /// Sets or clears `FD_CLOEXEC` of descriptor `fd`, as `F_SETFD`, `FIOCLEX`
    /// and `FIONCLEX` do.
    pub(crate) fn set_cloexec(&self, fd: u64, cloexec: bool) -> Result<(), Errno> {
        self.fds
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get_mut(&(fd as u32))
            .ok_or(Errno::EBADF)?
            .cloexec = cloexec;
        Ok(())
    }
    /// Descriptor `fd`, from the low 32 bits of the register only, as Linux's
    /// `fget` takes an `unsigned int`: a caller may leave the upper half dirty.
    pub(crate) fn descriptor(&self, fd: u64) -> Result<Descriptor, Errno> {
        self.fds
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&(fd as u32))
            .cloned()
            .ok_or(Errno::EBADF)
    }
    pub(crate) fn path(&self, dir: u64, p: Vec<u8>) -> Result<Vec<u8>, Errno> {
        if p.is_empty() {
            return Err(Errno::ENOENT);
        }
        if p.first() == Some(&b'/') {
            return Ok(p);
        }
        let mut base = if dir as i32 == -100 {
            self.cwd
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone()
        } else {
            let d = self.descriptor(dir)?;
            if d.file.stat()?.mode & 0o170000 != 0o040000 {
                return Err(Errno::ENOTDIR);
            }
            d.file.guest_path_hint().unwrap_or(d.path)
        };
        if base.last() != Some(&b'/') {
            base.push(b'/')
        }
        base.extend_from_slice(&p);
        Ok(base)
    }
    /// The file a core dump goes to: `core` in the working directory, made
    /// afresh with mode 0600 less the umask, as Linux's `do_coredump` removes
    /// an old one and opens it with `O_CREAT | O_EXCL | O_NOFOLLOW`, each
    /// with the permissions of `creds`, whose filesystem IDs then own it.
    pub(crate) fn create_core(
        &self,
        creds: &crate::credentials::Credentials,
    ) -> Result<Arc<dyn paludarium_host::FileHandle>, Errno> {
        const AT_FDCWD: u64 = -100i64 as u64;
        const FLAGS: u32 = 0o1 | 0o100 | 0o200 | 0o400000;
        let path = paludarium_vfs::normalize_path(&self.path(AT_FDCWD, b"core".to_vec())?)?;
        if crate::permissions::delete(self, creds, AT_FDCWD, b"core").is_ok() {
            let _ = self.fs.unlink(&path, false);
        }
        let parent = crate::permissions::open(self, creds, AT_FDCWD, b"core", FLAGS)?;
        let file = self.fs.open(&path, FLAGS, 0o600 & !self.umask())?;
        if let Some(parent) = parent {
            crate::permissions::own(self, creds, &path, false, &parent);
        }
        Ok(file)
    }
    /// Whether another thread shares the working directory and umask
    /// (`CLONE_FS`), as Linux's `fs_struct` counts its users.
    pub(crate) fn shares_fs(&self) -> bool {
        Arc::strong_count(&self.cwd) > 1
    }
    /// Entering a mount namespace: the working directory is its root, as
    /// Linux's `mntns_install` sets it.
    pub(crate) fn enter_root(&self) {
        self.change_directory(b"/".to_vec());
    }
    /// This task's own copy of the descriptor table, as `unshare_fd` gives
    /// one (for `unshare(CLONE_FILES)`, `CLOSE_RANGE_UNSHARE` and exec): of a
    /// table no other task shares, the same table, with its record locks, as
    /// Linux copies only a shared one. With `share_fs` the working directory
    /// stays shared.
    pub(crate) fn unshared(&self, share_fs: bool) -> Self {
        let mut copy = self.for_clone(false, share_fs);
        if Arc::strong_count(&self.fds) == 1 {
            copy.table = Arc::clone(&self.table);
        }
        copy
    }
    pub(crate) fn for_clone(&self, share_files: bool, share_fs: bool) -> Self {
        let mut child = self.clone();
        if !share_files {
            child.table = Arc::new(Table::new());
            child.fds = Arc::new(Mutex::new(
                self.fds
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .clone(),
            ));
            child.reserved = Arc::default();
        }
        if !share_fs {
            child.cwd = Arc::new(Mutex::new(
                self.cwd
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .clone(),
            ));
            child.home = Arc::new(Mutex::new(
                self.home
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .as_ref()
                    .map(crate::page_cache::Hold::copy),
            ));
            child.umask = Arc::new(AtomicU32::new(self.umask.load(Ordering::SeqCst)));
        }
        child
    }
}
/// The number of a descriptor table, which no other table has had.
#[derive(Debug)]
pub(crate) struct Table(u64);
impl Table {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        Self(NEXT.fetch_add(1, Ordering::Relaxed))
    }
}
/// The lowest number from `min` with no descriptor or reservation, which
/// must be below the RLIMIT_NOFILE soft limit `limit` (EMFILE), as in Linux's
/// alloc_fd.
fn lowest_free(
    fds: &BTreeMap<u32, Descriptor>,
    reserved: &BTreeSet<u32>,
    min: u32,
    limit: u64,
) -> Result<u32, Errno> {
    let mut n = min;
    while fds.contains_key(&n) || reserved.contains(&n) {
        n = n.checked_add(1).ok_or(Errno::EMFILE)?;
    }
    if u64::from(n) < limit {
        Ok(n)
    } else {
        Err(Errno::EMFILE)
    }
}
/// The path at `addr`, with a link in `/proc/self/fd` (or `/proc/self/cwd`,
/// `/proc/self/exe`, `/dev/fd`) before its last component taken to where it
/// leads ([`through_magic_links`]).
fn path(c: &Context<'_>, addr: u64) -> Result<Vec<u8>, Errno> {
    through_magic_links(c, string(c, addr)?)
}
/// Path `p` with each magic link it goes through, a link in a process's
/// `fd` directory, its `cwd` or `exe`, which Linux's walk (`nd_jump_link`)
/// does not read but jumps to the file of, replaced by that file's path: a
/// directory a descriptor holds by the path that names it now (it may have
/// been renamed), a removed one is ENOENT, and a file that is not a
/// directory ENOTDIR. A link the path ends in is left to the call, which
/// may not follow it.
fn through_magic_links(c: &Context<'_>, mut p: Vec<u8>) -> Result<Vec<u8>, Errno> {
    for _ in 0..40 {
        if !p.starts_with(b"/proc/") && !p.starts_with(b"/dev/") {
            return Ok(p);
        }
        let jump = (1..p.len()).filter(|&i| p[i] == b'/').find_map(|i| {
            let prefix = crate::devices::through_link(&p[..i]).unwrap_or_else(|| p[..i].to_vec());
            let prefix = match crate::devices::entry(&prefix) {
                Some(crate::devices::Entry::Link(target)) => target.to_vec(),
                _ => prefix,
            };
            magic_link_directory(c, &prefix).map(|target| (target, i))
        });
        let Some((target, at)) = jump else {
            return Ok(p);
        };
        let mut next = target?;
        next.extend_from_slice(&p[at..]);
        p = next;
    }
    Err(Errno(40)) // ELOOP
}
/// The directory magic link `path` leads to, for [`through_magic_links`],
/// or `None` when `path` is not one.
fn magic_link_directory(c: &Context<'_>, path: &[u8]) -> Option<Result<Vec<u8>, Errno>> {
    const ENOTDIR: Errno = Errno::ENOTDIR;
    let is_dir = |stat: FileStat| stat.mode & 0o170000 == 0o040000;
    match crate::proc::own_entry(path, c.process.pid) {
        Some(crate::proc::OwnEntry::Descriptor(n)) => Some((|| {
            let d = c
                .files
                .descriptor(u64::from(n))
                .map_err(|_| Errno::ENOENT)?;
            let stat = d.file.stat()?;
            if !is_dir(stat) || d.file.as_any().is_some_and(|v| v.is::<LinkPath>()) {
                return Err(ENOTDIR);
            }
            let path = d.file.guest_path_hint().unwrap_or_else(|| d.path.clone());
            // The path still names the directory, or it was removed.
            let named = generated(&path)
                || c.files
                    .fs
                    .metadata(&path, true)
                    .is_ok_and(|now| now.inode == stat.inode);
            if named { Ok(path) } else { Err(Errno::ENOENT) }
        })()),
        Some(entry @ (crate::proc::OwnEntry::Cwd | crate::proc::OwnEntry::Exe)) => {
            let target = own_link(c, entry)?;
            Some(if entry == crate::proc::OwnEntry::Exe {
                Err(ENOTDIR)
            } else {
                Ok(target)
            })
        }
        _ => {
            let task_path = crate::proc::task_path(path, c.process.pid, c.tid)?;
            match task_path.entry {
                crate::proc::TaskEntry::Exe => Some(Err(ENOTDIR)),
                crate::proc::TaskEntry::Cwd => Some(own_link_target(c, path).ok_or(Errno::ENOENT)),
                _ => None,
            }
        }
    }
}
/// The NUL-terminated string at `addr`, of at most 4096 bytes.
pub(crate) fn string(c: &Context<'_>, addr: u64) -> Result<Vec<u8>, Errno> {
    if addr == 0 {
        return Err(Errno::EFAULT);
    }
    let mut b = Vec::new();
    for i in 0..4096 {
        let mut v = [0];
        c.mem
            .read(GuestAddr(addr.checked_add(i).ok_or(Errno::EFAULT)?), &mut v)
            .map_err(|_| Errno::EFAULT)?;
        if v[0] == 0 {
            return Ok(b);
        }
        b.push(v[0]);
    }
    Err(Errno::ENAMETOOLONG)
}
/// The path `raw` names from `dir`, and what Linux's walk to it found with
/// the thread's credentials, after its search permission checks
/// ([`crate::permissions::search`]).
fn lookup(
    c: &Context<'_>,
    dir: u64,
    raw: Vec<u8>,
    follow: bool,
) -> Result<(Vec<u8>, crate::permissions::Found), Errno> {
    let p = c.files.path(dir, raw.clone())?;
    let found = crate::permissions::search(c.files, &c.process.credentials, dir, &raw, follow)?;
    Ok((p, found))
}
/// [`lookup`] of the path at `ptr`.
fn looked_up(
    c: &Context<'_>,
    dir: u64,
    ptr: u64,
    follow: bool,
) -> Result<(Vec<u8>, crate::permissions::Found), Errno> {
    lookup(c, dir, path(c, ptr)?, follow)
}
/// The file `inotify_add_watch` watches, as Linux's `inotify_find_inode`
/// finds it: what the path at `ptr` names (the last symbolic link itself
/// without `follow`), a directory with `directory` (ENOTDIR), and one the
/// caller may read (EACCES); by its device and inode, with its file
/// system (`f_type`).
pub(crate) fn watched(
    c: &Context<'_>,
    ptr: u64,
    follow: bool,
    directory: bool,
) -> Result<(crate::page_cache::Key, u64), Errno> {
    let (p, _) = looked_up(c, (-100i32) as u64, ptr, follow)?;
    let (stat, device, kind) = named(c, &p, follow)?;
    if directory && stat.mode & 0o170000 != 0o040000 {
        return Err(Errno::ENOTDIR);
    }
    crate::permissions::permission(&c.process.credentials, &stat, 4)?;
    Ok(((device, stat.inode), kind))
}
/// The device of the file `path` names, by the mount it is in once its
/// links are resolved, as the changes inotify hears of name it.
fn watched_device(c: &Context<'_>, path: &[u8], follow: bool) -> u64 {
    let place = if follow {
        resolved(c.files, path)
    } else {
        path.iter().rposition(|&b| b == b'/').and_then(|at| {
            let mut directory = resolved(c.files, &path[..at.max(1)])?;
            if directory != b"/" {
                directory.push(b'/');
            }
            directory.extend_from_slice(&path[at + 1..]);
            Some(directory)
        })
    };
    device(c, place.as_deref().unwrap_or(path))
}
/// `faccessat2(dirfd, path, mode, flags)`: with the real IDs, as Linux's
/// `access_override_creds` gives them, or the filesystem ones with
/// `AT_EACCESS`; root may read and write anything, and execute a directory
/// or a file with an execute bit.
fn access(c: &Context<'_>, dir: u64, ptr: u64, mode: u64, flags: u64) -> Result<u64, Errno> {
    const AT_EACCESS: u64 = 0x200;
    if mode & !7 != 0 || flags & !(AT_SYMLINK_NOFOLLOW | AT_EACCESS | AT_EMPTY_PATH) != 0 {
        return Err(Errno::EINVAL);
    }
    let creds = if flags & AT_EACCESS != 0 {
        c.process.credentials.clone()
    } else {
        c.process.credentials.for_access()
    };
    let raw = path(c, ptr)?;
    let stat = if raw.is_empty() && flags & AT_EMPTY_PATH != 0 {
        c.files.descriptor(dir)?.file.stat()?
    } else {
        let p = c.files.path(dir, raw.clone())?;
        let follow = flags & AT_SYMLINK_NOFOLLOW == 0;
        crate::permissions::search(c.files, &creds, dir, &raw, follow)?;
        match generated_stat(c, &p, follow)? {
            Some((stat, ..)) => stat,
            None => c.files.fs.metadata(&p, follow)?,
        }
    };
    crate::permissions::permission(&creds, &stat, mode as u32)?;
    Ok(0)
}
/// What `statfs` reports for a pipe, a socket, /proc or a terminal: an
/// empty pseudo filesystem of type `kind`, with the page as its block, as
/// Linux's `simple_statfs` gives whatever the superblock's block size.
fn pseudo_fs(kind: u64) -> paludarium_host::FsStats {
    paludarium_host::FsStats {
        kind,
        block_size: u64::from(BLOCK_SIZE),
        name_max: 255,
        ..Default::default()
    }
}
/// What `fstatfs` reports for the file `d` holds: an empty pseudo
/// filesystem for a /proc file (procfs), a terminal (devpts), a pipe, a
/// socket, a pidfd (pidfs) or another file of no type (Linux's anonymous
/// inodes), else the statistics of the filesystem holding its path.
fn descriptor_statfs(c: &Context<'_>, d: &Descriptor) -> Result<paludarium_host::FsStats, Errno> {
    if in_proc(&d.path) {
        return Ok(pseudo_fs(PROC_SUPER_MAGIC));
    }
    if is_terminal(c, d) {
        return Ok(pseudo_fs(DEVPTS_SUPER_MAGIC));
    }
    if crate::mqueue::is_queue(&*d.file) || d.path == b"/dev/mqueue" {
        return Ok(pseudo_fs(MQUEUE_MAGIC));
    }
    if d.file
        .as_any()
        .and_then(|v| v.downcast_ref::<crate::memfd::Memfd>())
        .is_some_and(crate::memfd::Memfd::is_secret)
    {
        return Ok(pseudo_fs(crate::memfd::SECRETMEM_MAGIC));
    }
    if d.file
        .as_any()
        .is_some_and(|v| v.is::<crate::processes::PidFd>())
    {
        return Ok(pseudo_fs(PID_FS_MAGIC));
    }
    Ok(match d.file.stat()?.mode & 0o170000 {
        0o010000 => pseudo_fs(0x5049_5045), // PIPEFS_MAGIC
        0o140000 => pseudo_fs(0x534F_434B), // SOCKFS_MAGIC
        0 if !is_namespace(d) => pseudo_fs(ANON_INODE_FS_MAGIC),
        _ => c
            .files
            .fs
            .statfs(&d.path)
            .or_else(|_| c.files.fs.statfs(b"/"))?,
    })
}
/// Linux's 120-byte `struct statfs`. `f_flags` is ST_VALID and `f_fsid` 0.
fn write_statfs(c: &Context<'_>, addr: u64, s: paludarium_host::FsStats) -> Result<u64, Errno> {
    let mut b = [0u8; 120];
    for (i, v) in [
        s.kind,
        s.block_size,
        s.blocks,
        s.blocks_free,
        s.blocks_available,
        s.files,
        s.files_free,
        0, // f_fsid
        s.name_max,
        s.block_size, // f_frsize
        0x20,         // f_flags: ST_VALID
    ]
    .iter()
    .enumerate()
    {
        b[i * 8..i * 8 + 8].copy_from_slice(&v.to_le_bytes());
    }
    output(c, addr, &b)?;
    Ok(0)
}
/// `AT_FDCWD`, as the 64-bit register holds it.
const AT_FDCWD: u64 = -100i64 as u64;
const UTIME_NOW: u64 = (1 << 30) - 1;
const UTIME_OMIT: u64 = (1 << 30) - 2;
/// `utimensat(dirfd, path, times, flags)`, in the order Linux checks it.
fn utimensat(c: &mut Context<'_>, a: [u64; 6]) -> Result<u64, Errno> {
    let now = || c.host.clock(ClockId::Realtime).map(i128::from);
    // Setting both times to now (`ATTR_TOUCH`) needs less than setting them,
    // and leaving out or setting one to now less than giving one
    // (`ATTR_TIMES_SET`).
    let mut touch = true;
    let mut set = false;
    let (atime, mtime) = if a[2] == 0 {
        let now = now()?;
        (Some(now), Some(now))
    } else {
        let mut raw = [0u8; 32];
        c.mem
            .read(GuestAddr(a[2]), &mut raw)
            .map_err(|_| Errno::EFAULT)?;
        let field =
            |i: usize| u64::from_le_bytes(raw[i * 8..i * 8 + 8].try_into().unwrap_or([0; 8]));
        let mut times = [None, None];
        for (slot, i) in times.iter_mut().zip([0, 2]) {
            let (seconds, nanos) = (field(i) as i64, field(i + 1));
            touch &= nanos == UTIME_NOW;
            set |= nanos != UTIME_NOW && nanos != UTIME_OMIT;
            *slot = match nanos {
                UTIME_OMIT => None,
                UTIME_NOW => Some(now()?),
                0..1_000_000_000 => Some(i128::from(seconds) * 1_000_000_000 + i128::from(nanos)),
                _ => return Err(Errno::EINVAL),
            };
        }
        // Linux: "Nothing to do, we must not even check the path."
        if times == [None, None] {
            return Ok(0);
        }
        (times[0], times[1])
    };
    set_times_at(c, a, atime, mtime, (touch, set))
}
/// Linux's `do_utimes`: the times of the file `a[1]` names from `a[0]`
/// with the flags `a[3]`, or of descriptor `a[0]` for no path.
fn set_times_at(
    c: &mut Context<'_>,
    a: [u64; 6],
    atime: Option<i128>,
    mtime: Option<i128>,
    (touch, set): (bool, bool),
) -> Result<u64, Errno> {
    if a[3] & !(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH) != 0 {
        return Err(Errno::EINVAL);
    }
    // A null path with a descriptor is futimens.
    let descriptor = if a[1] == 0 && a[0] as i32 != -100 {
        if a[3] != 0 {
            return Err(Errno::EINVAL);
        }
        true
    } else {
        a[3] & AT_EMPTY_PATH != 0 && path(c, a[1])?.is_empty()
    };
    if descriptor {
        // `futimens` takes the descriptor as `fdget` does, which an `O_PATH`
        // one is not; `AT_EMPTY_PATH` takes it as a path.
        let file = if a[1] == 0 {
            io_descriptor(c, a[0])?
        } else {
            c.files.descriptor(a[0])?.file
        };
        crate::permissions::times(&c.process.credentials, &file.stat()?, touch, set)?;
        return file.set_times(atime, mtime).map(|()| 0);
    }
    let follow = a[3] & AT_SYMLINK_NOFOLLOW == 0;
    let (p, found) = looked_up(c, a[0], a[1], follow)?;
    match reached(c, &p, follow)? {
        Some(Followed::Path { path, follow }) => {
            let stat = c.files.fs.metadata(&path, follow)?;
            crate::permissions::times(&c.process.credentials, &stat, touch, set)?;
            return c
                .files
                .fs
                .set_times(&path, follow, atime, mtime)
                .map(|()| 0);
        }
        Some(Followed::File(d)) => {
            crate::permissions::times(&c.process.credentials, &d.file.stat()?, touch, set)?;
            return d.file.set_times(atime, mtime).map(|()| 0);
        }
        None => {}
    }
    if let Some(stat) = found.file {
        crate::permissions::times(&c.process.credentials, &stat, touch, set)?;
    }
    c.files.fs.set_times(&p, follow, atime, mtime).map(|()| 0)
}
/// `futimesat(dirfd, path, times)` and `utimes(path, times)`, as Linux's
/// `do_futimesat`: two `struct timeval`s (`EFAULT`), each with fewer than a
/// million microseconds (`EINVAL`, which `UTIME_NOW` and `UTIME_OMIT` are
/// too), or none for now; then `do_utimes` with no flags, so a null path
/// with a descriptor sets that descriptor's times.
fn futimesat(c: &mut Context<'_>, dirfd: u64, path: u64, times: u64) -> Result<u64, Errno> {
    let (atime, mtime, touch) = if times == 0 {
        let now = i128::from(c.host.clock(ClockId::Realtime)?);
        (now, now, true)
    } else {
        let [a_seconds, a_micros, m_seconds, m_micros] =
            crate::syscalls::read_words::<4>(c.mem, times)?;
        if [a_micros, m_micros]
            .iter()
            .any(|&micros| micros >= 1_000_000)
        {
            return Err(Errno::EINVAL);
        }
        let at = |seconds: u64, micros: u64| {
            i128::from(seconds as i64) * 1_000_000_000 + i128::from(micros) * 1000
        };
        (at(a_seconds, a_micros), at(m_seconds, m_micros), false)
    };
    set_times_at(
        c,
        [dirfd, path, 0, 0, 0, 0],
        Some(atime),
        Some(mtime),
        (touch, !touch),
    )
}
/// `utime(path, times)`: a `struct utimbuf` of whole seconds (`EFAULT`), or
/// none for now, then `do_utimes` from the working directory.
fn utime(c: &mut Context<'_>, path: u64, times: u64) -> Result<u64, Errno> {
    let (atime, mtime, touch) = if times == 0 {
        let now = i128::from(c.host.clock(ClockId::Realtime)?);
        (now, now, true)
    } else {
        let [access, modification] = crate::syscalls::read_words::<2>(c.mem, times)?;
        let at = |seconds: u64| i128::from(seconds as i64) * 1_000_000_000;
        (at(access), at(modification), false)
    };
    set_times_at(
        c,
        [AT_FDCWD, path, 0, 0, 0, 0],
        Some(atime),
        Some(mtime),
        (touch, !touch),
    )
}
/// The owner and group of a `chown` call, as kernel IDs: -1 leaves one as
/// it is, and one the caller's user namespace does not map is `EINVAL`
/// (`chown_common`).
fn owner_ids(c: &Context<'_>, uid: u64, gid: u64) -> Result<(Option<u32>, Option<u32>), Errno> {
    let user = &c.process.credentials.user;
    let id = |id: u64, ids: crate::users::Ids| match id as u32 {
        u32::MAX => Ok(None),
        id => user.kernel_of(ids, id).map(Some).ok_or(Errno::EINVAL),
    };
    Ok((
        id(uid, crate::users::Ids::User)?,
        id(gid, crate::users::Ids::Group)?,
    ))
}
/// The mode a file of `mode` has after `chown`, when it changes: as Linux's
/// `chown_common`, a file that is not a directory loses its set-user-ID bit,
/// and its set-group-ID bit when group execution is set or the caller may
/// not keep it (`keeps_sgid`, [`crate::permissions::chown`]), even when the
/// owner and group stay.
fn mode_after_chown(mode: u32, keeps_sgid: bool) -> Option<u32> {
    if mode & 0o170000 == 0o040000 {
        return None;
    }
    let mut kept = mode & !0o4000;
    if mode & 0o010 != 0 || !keeps_sgid {
        kept &= !0o2000;
    }
    (kept != mode).then_some(kept & 0o7777)
}
/// `fchown(fd, owner, group)`.
fn chown_file(
    c: &Context<'_>,
    file: &Arc<dyn FileHandle>,
    uid: u64,
    gid: u64,
) -> Result<u64, Errno> {
    let stat = file.stat()?;
    let (uid, gid) = owner_ids(c, uid, gid)?;
    let keeps_sgid = crate::permissions::chown(&c.process.credentials, &stat, uid, gid)?;
    file.set_owner(uid, gid)?;
    if let Some(mode) = mode_after_chown(stat.mode, keeps_sgid) {
        file.set_mode(mode)?;
    }
    Ok(0)
}
/// `chown` of `path`; with `follow` false (`lchown`) a final symbolic link
/// itself, which has no set-user-ID bit to lose. A link in `/proc/self/fd`
/// that it follows leads to the descriptor's file ([`Followed`]).
fn chown_path(
    c: &Context<'_>,
    path: &[u8],
    follow: bool,
    uid: u64,
    gid: u64,
) -> Result<u64, Errno> {
    match reached(c, path, follow)? {
        Some(Followed::Path { path, follow }) => return chown_path(c, &path, follow, uid, gid),
        Some(Followed::File(d)) => return chown_file(c, &d.file, uid, gid),
        None => {}
    }
    let stat = c.files.fs.metadata(path, follow)?;
    let (uid, gid) = owner_ids(c, uid, gid)?;
    let keeps_sgid = crate::permissions::chown(&c.process.credentials, &stat, uid, gid)?;
    c.files.fs.set_owner(path, follow, uid, gid)?;
    if let Some(mode) = mode_after_chown(stat.mode, keeps_sgid) {
        c.files.fs.set_mode(path, mode)?;
    }
    Ok(0)
}
/// `fchmodat2`, as Linux's `do_fchmodat`: `fchmodat` with flags.
/// `AT_SYMLINK_NOFOLLOW` gives a symbolic link `EOPNOTSUPP`, since its mode
/// cannot change, and `AT_EMPTY_PATH` changes the descriptor's file.
fn fchmodat2(c: &Context<'_>, a: [u64; 6]) -> Result<u64, Errno> {
    if a[3] & !(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH) != 0 {
        return Err(Errno::EINVAL);
    }
    let raw = path(c, a[1])?;
    let (p, stat) = if raw.is_empty() && a[3] & AT_EMPTY_PATH != 0 {
        if a[0] as i32 != -100 {
            let file = c.files.descriptor(a[0])?.file;
            let mode =
                crate::permissions::chmod(&c.process.credentials, &file.stat()?, a[2] as u32)?;
            return file.set_mode(mode).map(|()| 0);
        }
        let cwd = c
            .files
            .cwd
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let stat = c.files.fs.metadata(&cwd, true)?;
        (cwd, stat)
    } else {
        let follow = a[3] & AT_SYMLINK_NOFOLLOW == 0;
        let (p, _) = lookup(c, a[0], raw, follow)?;
        if let Some(target) = reached(c, &p, follow)? {
            return chmod_followed(c, target, a[2] as u32);
        }
        // A link in `/proc` or `/dev` not followed is a symbolic link too.
        let stat = match generated_stat(c, &p, follow)? {
            Some((stat, ..)) => stat,
            None => c.files.fs.metadata(&p, follow)?,
        };
        (p, stat)
    };
    if stat.mode & 0o170000 == 0o120000 {
        return Err(Errno::EOPNOTSUPP);
    }
    let mode = crate::permissions::chmod(&c.process.credentials, &stat, a[2] as u32)?;
    c.files.fs.set_mode(&p, mode).map(|()| 0)
}
/// The file of descriptor `fd` for a call that takes it as Linux's `fdget`
/// does (`fchmod`, `fchown`, `futimens`, `ftruncate`): an `O_PATH` descriptor is
/// `EBADF`, as only path calls (`AT_EMPTY_PATH`, a link in `/proc/self/fd`)
/// reach its file.
fn io_descriptor(c: &Context<'_>, fd: u64) -> Result<Arc<dyn FileHandle>, Errno> {
    let file = c.files.descriptor(fd)?.file;
    if file.flags() & O_PATH != 0 {
        return Err(Errno::EBADF);
    }
    Ok(file)
}
/// The checks `filename_create` makes of a new name before a link that
/// fails later: its directory is searched, and the name is not there.
fn new_name_free(c: &Context<'_>, dir: u64, raw: &[u8], new: &[u8]) -> Result<(), Errno> {
    crate::permissions::search(c.files, &c.process.credentials, dir, raw, false)?;
    if c.files.fs.metadata(new, false).is_ok() {
        return Err(Errno::EEXIST);
    }
    Ok(())
}
/// `link(old, new)` and `linkat(olddir, old, newdir, new, flags)`, as
/// Linux's `do_linkat`: `AT_SYMLINK_FOLLOW` follows a symbolic link the old
/// path ends in, and a link in `/proc/self/fd` to the descriptor's file, and
/// `AT_EMPTY_PATH` with an empty old path links the file `olddir` holds
/// (the working directory's, a directory, is EPERM). The old name is looked
/// up, the new one must not be there (EEXIST) and be on the same filesystem
/// (EXDEV), which the link finds, before `may_create`. A file no path names
/// any more is ENOENT, as Linux's `vfs_link` finds it with no links, and a
/// memfd, a pipe or a socket is on a filesystem of its own (EXDEV).
fn link(c: &Context<'_>, n: u64, a: [u64; 6]) -> Result<u64, Errno> {
    const AT_SYMLINK_FOLLOW: u64 = 0x400;
    let ((old_dir, old_ptr), (new_dir, new_ptr), flags) = if n == 86 {
        (((-100i32) as u64, a[0]), ((-100i32) as u64, a[1]), 0)
    } else {
        ((a[0], a[1]), (a[2], a[3]), a[4])
    };
    if flags & !(AT_SYMLINK_FOLLOW | AT_EMPTY_PATH) != 0 {
        return Err(Errno::EINVAL);
    }
    let follow = flags & AT_SYMLINK_FOLLOW != 0;
    let old_raw = path(c, old_ptr)?;
    if !(old_raw.is_empty() && flags & AT_EMPTY_PATH != 0) {
        let new_raw = path(c, new_ptr)?;
        let old_name = queue_name(&c.files.path(old_dir, old_raw.clone())?);
        let new_name = queue_name(&c.files.path(new_dir, new_raw.clone())?);
        if old_name.is_some() || new_name.is_some() {
            return link_queue(
                c,
                (old_dir, old_raw, follow),
                (new_dir, &new_raw),
                (old_name, new_name),
            );
        }
    }
    // A queue's descriptor is on its `mqueue` mount: `/dev/mqueue` for one
    // opened there, whose root has no `link`, else one mounted nowhere.
    if old_raw.is_empty() && flags & AT_EMPTY_PATH != 0 && old_dir as i32 != -100 {
        let d = c.files.descriptor(old_dir)?;
        if crate::mqueue::is_queue(&*d.file) {
            let new_raw = path(c, new_ptr)?;
            let new = c.files.path(new_dir, new_raw.clone())?;
            let name = queue_name(&new);
            match &name {
                Some(name) if crate::mqueue::mounted_there(c, name)? => {
                    return Err(Errno::EEXIST);
                }
                Some(_) => {}
                None => new_name_free(c, new_dir, &new_raw, &new)?,
            }
            if name.is_none() || queue_name(&d.path).is_none() {
                return Err(EXDEV);
            }
            crate::mqueue::may_change_root(c)?;
            return Err(Errno::EPERM);
        }
    }
    let target = if old_raw.is_empty() && flags & AT_EMPTY_PATH != 0 {
        if old_dir as i32 == -100 {
            Followed::Path {
                path: c.files.path(old_dir, b".".to_vec())?,
                follow: false,
            }
        } else {
            descriptor_followed(c.files, c.files.descriptor(old_dir)?)?
        }
    } else {
        let (old, _) = lookup(c, old_dir, old_raw, follow)?;
        match followed(c, &old, follow)? {
            Some(target) => target,
            // A dangling symbolic link leads nowhere (ENOENT).
            None if follow => Followed::Path {
                path: resolved(c.files, &old).ok_or(Errno::ENOENT)?,
                follow: false,
            },
            None => Followed::Path {
                path: old,
                follow: false,
            },
        }
    };
    let new_raw = path(c, new_ptr)?;
    let new = c.files.path(new_dir, new_raw.clone())?;
    let old = match target {
        Followed::Path { path, follow: true } => resolved(c.files, &path).unwrap_or(path),
        Followed::Path { path, .. } => path,
        // Not linkable: the new name is still looked up first.
        Followed::File(d) => {
            new_name_free(c, new_dir, &new_raw, &new)?;
            let named = !d.path.is_empty()
                && d.file
                    .as_any()
                    .is_none_or(|v| !v.is::<crate::memfd::Memfd>());
            if named && device(c, &d.path) == device(c, &new) {
                return Err(Errno::ENOENT);
            }
            return Err(EXDEV);
        }
    };
    // A file of `/proc` or `/dev` (a link in `/proc/self/fd` not followed)
    // is on procfs or devtmpfs, which the new name is not.
    if generated(&old) {
        new_name_free(c, new_dir, &new_raw, &new)?;
        return Err(EXDEV);
    }
    let source = c.files.fs.metadata(&old, false).ok();
    if source.is_some() && device(c, &old) == device(c, &new) {
        crate::permissions::create(c.files, &c.process.credentials, new_dir, &new_raw)?;
    }
    // Landlock's check (`hook_path_link`) of a new name on the same
    // filesystem, whatever the permission walk found.
    if c.process.credentials.landlock != Default::default()
        && device(c, &old) == device(c, &new)
        && let (Some((old_path, Some(_))), Some((new_path, None))) =
            (landlock_named(c, &old), landlock_named(c, &new))
    {
        crate::landlock::refer(c, &old_path, &new_path, false, 0)?;
    }
    // `vfs_link`: no link to an append-only or immutable file (EPERM).
    if let Some(source) = &source
        && device(c, &old) == device(c, &new)
    {
        attributes::unchangeable(source)?;
    }
    c.files.fs.link(&old, &new)?;
    Ok(0)
}
/// `getdents` and `getdents64(fd, buf, count)`: the directory's entries
/// from its position on, as many as fit in `count` bytes, as Linux's
/// `filldir` and `filldir64` write them (`EINVAL` when not even the first
/// fits). `old` writes the `linux_dirent` of `getdents`, whose `d_type` is
/// the last byte of each entry.
fn directory_entries(
    c: &mut Context<'_>,
    fd: u64,
    buf: u64,
    count: u32,
    old: bool,
) -> Result<u64, Errno> {
    let d = c.files.descriptor(fd)?;
    if d.file.stat()?.mode & 0o170000 != 0o040000 {
        return Err(Errno::ENOTDIR);
    }
    let task = crate::proc::task_path(&d.path, c.process.pid, c.tid);
    let entries = match crate::proc::own_entry(&d.path, c.process.pid) {
        _ if tasks::is_root(&d.path) => tasks::root_entries(c),
        _ if let Some(crate::sysctl::Entry::Directory(directory)) =
            crate::sysctl::entry(&d.path) =>
        {
            crate::sysctl::entries(directory)
        }
        _ if let Some(path) = task => tasks::entries(&tasks::find(c, &path)?, path.entry),
        Some(crate::proc::OwnEntry::Descriptors) => descriptor_entries(c, false),
        Some(crate::proc::OwnEntry::DescriptorInfos) => descriptor_entries(c, true),
        Some(crate::proc::OwnEntry::Directory) => own_entries(),
        _ if crate::devices::entry(&d.path) == Some(crate::devices::Entry::Directory) => {
            crate::devices::entries(c.files.fs.metadata(b"/", true)?.inode)
        }
        _ if crate::devices::entry(&d.path) == Some(crate::devices::Entry::Mqueue) => {
            crate::mqueue::mounted_entries(c, crate::devices::directory_stat().inode)
        }
        _ if crate::devices::entry(&d.path) == Some(crate::devices::Entry::Pts) => c
            .files
            .devpts
            .entries(crate::devices::directory_stat().inode),
        _ => c.files.fs.read_dir(&d.path)?,
    };
    let position = d.file.seek(0, 1)? as usize;
    let mut listed = d.listed.lock().unwrap_or_else(PoisonError::into_inner);
    listed.seek(position, &entries);
    let mut bytes = Vec::new();
    let mut returned = Vec::new();
    // Linux keeps the count in an `int`: one past `i32::MAX` is negative,
    // so no entry fits.
    let room = usize::try_from(count as i32).unwrap_or(0);
    // A `linux_dirent` has its name after 18 bytes and its type in its last
    // byte; a `linux_dirent64` has the type, then the name, after 18.
    let name_at = if old { 18 } else { 19 };
    for e in entries.iter().filter(|e| !listed.names.contains(&e.name)) {
        let size = (name_at + e.name.len() + 1 + usize::from(old)).div_ceil(8) * 8;
        if bytes.len() + size > room {
            if bytes.is_empty() {
                return Err(Errno::EINVAL);
            }
            break;
        }
        let pos = bytes.len();
        bytes.resize(pos + size, 0);
        bytes[pos..pos + 8].copy_from_slice(&e.inode.to_le_bytes());
        let next = position + returned.len() + 1;
        bytes[pos + 8..pos + 16].copy_from_slice(&(next as u64).to_le_bytes());
        bytes[pos + 16..pos + 18].copy_from_slice(&(size as u16).to_le_bytes());
        if old {
            bytes[pos + size - 1] = e.kind;
        } else {
            bytes[pos + 18] = e.kind;
        }
        bytes[pos + name_at..pos + name_at + e.name.len()].copy_from_slice(&e.name);
        returned.push(&e.name);
    }
    output(c, buf, &bytes)?;
    d.file.seek(returned.len() as i64, 1)?;
    listed.returned(&returned);
    Ok(bytes.len() as u64)
}
/// `ustat(dev, ubuf)`, as Linux's: the free blocks and inodes of the
/// filesystem whose device `dev` is, in the "new" encoding `stat`'s
/// `st_dev` has (`new_decode_dev`), else `EINVAL`. The devices here are the
/// mounts' (0:1 the root, as [`device`] numbers them) and the internal file
/// systems' ([`Internal`]), which have none free, as their `simple_statfs`
/// and the `shmem_statfs` of a tmpfs of no limits give. The 32-byte
/// `struct ustat` has an `int f_tfree`, which takes the count's low bits as
/// C's conversion does, and an `unsigned long f_tinode`; its names are
/// empty.
fn ustat(c: &Context<'_>, dev: u32, buf: u64) -> Result<u64, Errno> {
    let major = (dev & 0xfff00) >> 8;
    let minor = (dev & 0xff) | ((dev >> 12) & 0xfff00);
    let mut b = [0u8; 32];
    if !Internal::ALL.iter().any(|fs| fs.device() == u64::from(dev)) {
        let mounts = c.files.fs.mounts();
        let mount = (major == 0)
            .then(|| minor.checked_sub(1))
            .flatten()
            .and_then(|i| mounts.get(i as usize))
            .ok_or(Errno::EINVAL)?;
        let stats = c.files.fs.statfs(&mount.path)?;
        b[0..4].copy_from_slice(&(stats.blocks_free as i32).to_le_bytes());
        b[8..16].copy_from_slice(&stats.files_free.to_le_bytes());
    }
    output(c, buf, &b)?;
    Ok(0)
}
/// EBADF for a call that takes its descriptors as Linux's `fdget` does,
/// which refuses an `O_PATH` one: reads and writes, `lseek`, `flock`,
/// `getdents`, `sendfile` and `copy_file_range`, and `fcntl` but for the
/// commands `check_fcntl_cmd` lets through (duplicating, the descriptor
/// flags and `F_GETFL`). A descriptor that is not open is left to the call.
/// `splice`, `tee` and `vmsplice` refuse one themselves (`splice::file`),
/// after the checks Linux makes before `fdget`.
fn refuse_path_only(c: &Context<'_>, n: u64, a: [u64; 6]) -> Result<(), Errno> {
    let descriptors: &[u64] = match n {
        // read, readv, writev, pread64, pwrite64, preadv, pwritev, preadv2,
        // pwritev2, lseek, flock, getdents, getdents64
        0 | 8 | 17 | 18 | 19 | 20 | 73 | 78 | 217 | 295 | 296 | 327 | 328 => &a[..1],
        // sendfile(out, in), copy_file_range(in, _, out)
        40 => &a[..2],
        326 => &[a[0], a[2]],
        // F_DUPFD, F_GETFD, F_SETFD, F_GETFL, F_DUPFD_QUERY, F_DUPFD_CLOEXEC
        72 if !matches!(a[1] as u32, 0..=3 | 1027 | 1030) => &a[..1],
        _ => return Ok(()),
    };
    for &fd in descriptors {
        if c.files
            .descriptor(fd)
            .is_ok_and(|d| d.file.flags() & O_PATH != 0)
        {
            return Err(Errno::EBADF);
        }
    }
    Ok(())
}
/// `chmod` of the file a link in `/proc/self/fd` leads to, which the
/// descriptor's access does not limit: an `O_PATH` one's file changes too,
/// as glibc's `fchmodat` with `AT_SYMLINK_NOFOLLOW` has it. A symbolic link
/// has a mode that cannot change (`EOPNOTSUPP`, Linux's `notify_change`).
fn chmod_followed(c: &Context<'_>, target: Followed, mode: u32) -> Result<u64, Errno> {
    let creds = &c.process.credentials;
    match target {
        Followed::Path { path, follow } => {
            let stat = c.files.fs.metadata(&path, follow)?;
            if stat.mode & 0o170000 == 0o120000 {
                return Err(Errno::EOPNOTSUPP);
            }
            let mode = crate::permissions::chmod(creds, &stat, mode)?;
            c.files.fs.set_mode(&path, mode).map(|()| 0)
        }
        Followed::File(d) => {
            let mode = crate::permissions::chmod(creds, &d.file.stat()?, mode)?;
            d.file.set_mode(mode).map(|()| 0)
        }
    }
}
/// `fchownat(dirfd, path, owner, group, flags)`, in `do_fchownat`'s order:
/// the flags (EINVAL), then the path; an empty one with `AT_EMPTY_PATH`
/// names `dirfd` itself, or the working directory.
fn fchownat(c: &Context<'_>, a: [u64; 6]) -> Result<u64, Errno> {
    if a[4] & !(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH) != 0 {
        return Err(Errno::EINVAL);
    }
    let raw = path(c, a[1])?;
    if raw.is_empty() && a[4] & AT_EMPTY_PATH != 0 {
        if a[0] as i32 != -100 {
            return chown_file(c, &c.files.descriptor(a[0])?.file, a[2], a[3]);
        }
        let cwd = c
            .files
            .cwd
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        return chown_path(c, &cwd, true, a[2], a[3]);
    }
    let follow = a[4] & AT_SYMLINK_NOFOLLOW == 0;
    let (p, _) = lookup(c, a[0], raw, follow)?;
    chown_path(c, &p, follow, a[2], a[3])
}
fn output(c: &Context<'_>, addr: u64, b: &[u8]) -> Result<(), Errno> {
    c.mem.write(GuestAddr(addr), b).map_err(|_| Errno::EFAULT)
}
/// Linux's largest single read or write (`MAX_RW_COUNT`).
pub(crate) const MAX_RW_COUNT: usize = 0x7fff_f000;
/// The file a positioned read or write uses, checked in Linux's order: a
/// negative offset (EINVAL), the descriptor (EBADF), a file without a
/// position such as a pipe or socket (ESPIPE), then the access mode (EBADF).
fn positioned(
    c: &Context<'_>,
    fd: u64,
    offset: u64,
    write: bool,
) -> Result<Arc<dyn FileHandle>, Errno> {
    if (offset as i64) < 0 {
        return Err(Errno::EINVAL);
    }
    let file = c.files.descriptor(fd)?.file;
    file.seek(0, 1).map_err(|_| Errno::ESPIPE)?;
    // A signalfd and an inotify instance seek (Linux's `noop_llseek`) but
    // are not opened with FMODE_PREAD or FMODE_PWRITE.
    if file.as_any().is_some_and(|any| {
        any.is::<crate::signalfd::SignalFile>() || any.is::<crate::inotify::Instance>()
    }) {
        return Err(Errno::ESPIPE);
    }
    if file.flags() & 3 == if write { 0 } else { 1 } {
        return Err(Errno::EBADF);
    }
    Ok(file)
}
/// Where reads of a regular file stop: at its size, but for `maps`, which
/// and `smaps`, which say 0 as Linux's /proc does and end where their
/// `read` does.
fn read_limit(file: &Arc<dyn FileHandle>, metadata: &FileStat) -> u64 {
    if file
        .as_any()
        .is_some_and(|file| file.is::<crate::proc::MapsFile>())
    {
        u64::MAX
    } else {
        metadata.size
    }
}
/// The bytes to transfer for a request of `count` at `offset`: at most
/// `MAX_RW_COUNT`, and for a read of a regular file no more than it holds.
/// An end past the largest offset is EINVAL, and reading a directory EISDIR.
fn request(
    file: &Arc<dyn FileHandle>,
    count: u64,
    offset: u64,
    read: bool,
) -> Result<usize, Errno> {
    if (count as i64) < 0
        || offset
            .checked_add(count)
            .is_none_or(|end| end > i64::MAX as u64)
    {
        return Err(Errno::EINVAL);
    }
    let len = usize::try_from(count)
        .map_err(|_| Errno::EINVAL)?
        .min(MAX_RW_COUNT);
    if !read {
        return Ok(len);
    }
    let metadata = file.stat()?;
    match metadata.mode & 0o170000 {
        0o040000 => Err(Errno::EISDIR),
        // Saturating, so a remainder past usize (wasm32) does not wrap.
        0o100000 => Ok(len.min(
            usize::try_from(read_limit(file, &metadata).saturating_sub(offset))
                .unwrap_or(usize::MAX),
        )),
        _ => Ok(len),
    }
}
fn buffer(len: usize) -> Result<Vec<u8>, Errno> {
    let mut b = Vec::new();
    b.try_reserve(len).map_err(|_| Errno::ENOMEM)?;
    b.resize(len, 0);
    Ok(b)
}
/// A positioned read; a file kind without `read_at` reads through its
/// position, which is then put back.
fn read_at(file: &Arc<dyn FileHandle>, offset: u64, b: &mut [u8]) -> Result<usize, Errno> {
    match file.read_at(offset, b) {
        Err(e) if e == Errno::ENODEV => {
            let position = file.seek(0, 1)?;
            file.seek(offset as i64, 0)?;
            let result = file.read(b);
            file.seek(position as i64, 0)?;
            result
        }
        result => result,
    }
}
/// A positioned write, falling back like [`read_at`].
fn write_at(file: &Arc<dyn FileHandle>, offset: u64, b: &[u8]) -> Result<usize, Errno> {
    match file.write_at(offset, b) {
        Err(e) if e == Errno::ENODEV => {
            let position = file.seek(0, 1)?;
            file.seek(offset as i64, 0)?;
            let result = file.write(b);
            file.seek(position as i64, 0)?;
            result
        }
        result => result,
    }
}
/// The bytes of a `len`-byte write at `offset` (the file's position when
/// `None`) that RLIMIT_FSIZE lets through, as Linux's generic_write_checks:
/// an O_APPEND file starts at its size whatever the offset, as its pwrite
/// appends; only regular files are limited, and a write starting at or past
/// the limit raises SIGXFSZ and fails with EFBIG.
fn size_limited(
    c: &mut Context<'_>,
    file: &Arc<dyn FileHandle>,
    offset: Option<u64>,
    len: usize,
) -> Result<usize, Errno> {
    size_limited_by(c, file, len, |metadata| {
        Ok(match offset {
            _ if file.flags() & 0o2000 != 0 => metadata.size,
            Some(offset) => offset,
            None => file.seek(0, 1)?,
        })
    })
}
/// [`size_limited`] for a write that starts at `start` whatever the file's
/// `O_APPEND` (`RWF_NOAPPEND`).
fn size_limited_from(
    c: &mut Context<'_>,
    file: &Arc<dyn FileHandle>,
    start: u64,
    len: usize,
) -> Result<usize, Errno> {
    size_limited_by(c, file, len, |_| Ok(start))
}
/// The bytes of a `len`-byte write of a regular file that RLIMIT_FSIZE lets
/// through from where `start` says it starts.
fn size_limited_by(
    c: &mut Context<'_>,
    file: &Arc<dyn FileHandle>,
    len: usize,
    start: impl FnOnce(&FileStat) -> Result<u64, Errno>,
) -> Result<usize, Errno> {
    if c.group.fsize() == u64::MAX || len == 0 {
        return Ok(len);
    }
    let metadata = file.stat()?;
    if metadata.mode & 0o170000 != 0o100000 {
        return Ok(len);
    }
    let room = size_room(c, start(&metadata)?)?;
    Ok(len.min(usize::try_from(room).unwrap_or(usize::MAX)))
}
/// A positioned write with `RWF_NOAPPEND`: at `offset` even in an
/// `O_APPEND` file ([`FileHandle::write_at_unappended`]). A kind without it
/// writes as [`write_at`] does if it has no position to append at (a
/// device); a regular file of such a kind gives `EOPNOTSUPP` rather than
/// append.
fn write_at_unappended(file: &Arc<dyn FileHandle>, offset: u64, b: &[u8]) -> Result<usize, Errno> {
    match file.write_at_unappended(offset, b) {
        Err(e) if e == Errno::ENODEV => {
            if file.stat()?.mode & S_IFMT == S_IFREG {
                return Err(Errno::EOPNOTSUPP);
            }
            write_at(file, offset, b)
        }
        result => result,
    }
}
/// Whether a write with `flags` turns its file's `O_APPEND` off
/// (`RWF_NOAPPEND`, which clears `IOCB_APPEND`).
fn unappended(file: &Arc<dyn FileHandle>, flags: u32) -> bool {
    flags & RWF_NOAPPEND != 0 && file.flags() & O_APPEND != 0
}
/// The bytes RLIMIT_FSIZE lets a regular file take from `start`, as Linux's
/// generic_write_check_limits: from the limit on none, raising SIGXFSZ and
/// failing with EFBIG.
fn size_room(c: &mut Context<'_>, start: u64) -> Result<u64, Errno> {
    let limit = c.group.fsize();
    if limit == u64::MAX {
        return Ok(u64::MAX);
    }
    if start >= limit {
        crate::signals::queue(c.process, crate::signals::PendingSignal::user(25, 0));
        return Err(Errno(27));
    }
    Ok(limit - start)
}
const REGULAR: u32 = 0o100000;
/// A new inode number for a file on no mount (a pipe, a socket or a memfd),
/// so that no two share one, as Linux numbers its pipefs, sockfs and tmpfs
/// inodes.
pub(crate) fn anonymous_inode() -> u64 {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}
const DIRECTORY: u32 = 0o040000;
/// A guest `loff_t *` argument: none when null, else its value (EFAULT).
fn offset_argument(c: &Context<'_>, at: u64) -> Result<Option<u64>, Errno> {
    if at == 0 {
        return Ok(None);
    }
    c.mem
        .read_u64(GuestAddr(at))
        .map(Some)
        .map_err(|_| Errno::EFAULT)
}
/// Copies up to `count` bytes from `input` at `from` to `output` at `to`, in
/// pieces, stopping early at the input's end or a short write. An error
/// after some bytes are copied ends the copy with their count, as Linux
/// reports it on the next call.
fn copy_bytes(
    input: &Arc<dyn FileHandle>,
    from: u64,
    output: &Arc<dyn FileHandle>,
    to: u64,
    count: u64,
) -> Result<u64, Errno> {
    let mut piece = buffer(usize::try_from(count).unwrap_or(usize::MAX).min(1 << 20))?;
    let mut done = 0;
    while done < count {
        let want = usize::try_from(count - done).map_or(piece.len(), |n| n.min(piece.len()));
        let copied = read_at(input, from + done, &mut piece[..want])
            .and_then(|read| Ok((read, write_at(output, to + done, &piece[..read])?)));
        let (read, written) = match copied {
            Ok(counts) => counts,
            Err(_) if done > 0 => break,
            Err(error) => return Err(error),
        };
        done += written as u64;
        if read == 0 || written < read {
            break;
        }
    }
    Ok(done)
}
/// `fallocate(fd, mode, offset, len)`, with the checks of Linux's
/// vfs_fallocate in order. Files behave as on tmpfs: plain allocation (which
/// may grow the file) allocates the pages of the range, `FALLOC_FL_KEEP_SIZE`
/// keeps the size, `FALLOC_FL_PUNCH_HOLE` frees the pages it covers, and the
/// other modes give `EOPNOTSUPP`.
fn fallocate(c: &mut Context<'_>, a: [u64; 6]) -> Result<u64, Errno> {
    const KEEP_SIZE: u32 = 0x01;
    const PUNCH_HOLE: u32 = 0x02;
    // PUNCH_HOLE, COLLAPSE_RANGE, ZERO_RANGE, INSERT_RANGE, UNSHARE_RANGE
    // and WRITE_ZEROES; plain allocation is no bit.
    const MODE_MASK: u32 = 0xfa;
    const EOPNOTSUPP: Errno = Errno(95);
    let d = c.files.descriptor(a[0])?;
    let (mode, offset, len) = (a[1] as u32, a[2] as i64, a[3] as i64);
    if offset < 0 || len <= 0 {
        return Err(Errno::EINVAL);
    }
    if mode & !(MODE_MASK | KEEP_SIZE) != 0 {
        return Err(EOPNOTSUPP);
    }
    match mode & MODE_MASK {
        // Allocation, UNSHARE_RANGE and ZERO_RANGE take KEEP_SIZE or not.
        0 | 0x40 | 0x10 => {}
        PUNCH_HOLE if mode & KEEP_SIZE != 0 => {}
        // COLLAPSE_RANGE, INSERT_RANGE and WRITE_ZEROES do not take it.
        0x08 | 0x20 | 0x80 if mode & KEEP_SIZE == 0 => {}
        _ => return Err(EOPNOTSUPP),
    }
    if d.file.flags() & 3 == 0 {
        return Err(Errno::EBADF);
    }
    let stat = d.file.stat()?;
    // `vfs_fallocate`: an append-only file only preallocates, and an
    // immutable one not even that (EPERM), before the file's type.
    if (mode & !KEEP_SIZE != 0 && attributes::append_only(&stat)) || attributes::immutable(&stat) {
        return Err(Errno::EPERM);
    }
    match stat.mode & 0o170000 {
        0o010000 => return Err(Errno::ESPIPE),
        DIRECTORY => return Err(Errno::EISDIR),
        REGULAR => {}
        _ => return Err(Errno(19)), // ENODEV
    }
    let end = offset.checked_add(len).ok_or(Errno(27))? as u64; // EFBIG
    let memfd = d
        .file
        .as_any()
        .and_then(|v| v.downcast_ref::<crate::memfd::Memfd>());
    // A secret file has no `fallocate`.
    if memfd.is_some_and(crate::memfd::Memfd::is_secret) {
        return Err(Errno::EOPNOTSUPP);
    }
    match mode & MODE_MASK {
        0 => {
            let grows = end > stat.size;
            // Going past RLIMIT_FSIZE raises SIGXFSZ (inode_newsize_ok); a
            // memfd, a tmpfs file, is checked even with KEEP_SIZE, as
            // shmem_fallocate checks it, and then its F_SEAL_GROW.
            if grows && (mode & KEEP_SIZE == 0 || memfd.is_some()) && end > c.group.fsize() {
                crate::signals::queue(c.process, crate::signals::PendingSignal::user(25, 0));
                return Err(Errno(27));
            }
            if let Some(memfd) = memfd {
                memfd.check_allocate(end)?;
            }
            // The pages of the range are allocated, and count in st_blocks.
            d.file.allocate(offset as u64, len as u64)?;
            if grows && mode & KEEP_SIZE == 0 {
                d.file.truncate(end)?;
            }
        }
        PUNCH_HOLE => d.file.zero_range(offset as u64, len as u64)?,
        _ => return Err(EOPNOTSUPP),
    }
    crate::permissions::remove_set_ids(&c.process.credentials, &*d.file);
    Ok(0)
}
/// `fallocate` of `FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE` over
/// `[offset, offset + len)` of `file`, as `madvise(MADV_REMOVE)` asks
/// Linux's vfs_fallocate for it, with [`fallocate`]'s checks in its order.
pub(crate) fn punch_hole(
    credentials: &crate::credentials::Credentials,
    file: &Arc<dyn FileHandle>,
    offset: u64,
    len: u64,
) -> Result<(), Errno> {
    if file.flags() & 3 == 0 {
        return Err(Errno::EBADF);
    }
    let stat = file.stat()?;
    if attributes::append_only(&stat) || attributes::immutable(&stat) {
        return Err(Errno::EPERM);
    }
    match stat.mode & 0o170000 {
        0o010000 => return Err(Errno::ESPIPE),
        DIRECTORY => return Err(Errno::EISDIR),
        REGULAR => {}
        _ => return Err(Errno(19)), // ENODEV
    }
    if offset
        .checked_add(len)
        .is_none_or(|end| end > i64::MAX as u64)
    {
        return Err(Errno(27)); // EFBIG
    }
    let memfd = file
        .as_any()
        .and_then(|v| v.downcast_ref::<crate::memfd::Memfd>());
    if memfd.is_some_and(crate::memfd::Memfd::is_secret) {
        return Err(Errno::EOPNOTSUPP);
    }
    file.zero_range(offset, len)?;
    crate::permissions::remove_set_ids(credentials, &**file);
    Ok(())
}
/// `close_range(first, last, flags)`, as Linux's ksys_close_range: the
/// arguments are `unsigned int`s, numbers with no open descriptor are skipped,
/// `CLOSE_RANGE_CLOEXEC` marks instead of closing, and `CLOSE_RANGE_UNSHARE`
/// first gives this thread its own copy of a shared table.
fn close_range(c: &mut Context<'_>, a: [u64; 6]) -> Result<u64, Errno> {
    const CLOSE_RANGE_UNSHARE: u32 = 2;
    const CLOSE_RANGE_CLOEXEC: u32 = 4;
    let (first, last, flags) = (a[0] as u32, a[1] as u32, a[2] as u32);
    if flags & !(CLOSE_RANGE_UNSHARE | CLOSE_RANGE_CLOEXEC) != 0 || first > last {
        return Err(Errno::EINVAL);
    }
    if flags & CLOSE_RANGE_UNSHARE != 0 {
        *c.files = c.files.unshared(true);
    }
    let mut fds = c.files.fds.lock().unwrap_or_else(PoisonError::into_inner);
    if flags & CLOSE_RANGE_CLOEXEC != 0 {
        for descriptor in fds.range_mut(first..=last).map(|(_, d)| d) {
            descriptor.cloexec = true;
        }
        return Ok(0);
    }
    let closed = fds
        .extract_if(first..=last, |_, _| true)
        .collect::<Vec<_>>();
    // The closed files are released only after the table is unlocked.
    drop(fds);
    for descriptor in closed.into_iter().map(|(_, d)| d) {
        crate::record_locks::closed(c, &descriptor);
        crate::mqueue::closed(c, &descriptor);
        crate::inet::linger(c, &descriptor.file);
    }
    Ok(0)
}
/// `cachestat(fd, range, stat, flags)`, as Linux's: a descriptor `fdget`
/// takes (EBADF, also for `O_PATH`), a `struct cachestat_range` (`off`,
/// `len`; EFAULT), a file the caller may write or could open to (EPERM,
/// `can_do_cachestat`), no flags (EINVAL), then the `struct cachestat` of
/// the pages from `off` for `len` bytes, or to the end for 0. A file in
/// memory has its allocated pages cached, as tmpfs has them, none dirty or
/// under writeback (tmpfs tags none) or evicted (no swap); any other file
/// has none that the emulator keeps.
fn cachestat(c: &Context<'_>, a: [u64; 6]) -> Result<u64, Errno> {
    let file = io_descriptor(c, a[0])?;
    let [off, len] = crate::syscalls::read_words::<2>(c.mem, a[1])?;
    let creds = &c.process.credentials;
    if file.flags() & 3 == 0 {
        let stat = file.stat()?;
        if !crate::permissions::owner_or_capable(creds, &stat)
            && crate::permissions::permission(creds, &stat, crate::permissions::MAY_WRITE).is_err()
        {
            return Err(Errno::EPERM);
        }
    }
    if a[3] != 0 {
        return Err(Errno::EINVAL);
    }
    let first = off >> 12;
    let last = if len == 0 {
        u64::MAX
    } else {
        off.wrapping_add(len).wrapping_sub(1) >> 12
    };
    let cached = file.cached_pages(first, last);
    let mut out = [0u8; 40];
    out[..8].copy_from_slice(&cached.to_le_bytes());
    output(c, a[2], &out)?;
    Ok(0)
}
/// `copy_file_range(fd_in, off_in, fd_out, off_out, len, flags)`, with the
/// checks of Linux's generic_copy_file_checks and rw_verify_area in order.
fn copy_file_range(c: &mut Context<'_>, a: [u64; 6]) -> Result<u64, Errno> {
    if a[5] != 0 {
        return Err(Errno::EINVAL);
    }
    let input = c.files.descriptor(a[0])?;
    let output = c.files.descriptor(a[2])?;
    // A file without a position (a pipe) is at 0, and fails as no regular file.
    let from = match offset_argument(c, a[1])? {
        Some(offset) => offset,
        None => input.file.seek(0, 1).unwrap_or(0),
    };
    let to = match offset_argument(c, a[3])? {
        Some(offset) => offset,
        None => output.file.seek(0, 1).unwrap_or(0),
    };
    let (source, target) = (input.file.stat()?, output.file.stat()?);
    if source.mode & 0o170000 == DIRECTORY || target.mode & 0o170000 == DIRECTORY {
        return Err(Errno::EISDIR);
    }
    if source.mode & 0o170000 != REGULAR || target.mode & 0o170000 != REGULAR {
        return Err(Errno::EINVAL);
    }
    if input.file.flags() & 3 == 1
        || output.file.flags() & 3 == 0
        || output.file.flags() & 0o2000 != 0
    {
        return Err(Errno::EBADF);
    }
    // Both files must be on one filesystem.
    let same_mount = descriptor_device(c, &input) == descriptor_device(c, &output);
    if !same_mount {
        return Err(Errno(18));
    }
    // An immutable file is not written (`generic_copy_file_checks`).
    if attributes::immutable(&target) {
        return Err(Errno::EPERM);
    }
    // Offsets that wrap with the requested length, compared as unsigned (a
    // negative one wraps with a long enough request).
    if from.checked_add(a[4]).is_none() || to.checked_add(a[4]).is_none() {
        return Err(Errno::EOVERFLOW);
    }
    // Shortened to the input's end, then to what RLIMIT_FSIZE allows.
    let mut count = if (from as i64) >= 0 && from >= source.size {
        0
    } else {
        a[4].min(source.size.wrapping_sub(from))
    };
    if (to as i64) >= 0 {
        count = count.min(size_room(c, to)?);
    }
    if same_mount
        && source.inode == target.inode
        && to.wrapping_add(count) > from
        && to < from.wrapping_add(count)
    {
        return Err(Errno::EINVAL);
    }
    for start in [from, to] {
        if (start as i64) < 0
            || start
                .checked_add(count)
                .is_none_or(|end| end > i64::MAX as u64)
        {
            return Err(Errno::EINVAL);
        }
    }
    let count = count.min(MAX_RW_COUNT as u64);
    if count == 0 {
        return Ok(0);
    }
    let copied = copy_bytes(&input.file, from, &output.file, to, count)?;
    if copied > 0 {
        crate::permissions::remove_set_ids(&c.process.credentials, &*output.file);
    }
    for (pointer, file, start) in [(a[1], &input.file, from), (a[3], &output.file, to)] {
        if pointer != 0 {
            c.mem
                .write_u64(GuestAddr(pointer), start + copied)
                .map_err(|_| Errno::EFAULT)?;
        } else {
            file.seek((start + copied) as i64, 0)?;
        }
    }
    Ok(copied)
}
/// `sendfile(out_fd, in_fd, offset, count)`, in the order of Linux's
/// do_sendfile: the input must be a readable regular file, and the output a
/// writable file without O_APPEND. Given an offset, the input's position
/// stays and the offset is written back, even after an error.
fn sendfile(c: &mut Context<'_>, a: [u64; 6]) -> Result<u64, Errno> {
    let offset = offset_argument(c, a[2])?;
    let result = send(c, a[0], a[1], offset, a[3]);
    if let Some(start) = offset {
        let sent = result.as_ref().map_or(0, |sent| *sent);
        c.mem
            .write_u64(GuestAddr(a[2]), start + sent)
            .map_err(|_| Errno::EFAULT)?;
    }
    result
}
fn send(
    c: &mut Context<'_>,
    out: u64,
    fd: u64,
    offset: Option<u64>,
    count: u64,
) -> Result<u64, Errno> {
    let input = c.files.descriptor(fd)?.file;
    if input.flags() & 3 == 1 {
        return Err(Errno::EBADF);
    }
    // An offset needs a file with a position (ESPIPE); without one, a pipe
    // input is at 0 and fails below as no regular file.
    let position = input.seek(0, 1);
    let from = match offset {
        Some(offset) => position.map(|_| offset).map_err(|_| Errno::ESPIPE)?,
        None => position.unwrap_or(0),
    };
    if (count as i64) < 0
        || (from as i64) < 0
        || from
            .checked_add(count)
            .is_none_or(|end| end > i64::MAX as u64)
    {
        return Err(Errno::EINVAL);
    }
    let count = count.min(MAX_RW_COUNT as u64);
    let output = c.files.descriptor(out)?.file;
    if output.flags() & 3 == 0 {
        return Err(Errno::EBADF);
    }
    let pipe = output
        .as_any()
        .and_then(|any| any.downcast_ref::<crate::sockets::PipeEnd>())
        .map(crate::sockets::PipeEnd::size);
    // do_splice_direct refuses O_APPEND; a pipe output does not use it.
    if pipe.is_none() && output.flags() & 0o2000 != 0 {
        return Err(Errno::EINVAL);
    }
    if count == 0 {
        return Ok(0);
    }
    let source = input.stat()?;
    if source.mode & 0o170000 != REGULAR {
        return Err(Errno::EINVAL);
    }
    let count = count.min(read_limit(&input, &source).saturating_sub(from));
    if count == 0 {
        return Ok(0);
    }
    let sent = if output.stat()?.mode & 0o170000 == REGULAR {
        let to = output.seek(0, 1)?;
        let count = count.min(size_room(c, to)?);
        let sent = copy_bytes(&input, from, &output, to, count)?;
        if sent > 0 {
            crate::permissions::remove_set_ids(&c.process.credentials, &*output);
        }
        output.seek((to + sent) as i64, 0)?;
        sent
    } else {
        // A pipe takes at most what it holds, as splice_file_to_pipe does;
        // other files take 1 MiB pieces until a short write.
        let count = pipe.map_or(count, |size| count.min(size));
        let mut piece = buffer(usize::try_from(count).unwrap_or(usize::MAX).min(1 << 20))?;
        let mut sent = 0;
        while sent < count {
            let want = usize::try_from(count - sent).map_or(piece.len(), |n| n.min(piece.len()));
            let written = read_at(&input, from + sent, &mut piece[..want])
                .and_then(|read| Ok((read, write_io(c, &output, &piece[..read], false)?)));
            let (read, written) = match written {
                Ok(counts) => counts,
                Err(_) if sent > 0 => break,
                Err(error) => return Err(error),
            };
            sent += written;
            if read == 0 || written < read as u64 {
                break;
            }
        }
        sent
    };
    if offset.is_none() {
        input.seek((from + sent) as i64, 0)?;
    }
    Ok(sent)
}
/// The `struct iovec` array of readv, writev and their positioned forms, as
/// Linux's `import_iovec` reads it (see [`iovecs_checked`]), each buffer
/// then mapped for the transfer (EFAULT).
pub(crate) fn iovecs(
    c: &Context<'_>,
    at: u64,
    count: u64,
    write: bool,
) -> Result<Vec<(u64, usize)>, Errno> {
    iovecs_checked(c.mem, at, count, |base, length| {
        if write {
            c.mem.check_write(GuestAddr(base), length)
        } else {
            c.mem.check_read(GuestAddr(base), length)
        }
        .map_err(|_| Errno::EFAULT)
    })
}
/// The `struct iovec` array at `at`, in Linux's `import_iovec` order: none
/// for no entries; more than 1024 are EINVAL; the array must lie in the user
/// half (EFAULT); then every entry is read (EFAULT) and a negative length is
/// EINVAL, in order, before any buffer is looked at; then each buffer is
/// `access_ok` (EFAULT), with its whole length when there are several and
/// cut to `MAX_RW_COUNT` first when there is one (`import_ubuf`), and the
/// lengths are cut so that the total is at most `MAX_RW_COUNT`. `check` then
/// looks at each cut buffer in turn.
pub(crate) fn iovecs_checked(
    mem: &AddressSpace,
    at: u64,
    count: u64,
    check: impl Fn(u64, usize) -> Result<(), Errno>,
) -> Result<Vec<(u64, usize)>, Errno> {
    if count == 0 {
        return Ok(Vec::new());
    }
    if count > 1024 {
        return Err(Errno::EINVAL);
    }
    crate::sockets::access_ok(at, (count * 16) as usize)?;
    let mut entries = Vec::with_capacity(count as usize);
    for index in 0..count {
        let addr = at + index * 16;
        let base = mem.read_u64(GuestAddr(addr)).map_err(|_| Errno::EFAULT)?;
        let length = mem
            .read_u64(GuestAddr(addr + 8))
            .map_err(|_| Errno::EFAULT)?;
        if (length as i64) < 0 {
            return Err(Errno::EINVAL);
        }
        entries.push((base, length));
    }
    // The lengths stay 64-bit until they are cut, as `usize` is 32 bits in
    // WebAssembly.
    let mut segments = Vec::with_capacity(entries.len());
    let mut total = 0usize;
    for (base, length) in entries {
        let cut = length.min((MAX_RW_COUNT - total) as u64);
        crate::sockets::access_ok_u64(base, if count == 1 { cut } else { length })?;
        let cut = cut as usize;
        total += cut;
        segments.push((base, cut));
    }
    for &(base, length) in &segments {
        check(base, length)?;
    }
    Ok(segments)
}
/// Copies `bytes` into the guest buffers of `segments`, in order.
pub(crate) fn scatter(
    c: &Context<'_>,
    segments: &[(u64, usize)],
    mut bytes: &[u8],
) -> Result<(), Errno> {
    for &(base, length) in segments {
        let (head, rest) = bytes.split_at(length.min(bytes.len()));
        output(c, base, head)?;
        bytes = rest;
    }
    Ok(())
}
/// `preadv2`'s and `pwritev2`'s flags (`RWF_*`). `RWF_HIPRI` (0x1), which
/// polls for a direct transfer, changes nothing for these buffered ones.
const RWF_HIPRI: u32 = 0x1;
const RWF_DSYNC: u32 = 0x2;
const RWF_SYNC: u32 = 0x4;
const RWF_NOWAIT: u32 = 0x8;
const RWF_APPEND: u32 = 0x10;
const RWF_NOAPPEND: u32 = 0x20;
const RWF_ATOMIC: u32 = 0x40;
const RWF_DONTCACHE: u32 = 0x80;
const RWF_NOSIGNAL: u32 = 0x100;
const RWF_SUPPORTED: u32 = 0x1ff;
const S_IFMT: u32 = 0o170000;
const S_IFREG: u32 = 0o100000;
const S_IFSOCK: u32 = 0o140000;
const S_IFIFO: u32 = 0o010000;
const O_APPEND: u32 = 0o2000;

/// What a regular file's file system takes, as Linux master's: `RWF_NOWAIT`
/// (`FMODE_NOWAIT`), a buffered write with it, and `RWF_DONTCACHE`
/// (`FOP_DONTCACHE`).
#[derive(Clone, Copy)]
struct FileSystemFlags {
    nowait: bool,
    nowait_write: bool,
    dontcache: bool,
}

/// [`FileSystemFlags`] by the file's file system ([`FileHandle::file_system`]):
/// ext4 takes NOWAIT but refuses it for a buffered write
/// (`ext4_buffered_write_iter`) and takes DONTCACHE; xfs takes all three;
/// btrfs and f2fs NOWAIT, for writes too, and not DONTCACHE; tmpfs (and
/// shmem, a memfd's), overlayfs, the files the kernel makes and every other
/// file system none. A host file system Linux has no number for (macOS's,
/// Windows') is taken as ext4.
fn file_system_flags(file: &Arc<dyn FileHandle>) -> FileSystemFlags {
    const EXT4_SUPER_MAGIC: u64 = 0xef53;
    const XFS_SUPER_MAGIC: u64 = 0x5846_5342;
    const BTRFS_SUPER_MAGIC: u64 = 0x9123_683e;
    const F2FS_SUPER_MAGIC: u64 = 0xf2f5_2010;
    let (nowait, nowait_write, dontcache) = match file.file_system() {
        Some(0 | EXT4_SUPER_MAGIC) => (true, false, true),
        Some(XFS_SUPER_MAGIC) => (true, true, true),
        Some(BTRFS_SUPER_MAGIC | F2FS_SUPER_MAGIC) => (true, true, false),
        _ => (false, false, false),
    };
    FileSystemFlags {
        nowait,
        nowait_write,
        dontcache,
    }
}

/// Whether a buffered write of `file` refuses `RWF_NOWAIT` (`EOPNOTSUPP`), as
/// ext4's `ext4_buffered_write_iter` does: a regular file whose file system
/// does not write without waiting.
fn refuses_nowait_write(file: &Arc<dyn FileHandle>, flags: u32) -> Result<bool, Errno> {
    Ok(flags & RWF_NOWAIT != 0
        && file.stat()?.mode & S_IFMT == S_IFREG
        && !file_system_flags(file).nowait_write)
}

/// The `RWF_*` flags of a transfer with bytes to move, checked as Linux's
/// `kiocb_set_rw_flags` checks them ([`kiocb_rw_flags`]), after the vector
/// and the range, and then as the file system's buffered write checks
/// `RWF_NOWAIT` ([`refuses_nowait_write`]).
fn rw_flags(file: &Arc<dyn FileHandle>, flags: u32, write: bool) -> Result<u32, Errno> {
    let flags = kiocb_rw_flags(file, flags)?;
    if write && refuses_nowait_write(file, flags)? {
        return Err(Errno::EOPNOTSUPP);
    }
    Ok(flags)
}

/// Linux's `kiocb_set_rw_flags`: unknown flags are `EOPNOTSUPP`, and
/// `RWF_APPEND` with `RWF_NOAPPEND` `EINVAL`. `RWF_NOWAIT` needs a file
/// opened with `FMODE_NOWAIT`: a regular file of a file system that has it
/// ([`file_system_flags`]), a pipe, a socket, an eventfd, a signalfd, a
/// timerfd, or `/dev/null`, `/dev/zero`, `/dev/random` and `/dev/urandom`
/// (`mm/char-mem.c`). No file can write atomically
/// (`FMODE_CAN_ATOMIC_WRITE`). `RWF_DONTCACHE` needs a regular file of a
/// file system with `FOP_DONTCACHE`. `RWF_NOSIGNAL` is taken by any file (a
/// write to a pipe or socket with no reader then raises no `SIGPIPE`).
/// `RWF_NOAPPEND` turns an `O_APPEND` file's append off for the transfer,
/// read or write, but not an append-only file's (`EPERM`).
pub(crate) fn kiocb_rw_flags(file: &Arc<dyn FileHandle>, flags: u32) -> Result<u32, Errno> {
    if flags == 0 {
        return Ok(0);
    }
    if flags & !RWF_SUPPORTED != 0 {
        return Err(Errno::EOPNOTSUPP);
    }
    if flags & RWF_APPEND != 0 && flags & RWF_NOAPPEND != 0 {
        return Err(Errno::EINVAL);
    }
    let kind = file.stat()?.mode & S_IFMT;
    if flags & RWF_NOWAIT != 0 {
        use crate::devices::{Device, Kind};
        let any = file.as_any();
        let nowait = if kind == S_IFREG {
            file_system_flags(file).nowait
        } else {
            kind == S_IFIFO
                || kind == S_IFSOCK
                || any.is_some_and(|any| {
                    any.is::<crate::events::EventCounter>()
                        || any.is::<crate::signalfd::SignalFile>()
                        || any.is::<crate::timerfd::TimerFile>()
                        || any.downcast_ref::<Device>().is_some_and(|device| {
                            matches!(
                                device.kind(),
                                Kind::Null | Kind::Zero | Kind::Random | Kind::Urandom
                            )
                        })
                })
        };
        if !nowait {
            return Err(Errno::EOPNOTSUPP);
        }
    }
    if flags & RWF_ATOMIC != 0 {
        return Err(Errno::EOPNOTSUPP);
    }
    if flags & RWF_DONTCACHE != 0 && (kind != S_IFREG || !file_system_flags(file).dontcache) {
        return Err(Errno::EOPNOTSUPP);
    }
    if unappended(file, flags) && attributes::append_only(&file.stat()?) {
        return Err(Errno::EPERM);
    }
    Ok(flags)
}

/// Whether an aio transfer of `file` is at its offset: a file with a
/// position that `pread` and `pwrite` take (Linux's `FMODE_PREAD`), not a
/// pipe, socket or terminal, a signalfd or an inotify instance, which read
/// and write as a stream whatever the offset.
fn aio_positioned(file: &Arc<dyn FileHandle>) -> bool {
    file.seek(0, 1).is_ok()
        && !file.as_any().is_some_and(|any| {
            any.is::<crate::signalfd::SignalFile>() || any.is::<crate::inotify::Instance>()
        })
}

/// An aio read or write of `segments` at `offset` with the `RWF_*` `flags`,
/// once `io_submit` has checked it (`aio_read`, `aio_write`): what the
/// file's `read_iter` or `write_iter` gives, a count or a negative errno,
/// for the completion event. As Linux's, it tells no inotify watch.
pub(crate) fn aio_transfer(
    c: &mut Context<'_>,
    file: &Arc<dyn FileHandle>,
    write: bool,
    segments: &[(u64, usize)],
    offset: u64,
    flags: u32,
) -> i64 {
    let result = if write {
        aio_write(c, file, segments, offset, flags)
    } else {
        aio_read(c, file, segments, offset, flags)
    };
    result.map_or_else(|e| -i64::from(e.0), |count| count as i64)
}

/// Checks that the first `len` bytes of `segments` can be written.
fn writable_prefix(
    c: &Context<'_>,
    segments: &[(u64, usize)],
    mut len: usize,
) -> Result<(), Errno> {
    for &(base, length) in segments {
        let length = length.min(len);
        c.mem
            .check_write(GuestAddr(base), length)
            .map_err(|_| Errno::EFAULT)?;
        len -= length;
    }
    Ok(())
}

fn aio_read(
    c: &mut Context<'_>,
    file: &Arc<dyn FileHandle>,
    segments: &[(u64, usize)],
    offset: u64,
    flags: u32,
) -> Result<u64, Errno> {
    let total = segments.iter().map(|&(_, length)| length).sum::<usize>();
    if total == 0 {
        return Ok(0);
    }
    let (b, count) = if aio_positioned(file) {
        let len = request(file, total as u64, offset, true)?;
        writable_prefix(c, segments, len)?;
        let mut b = buffer(len)?;
        let count = read_at(file, offset, &mut b)?;
        (b, count)
    } else {
        writable_prefix(c, segments, total)?;
        let mut b = buffer(total)?;
        let count = read_waiting(c, file, &mut b, flags & RWF_NOWAIT != 0)?;
        (b, count)
    };
    scatter(c, segments, &b[..count])?;
    Ok(count as u64)
}

fn aio_write(
    c: &mut Context<'_>,
    file: &Arc<dyn FileHandle>,
    segments: &[(u64, usize)],
    offset: u64,
    flags: u32,
) -> Result<u64, Errno> {
    let total = segments.iter().map(|&(_, length)| length).sum::<usize>();
    let mut bytes = Vec::new();
    bytes.try_reserve(total).map_err(|_| Errno::ENOMEM)?;
    for &(base, length) in segments {
        let start = bytes.len();
        bytes.resize(start + length, 0);
        c.mem
            .read(GuestAddr(base), &mut bytes[start..])
            .map_err(|_| Errno::EFAULT)?;
    }
    if bytes.is_empty() {
        return Ok(0);
    }
    if !aio_positioned(file) {
        let written = write_io_with(
            c,
            file,
            &bytes,
            flags & RWF_NOSIGNAL != 0,
            flags & RWF_NOWAIT != 0,
        )?;
        return sync_written(file, flags, written);
    }
    // A buffered write the file system cannot do without waiting
    // (ext4_buffered_write_iter's EOPNOTSUPP) is the event's result.
    if refuses_nowait_write(file, flags)? {
        return Err(Errno::EOPNOTSUPP);
    }
    let start = appending(file, flags)?.unwrap_or(offset);
    let written = if unappended(file, flags) {
        let len = size_limited_from(c, file, start, bytes.len())?;
        write_at_unappended(file, start, &bytes[..len])?
    } else {
        let len = size_limited(c, file, Some(start), bytes.len())?;
        write_at(file, start, &bytes[..len])?
    };
    if written > 0 {
        crate::permissions::remove_set_ids(&c.process.credentials, &**file);
    }
    sync_written(file, flags, written as u64)
}

/// After a write of a regular file with `RWF_DSYNC` or `RWF_SYNC`, its
/// data reaches the file as `fdatasync` brings it (`generic_write_sync`).
fn sync_written(file: &Arc<dyn FileHandle>, flags: u32, written: u64) -> Result<u64, Errno> {
    if written > 0 && flags & (RWF_DSYNC | RWF_SYNC) != 0 && file.stat()?.mode & S_IFMT == S_IFREG {
        file.sync()?;
    }
    Ok(written)
}

/// Where an `RWF_APPEND` write of a regular file starts: at its end.
fn appending(file: &Arc<dyn FileHandle>, flags: u32) -> Result<Option<u64>, Errno> {
    if flags & RWF_APPEND == 0 {
        return Ok(None);
    }
    let metadata = file.stat()?;
    Ok((metadata.mode & S_IFMT == S_IFREG).then_some(metadata.size))
}

/// Whether `file` has neither `read`/`read_iter` nor `write`/`write_iter`,
/// so that Linux opens it without `FMODE_CAN_READ` and `FMODE_CAN_WRITE`
/// and refuses `read`, `write` and their vectored forms (`EINVAL`) once
/// the access mode allows them: a secret memfd.
fn cannot_read_or_write(file: &Arc<dyn FileHandle>) -> bool {
    file.as_any()
        .and_then(|any| any.downcast_ref::<crate::memfd::Memfd>())
        .is_some_and(crate::memfd::Memfd::is_secret)
}
/// `readv(fd, iov, count)`, and `preadv2` at the file position, as Linux's
/// `vfs_readv`: the access mode, a file that cannot be read
/// ([`cannot_read_or_write`]), the vector, nothing to do for no bytes, the
/// range, then the flags.
fn readv(c: &mut Context<'_>, a: [u64; 6], flags: u32) -> Result<u64, Errno> {
    let file = c.files.descriptor(a[0])?.file;
    if file.flags() & 3 == 1 {
        return Err(Errno::EBADF);
    }
    if cannot_read_or_write(&file) {
        return Err(Errno::EINVAL);
    }
    if let Some(instance) = crate::inotify::of(&file) {
        return readv_instance(c, instance, a, flags);
    }
    let segments = iovecs(c, a[1], a[2], true)?;
    let total = segments.iter().map(|(_, length)| length).sum::<usize>();
    let position = file.seek(0, 1).ok();
    let len = match position {
        Some(position) => request(&file, total as u64, position, true)?,
        None => total,
    };
    if total == 0 && flags != 0 {
        return Ok(0);
    }
    let flags = rw_flags(&file, flags, false)?;
    let mut b = buffer(len)?;
    let count = read_waiting(c, &file, &mut b, flags & RWF_NOWAIT != 0)?;
    scatter(c, &segments, &b[..count])?;
    Ok(count as u64)
}

/// [`readv`] of an inotify instance, which has no `read_iter`: Linux's
/// `do_loop_readv_writev` reads each buffer in turn as
/// [`read_guest`](crate::inotify::read_guest) does, until one is not filled or fails;
/// nothing to do for no bytes, and any flag but `RWF_HIPRI` `EOPNOTSUPP`.
fn readv_instance(
    c: &mut Context<'_>,
    instance: &crate::inotify::Instance,
    a: [u64; 6],
    flags: u32,
) -> Result<u64, Errno> {
    let segments = iovecs_checked(c.mem, a[1], a[2], |_, _| Ok(()))?;
    if segments.iter().all(|&(_, length)| length == 0) {
        return Ok(0);
    }
    if flags & !RWF_HIPRI != 0 {
        return Err(Errno::EOPNOTSUPP);
    }
    let mut done = 0;
    for (base, length) in segments {
        match crate::inotify::read_guest(c, instance, base, length) {
            Ok(count) => {
                done += count as u64;
                if count != length {
                    break;
                }
            }
            Err(e) if done == 0 => return Err(e),
            Err(_) => break,
        }
    }
    Ok(done)
}

/// `writev(fd, iov, count)`, and `pwritev2` at the file position, as
/// Linux's `vfs_writev`: the descriptor and its access mode (EBADF), a file
/// that cannot be written ([`cannot_read_or_write`], EINVAL), the vector
/// (see [`iovecs`]), nothing to do for no bytes, then the flags.
fn writev(c: &mut Context<'_>, a: [u64; 6], flags: u32) -> Result<u64, Errno> {
    let file = c.files.descriptor(a[0])?.file;
    if file.flags() & 3 == 0 {
        return Err(Errno::EBADF);
    }
    if cannot_read_or_write(&file) {
        return Err(Errno::EINVAL);
    }
    let segments = iovecs(c, a[1], a[2], false)?;
    let total = segments.iter().map(|(_, length)| length).sum::<usize>();
    let mut bytes = Vec::new();
    bytes.try_reserve(total).map_err(|_| Errno::ENOMEM)?;
    for &(base, length) in &segments {
        let start = bytes.len();
        bytes.resize(start + length, 0);
        c.mem
            .read(GuestAddr(base), &mut bytes[start..])
            .map_err(|_| Errno::EFAULT)?;
    }
    if bytes.is_empty() && flags != 0 {
        return Ok(0);
    }
    let flags = rw_flags(&file, flags, true)?;
    // An RWF_APPEND write starts at the end and leaves the position after
    // what it wrote, as the kiocb's position goes back to the file's. As in
    // Linux's `do_writev`, a write that fails (`EFBIG`, `EINTR`, or a sync
    // after it) leaves the position as it was.
    let before = if flags != 0 {
        file.seek(0, 1).ok()
    } else {
        None
    };
    let result = (|| {
        // RWF_NOAPPEND writes an O_APPEND regular file at its position, which
        // then moves past what was written.
        if unappended(&file, flags) && file.stat()?.mode & S_IFMT == S_IFREG {
            let position = file.seek(0, 1)?;
            let len = size_limited_from(c, &file, position, bytes.len())?;
            let written = write_at_unappended(&file, position, &bytes[..len])?;
            file.seek((position + written as u64) as i64, 0)?;
            if written > 0 {
                crate::permissions::remove_set_ids(&c.process.credentials, &*file);
            }
            return sync_written(&file, flags, written as u64);
        }
        if let Some(end) = appending(&file, flags)? {
            file.seek(end as i64, 0)?;
        }
        let len = size_limited(c, &file, None, bytes.len())?;
        let written = write_io_with(
            c,
            &file,
            &bytes[..len],
            flags & RWF_NOSIGNAL != 0,
            flags & RWF_NOWAIT != 0,
        )?;
        sync_written(&file, flags, written)
    })();
    // A count of 0 moves it, as `do_writev` takes any `ret >= 0`; the
    // write's error stands even when putting the position back fails.
    if result.is_err()
        && let Some(before) = before
    {
        let _ = file.seek(before as i64, 0);
    }
    result
}

/// `preadv` and `pwritev`, and `preadv2` and `pwritev2` at an offset, as
/// Linux's `do_preadv` and `do_pwritev`.
fn positioned_vector(
    c: &mut Context<'_>,
    a: [u64; 6],
    write: bool,
    flags: u32,
) -> Result<u64, Errno> {
    let file = positioned(c, a[0], a[3], write)?;
    let segments = iovecs(c, a[1], a[2], !write)?;
    let total = segments.iter().map(|(_, length)| length).sum::<usize>();
    let len = request(&file, total as u64, a[3], !write)?;
    if total == 0 && flags != 0 {
        return Ok(0);
    }
    let flags = rw_flags(&file, flags, write)?;
    if !write {
        let mut b = buffer(len)?;
        let count = read_at(&file, a[3], &mut b)?;
        scatter(c, &segments, &b[..count])?;
        return Ok(count as u64);
    }
    let offset = appending(&file, flags)?.unwrap_or(a[3]);
    let len = if unappended(&file, flags) {
        size_limited_from(c, &file, offset, len)?
    } else {
        size_limited(c, &file, Some(offset), len)?
    };
    let mut b = Vec::new();
    b.try_reserve(len).map_err(|_| Errno::ENOMEM)?;
    for &(base, length) in &segments {
        let start = b.len();
        b.resize(start + length, 0);
        c.mem
            .read(GuestAddr(base), &mut b[start..])
            .map_err(|_| Errno::EFAULT)?;
    }
    b.truncate(len);
    let written = if unappended(&file, flags) {
        write_at_unappended(&file, offset, &b)?
    } else {
        write_at(&file, offset, &b)?
    };
    if written > 0 {
        crate::permissions::remove_set_ids(&c.process.credentials, &*file);
    }
    sync_written(&file, flags, written as u64)
}
/// A read that waits while a blocking file has nothing to give yet.
fn read_blocking(
    c: &mut Context<'_>,
    file: &Arc<dyn FileHandle>,
    b: &mut [u8],
) -> Result<usize, Errno> {
    read_waiting(c, file, b, false)
}
/// [`read_blocking`] that, with `nowait` (`RWF_NOWAIT`), does not wait, as
/// if the file were non-blocking.
fn read_waiting(
    c: &mut Context<'_>,
    file: &Arc<dyn FileHandle>,
    b: &mut [u8],
    nowait: bool,
) -> Result<usize, Errno> {
    // A pseudo-terminal reads as its line discipline says.
    if let Some(result) = crate::pty::read(c, file, b) {
        return result;
    }
    // A signal file reads the reading thread's signals.
    if let Some(result) = crate::signalfd::read(c, file, b, nowait) {
        return result;
    }
    // An inotify instance reads its events.
    if let Some(result) = crate::inotify::read(c, file, b, nowait) {
        return result;
    }
    // A socket's read waits as its SO_RCVLOWAT says. A pipe is a PipeEnd,
    // not a SocketPairEnd, so it reads below and still signals its writer.
    if file
        .as_any()
        .is_some_and(|a| a.is::<crate::sockets::SocketPairEnd>())
    {
        return crate::sockets::read(c, file, b, nowait);
    }
    let result = wait_for_read(c, file, nowait, || file.read(b));
    // A pipe read signals the writer as it ends, with data or not, unless a
    // signal interrupts it, as Linux's `pipe_read`.
    if !b.is_empty() && (result.is_ok() || result == Err(Errno::EAGAIN)) {
        crate::sockets::pipe_read_ended(file);
    }
    result
}
/// Repeats `read` while it finds nothing yet (EAGAIN) and `file` blocks:
/// neither `O_NONBLOCK` nor, with `dontwait`, `MSG_DONTWAIT`; a socket waits
/// no longer than its `SO_RCVTIMEO`.
pub(crate) fn wait_for_read<T>(
    c: &mut Context<'_>,
    file: &Arc<dyn FileHandle>,
    dontwait: bool,
    read: impl FnMut() -> Result<T, Errno>,
) -> Result<T, Errno> {
    let wait = crate::sockets::deadline(c, file, true)?;
    wait_for_read_until(c, file, dontwait, wait, read)
}
/// [`wait_for_read`] that waits as `wait` allows: EAGAIN once it is over,
/// and a signal that ends a wait with a time limit is EINTR, which no
/// SA_RESTART restarts, as Linux's `sock_intr_errno`.
pub(crate) fn wait_for_read_until<T>(
    c: &mut Context<'_>,
    file: &Arc<dyn FileHandle>,
    dontwait: bool,
    wait: crate::sockets::Wait,
    mut read: impl FnMut() -> Result<T, Errno>,
) -> Result<T, Errno> {
    loop {
        let ticket = c.files.readiness.token.value();
        match read() {
            Err(e)
                if e == Errno::EAGAIN
                    && !dontwait
                    && file.readiness().is_ok()
                    && file.flags() & crate::events::NONBLOCK == 0 =>
            {
                let deadline = wait.deadline(c)?.ok_or(Errno::EAGAIN)?;
                crate::sockets::wait_data(file, true);
                let waited = crate::events::wait(c, ticket, deadline);
                crate::sockets::wait_data(file, false);
                if let Err(e) = waited {
                    if !wait.forever() {
                        c.process.restart = None;
                    }
                    return Err(e);
                }
            }
            result => return result,
        }
    }
}
const AT_SYMLINK_NOFOLLOW: u64 = 0x100;
const AT_NO_AUTOMOUNT: u64 = 0x800;
const AT_EMPTY_PATH: u64 = 0x1000;
/// AT_STATX_FORCE_SYNC | AT_STATX_DONT_SYNC; both together are invalid.
const AT_STATX_SYNC_TYPE: u64 = 0x6000;
/// STATX_TYPE ... STATX_BLOCKS: the fields a `stat` also has.
const STATX_BASIC_STATS: u32 = 0x7ff;
/// `stx_mnt_id` holds the mount's ID, as /proc/self/mountinfo numbers it.
const STATX_MNT_ID: u32 = 0x1000;
/// `stx_mnt_id` holds the mount's 64-bit ID that is never reused (Linux 6.8),
/// numbered from 2^31 (Linux's `MNT_UNIQUE_ID_OFFSET`).
const STATX_MNT_ID_UNIQUE: u32 = 0x4000;
/// The attributes tmpfs's `shmem_getattr` reports: `STATX_ATTR_IMMUTABLE`,
/// `STATX_ATTR_APPEND` and `STATX_ATTR_NODUMP`.
const STATX_ATTR_FLAGS: u32 = 0x10 | 0x20 | 0x40;
/// `statx(dirfd, path, flags, mask, buffer)`, with the checks of Linux's
/// do_statx and vfs_statx. As since Linux 6.11, a null path with
/// AT_EMPTY_PATH names the descriptor like an empty one.
fn statx(c: &mut Context<'_>, a: [u64; 6]) -> Result<u64, Errno> {
    let (dir, flags, mask, out) = (a[0], a[2], a[3] as u32, a[4]);
    let raw = if a[1] == 0 && flags & AT_EMPTY_PATH != 0 {
        Vec::new()
    } else {
        path(c, a[1])?
    };
    if mask & 0x8000_0000 != 0 || flags & AT_STATX_SYNC_TYPE == AT_STATX_SYNC_TYPE {
        return Err(Errno::EINVAL);
    }
    if flags & !(AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT | AT_EMPTY_PATH | AT_STATX_SYNC_TYPE) != 0 {
        return Err(Errno::EINVAL);
    }
    // Whether the file keeps inode flags, as a tmpfs one does, whose
    // `shmem_getattr` gives them as attributes.
    let noop = &mut |_: &mut u32| {};
    let (s, device, block_size, kept) = if raw.is_empty() && flags & AT_EMPTY_PATH != 0 {
        if dir as i32 == -100 {
            let cwd = c
                .files
                .cwd
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone();
            (
                c.files.fs.metadata(&cwd, true)?,
                device(c, &cwd),
                path_block_size(&cwd),
                c.files.fs.with_attributes(&cwd, true, noop).is_ok(),
            )
        } else {
            let d = c.files.descriptor(dir)?;
            (
                d.file.stat()?,
                descriptor_device(c, &d),
                descriptor_block_size(c, &d),
                d.file.with_attributes(noop).is_ok(),
            )
        }
    } else {
        let follow = flags & AT_SYMLINK_NOFOLLOW == 0;
        let (p, _) = lookup(c, dir, raw, follow)?;
        match generated_stat(c, &p, follow)? {
            Some((stat, device, block_size)) => (stat, device, block_size, false),
            None => (
                c.files.fs.metadata(&p, follow)?,
                device(c, &p),
                path_block_size(&p),
                c.files.fs.with_attributes(&p, follow, noop).is_ok(),
            ),
        }
    };
    let attributes = u64::from(s.attributes & STATX_ATTR_FLAGS);
    let mut b = encode_statx(shown(c, s), device, block_size)?;
    // STATX_ATTR_IMMUTABLE, STATX_ATTR_APPEND and STATX_ATTR_NODUMP, which
    // have the inode flags' values.
    if kept {
        b[8..16].copy_from_slice(&attributes.to_le_bytes());
        b[56..64].copy_from_slice(&u64::from(STATX_ATTR_FLAGS).to_le_bytes());
    }
    // As Linux's vfs_statx, the mount's ID whether or not it was asked for:
    // the unique one if that was, the one mountinfo shows otherwise. A
    // mount's minor number is its position in mountinfo, whose IDs start at
    // 21; an internal file system's mount has a small one that mountinfo
    // does not show, as Linux's internal mounts are not shown.
    let id = mount_id(device);
    let (bit, id) = if mask & STATX_MNT_ID_UNIQUE != 0 {
        (STATX_MNT_ID_UNIQUE, 1 << 31 | id)
    } else {
        (STATX_MNT_ID, id)
    };
    b[0..4].copy_from_slice(&(STATX_BASIC_STATS | bit).to_le_bytes());
    b[144..152].copy_from_slice(&id.to_le_bytes());
    output(c, out, &b)?;
    Ok(0)
}
/// `MAX_HANDLE_SZ`: the most bytes a file handle's own part may have.
const MAX_HANDLE_SZ: u32 = 128;
/// `name_to_handle_at` gives the mount's unique 64-bit ID (Linux 6.12).
const AT_HANDLE_MNT_ID_UNIQUE: u64 = 0x001;
/// A handle that can be opened again with its path's directories (Linux
/// 6.13), which tmpfs cannot give (no `fh_to_parent`).
const AT_HANDLE_CONNECTABLE: u64 = 0x002;
/// A handle only to tell files apart, which any file system gives.
const AT_HANDLE_FID: u64 = 0x200;
const AT_SYMLINK_FOLLOW: u64 = 0x400;
/// `FILEID_INVALID`: the type of a handle that did not fit.
const FILEID_INVALID: u32 = 0xff;
/// The handle types: tmpfs's, pidfs's, and the identifier of a file system
/// without NFS export.
const FILEID_INO32_GEN: u32 = 1;
const FILEID_KERNFS: u32 = 0xfe;
const FILEID_INO64_GEN: u32 = 0x81;
/// The flags `name_to_handle_at` may put in a handle's type, above its low
/// 16 bits: a connectable handle's and a directory's.
const FILEID_IS_CONNECTABLE: u32 = 0x1_0000;
const FILEID_IS_DIR: u32 = 0x2_0000;
/// `ESTALE`: a handle that names no file the file system has.
pub(crate) const ESTALE: Errno = Errno(116);

/// The handle a file of the file system `kind` with inode `inode` has, as
/// Linux encodes it: its type and its bytes. A tmpfs file's is
/// `shmem_encode_fh`'s (`FILEID_INO32_GEN`: the generation, then the inode's
/// low and high halves) and a pidfd's `pidfs_encode_fh`'s (`FILEID_KERNFS`:
/// the inode); any other's is the identifier `exportfs_encode_ino64_fid`
/// gives a file system without NFS export (`FILEID_INO64_GEN`: the inode,
/// then the generation). The in-memory root's files have the generation 0
/// and memfds (on `device` [`crate::memfd::DEVICE`] or
/// [`crate::memfd::SECRET_DEVICE`]) 1, so that neither's
/// handle names the other's file, where tmpfs picks a random generation for
/// each inode.
pub(crate) fn file_handle(kind: u64, device: u64, inode: u64) -> (u32, Vec<u8>) {
    let generation =
        u32::from(device == crate::memfd::DEVICE || device == crate::memfd::SECRET_DEVICE);
    match kind {
        paludarium_vfs::TMPFS_MAGIC => (
            FILEID_INO32_GEN,
            [
                generation.to_le_bytes(),
                (inode as u32).to_le_bytes(),
                ((inode >> 32) as u32).to_le_bytes(),
            ]
            .concat(),
        ),
        PID_FS_MAGIC => (FILEID_KERNFS, inode.to_le_bytes().to_vec()),
        _ => (
            FILEID_INO64_GEN,
            [&inode.to_le_bytes()[..], &generation.to_le_bytes()].concat(),
        ),
    }
}
/// Whether the file system `kind` has Linux's NFS export operations, so
/// that it gives a handle that is not `AT_HANDLE_FID` and decodes one: tmpfs
/// and pidfs here.
fn exportable(kind: u64) -> bool {
    matches!(kind, paludarium_vfs::TMPFS_MAGIC | PID_FS_MAGIC)
}
/// `name_to_handle_at(dirfd, path, handle, mount_id, flags)`, as Linux's
/// (6.13 and later): the flags (`EINVAL`), the path, whether the file
/// system can give the handle asked for (`EOPNOTSUPP`: only tmpfs and
/// pidfs, the file systems here with NFS export, give one that is not
/// `AT_HANDLE_FID`, and none a connectable one), the size the caller gives
/// (`EINVAL` over `MAX_HANDLE_SZ`; `EOVERFLOW` under the handle's, with that
/// size and `FILEID_INVALID` written back), then the mount's ID, as `statx`
/// gives it, and the handle.
fn name_to_handle_at(c: &mut Context<'_>, a: [u64; 6]) -> Result<u64, Errno> {
    let (dir, handle, mount, flags) = (a[0], a[2], a[3], a[4]);
    if flags
        & !(AT_SYMLINK_FOLLOW
            | AT_EMPTY_PATH
            | AT_HANDLE_FID
            | AT_HANDLE_MNT_ID_UNIQUE
            | AT_HANDLE_CONNECTABLE)
        != 0
        || (flags & AT_HANDLE_CONNECTABLE != 0 && flags & (AT_HANDLE_FID | AT_EMPTY_PATH) != 0)
    {
        return Err(Errno::EINVAL);
    }
    let raw = path(c, a[1])?;
    let (stat, device, kind) = if raw.is_empty() && flags & AT_EMPTY_PATH != 0 {
        if dir as i32 == -100 {
            let cwd = c
                .files
                .cwd
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone();
            named(c, &cwd, true)?
        } else {
            let d = c.files.descriptor(dir)?;
            (
                d.file.stat()?,
                descriptor_device(c, &d),
                descriptor_kind(c, &d)?,
            )
        }
    } else {
        let follow = flags & AT_SYMLINK_FOLLOW != 0;
        let (p, _) = lookup(c, dir, raw, follow)?;
        named(c, &p, follow)?
    };
    if flags & AT_HANDLE_CONNECTABLE != 0 || (flags & AT_HANDLE_FID == 0 && !exportable(kind)) {
        return Err(Errno::EOPNOTSUPP);
    }
    let mut given = [0u8; 4];
    c.mem
        .read(GuestAddr(handle), &mut given)
        .map_err(|_| Errno::EFAULT)?;
    // The whole header is read, as `copy_from_user` of the struct does.
    c.mem
        .read(GuestAddr(handle.wrapping_add(4)), &mut [0u8; 4])
        .map_err(|_| Errno::EFAULT)?;
    let given = u32::from_le_bytes(given);
    if given > MAX_HANDLE_SZ {
        return Err(Errno::EINVAL);
    }
    let (kind, bytes) = file_handle(kind, device, stat.inode);
    // The file system takes the size in 4-byte words, as it encodes them.
    let fits = given >> 2 >= bytes.len() as u32 >> 2;
    let id = mount_id(device);
    if flags & AT_HANDLE_MNT_ID_UNIQUE != 0 {
        output(c, mount, &(1u64 << 31 | id).to_le_bytes())?;
    } else {
        output(c, mount, &(id as u32).to_le_bytes())?;
    }
    let mut out = Vec::with_capacity(8 + bytes.len());
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(&(if fits { kind } else { FILEID_INVALID }).to_le_bytes());
    if fits {
        out.extend_from_slice(&bytes);
    }
    output(c, handle, &out)?;
    if fits { Ok(0) } else { Err(Errno::EOVERFLOW) }
}
/// `FD_PIDFS_ROOT` and `FD_NSFS_ROOT`: the roots of pidfs and nsfs, which
/// `open_by_handle_at` takes for the mount to decode a handle on.
const FD_PIDFS_ROOT: i32 = -10002;
const FD_NSFS_ROOT: i32 = -10003;
/// What `open_by_handle_at` decodes a handle on: the mount of its
/// `mountdirfd`.
enum HandleMount {
    /// pidfs: its root, or the pidfd whose inode is `Some(inode)`.
    Pidfs(Option<u64>),
    /// nsfs, whose handles name namespaces.
    Nsfs,
    /// Another file system, `kind`, by the path of its directory or file.
    Path(u64, Vec<u8>),
}
/// `open_by_handle_at(mountdirfd, handle, flags)`, as Linux's
/// `do_handle_open` (master): the handle's header (`EFAULT`), its size
/// (`EINVAL` for 0 or over `MAX_HANDLE_SZ`) and the flags of its type
/// (`EINVAL`), the mount (`EBADF`), whether the caller may decode handles
/// there (pidfs's `permission` takes only the flags a pidfd opens with, and
/// `EINVAL` for others; nsfs's takes any; elsewhere it is `EPERM` without
/// `CAP_DAC_READ_SEARCH`), the handle's bytes (`EFAULT`), then the file it
/// names (`ESTALE` for none), which is opened.
fn open_by_handle_at(c: &mut Context<'_>, a: [u64; 6]) -> Result<u64, Errno> {
    const O_CREAT: u32 = 0o100;
    const O_EXCL: u32 = 0o200;
    const O_NONBLOCK: u32 = 0o4000;
    const O_LARGEFILE: u32 = 0o100000;
    const O_NOFOLLOW: u32 = 0o400000;
    const O_CLOEXEC: u32 = 0o2000000;
    const CAP_DAC_READ_SEARCH: u64 = 1 << 2;
    let (handle, flags) = (a[1], a[2] as u32);
    let mut header = [0u8; 8];
    c.mem
        .read(GuestAddr(handle), &mut header)
        .map_err(|_| Errno::EFAULT)?;
    let size = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
    let kind = u32::from_le_bytes([header[4], header[5], header[6], header[7]]);
    if size == 0 || size > MAX_HANDLE_SZ {
        return Err(Errno::EINVAL);
    }
    if (kind as i32) < 0 || kind & 0xffff_0000 & !(FILEID_IS_CONNECTABLE | FILEID_IS_DIR) != 0 {
        return Err(Errno::EINVAL);
    }
    let mount = match a[0] as i32 {
        FD_PIDFS_ROOT => HandleMount::Pidfs(None),
        FD_NSFS_ROOT => HandleMount::Nsfs,
        -100 => {
            let cwd = c
                .files
                .cwd
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone();
            HandleMount::Path(path_kind(c, &cwd, true), cwd)
        }
        fd if fd >= 0 => {
            let d = c.files.descriptor(u64::from(fd as u32))?;
            if let Some(pidfd) = d
                .file
                .as_any()
                .and_then(|v| v.downcast_ref::<crate::processes::PidFd>())
            {
                HandleMount::Pidfs(Some(pidfd.inode()))
            } else if is_namespace(&d) {
                HandleMount::Nsfs
            } else {
                HandleMount::Path(descriptor_kind(c, &d).unwrap_or(0), d.path.clone())
            }
        }
        _ => return Err(Errno::EBADF),
    };
    // pidfs's `pidfs_export_permission`, nsfs's (its decoding checks), and
    // `may_decode_fh` elsewhere. Linux 6.10 also lets a caller with
    // CAP_SYS_ADMIN over the mount decode a directory's handle with
    // `O_DIRECTORY`; that relaxed check is not made here.
    match mount {
        HandleMount::Pidfs(_) => {
            if flags & !(3 | O_NONBLOCK | O_CLOEXEC | O_EXCL | O_LARGEFILE) != 0 {
                return Err(Errno::EINVAL);
            }
        }
        HandleMount::Nsfs => {}
        HandleMount::Path(..) => {
            if !c.process.credentials.capable(CAP_DAC_READ_SEARCH) {
                return Err(Errno::EPERM);
            }
        }
    }
    let mut bytes = vec![0u8; size as usize];
    c.mem
        .read(GuestAddr(handle.wrapping_add(8)), &mut bytes)
        .map_err(|_| Errno::EFAULT)?;
    let (connectable, directory) = (kind & FILEID_IS_CONNECTABLE != 0, kind & FILEID_IS_DIR != 0);
    let kind = kind & 0xffff;
    // The file system decodes the size in 4-byte words.
    let words = size as usize >> 2;
    let cloexec = flags & O_CLOEXEC != 0;
    match mount {
        HandleMount::Pidfs(anchor) => {
            // `pidfs_fh_to_dentry`; a pidfd is no directory, and a
            // connectable handle's file is reached only from its own pidfd,
            // as pidfs's files have no parents. `do_handle_to_path` gives
            // `ESTALE` for any file the decoding refuses.
            if kind != FILEID_KERNFS || words < 2 {
                return Err(ESTALE);
            }
            let inode = u64::from_le_bytes(bytes[..8].try_into().map_err(|_| ESTALE)?);
            let space = c.group.namespaces(c.tid).pid.clone();
            let pidfd = crate::processes::PidFd::by_inode(c.processes, &space, inode, flags)?;
            if directory || connectable && anchor != Some(inode) {
                return Err(ESTALE);
            }
            c.files
                .install(pidfd, cloexec, c.group.nofile())
                .map(u64::from)
        }
        // No namespace has a handle here (`name_to_handle_at` of one is
        // `EOPNOTSUPP`), so none decodes.
        HandleMount::Nsfs => Err(ESTALE),
        HandleMount::Path(file_system, anchor) => {
            // Only the in-memory root is a file system here that decodes
            // handles, tmpfs's `shmem_fh_to_dentry`: the generation (0
            // there, [`file_handle`]) and the inode, of a file a name links.
            if file_system != paludarium_vfs::TMPFS_MAGIC || words < 3 || bytes[..4] != [0; 4] {
                return Err(ESTALE);
            }
            let low = u32::from_le_bytes(bytes[4..8].try_into().map_err(|_| ESTALE)?);
            let high = u32::from_le_bytes(bytes[8..12].try_into().map_err(|_| ESTALE)?);
            let inode = u64::from(high) << 32 | u64::from(low);
            let p = c.files.fs.memory_path(&anchor, inode).ok_or(ESTALE)?;
            let stat = c.files.fs.metadata(&p, false)?;
            let is_directory = stat.mode & 0o170000 == 0o040000;
            // A directory's handle names a directory, and a connectable
            // handle's file must be reached from the mount's directory
            // (`vfs_dentry_acceptable`'s check of the subtree); the
            // decoding's `ENOTDIR` and `EACCES` both become `ESTALE`.
            let under = |root: &[u8]| {
                root == b"/" || p == root || p.starts_with(root) && p.get(root.len()) == Some(&b'/')
            };
            if directory && !is_directory || connectable && !under(&anchor) {
                return Err(ESTALE);
            }
            // `file_open_root` of the file itself: as the last component of
            // an open, `O_CREAT` finds it there (`EEXIST` with `O_EXCL`,
            // `EISDIR` for a directory), and a symbolic link is not followed.
            if flags & O_CREAT != 0 {
                if flags & O_EXCL != 0 {
                    return Err(Errno::EEXIST);
                }
                if is_directory {
                    return Err(Errno::EISDIR);
                }
            }
            let link = stat.mode & 0o170000 == 0o120000;
            let flags = flags & !(O_CREAT | O_EXCL) | if link { O_NOFOLLOW } else { 0 };
            open_at(c, (-100i32) as u64, p, u64::from(flags), 0, 0)
        }
    }
}
/// The status, device and file system (`f_type`) of what path `p` names
/// (the last link itself without `follow`), as the calls that name a file
/// without opening it reach it: through a descriptor's link in `/proc`, a
/// file paludarium makes, or the mounted directories.
pub(crate) fn named(
    c: &Context<'_>,
    p: &[u8],
    follow: bool,
) -> Result<(FileStat, u64, u64), Errno> {
    Ok(match followed(c, p, follow)? {
        Some(Followed::Path { path, follow }) => (
            c.files.fs.metadata(&path, follow)?,
            watched_device(c, &path, follow),
            path_kind(c, &path, follow),
        ),
        Some(Followed::File(d)) => (
            d.file.stat()?,
            descriptor_device(c, &d),
            descriptor_kind(c, &d)?,
        ),
        None => match generated_stat(c, p, follow)? {
            Some((stat, device, _)) => (stat, device, path_kind(c, p, follow)),
            None => (
                c.files.fs.metadata(p, follow)?,
                watched_device(c, p, follow),
                path_kind(c, p, follow),
            ),
        },
    })
}
/// The file system (`f_type`) of the file `d` holds, as `fstatfs` gives it;
/// a memfd's is shmem's, a tmpfs.
fn descriptor_kind(c: &Context<'_>, d: &Descriptor) -> Result<u64, Errno> {
    if let Some(memfd) = d
        .file
        .as_any()
        .and_then(|v| v.downcast_ref::<crate::memfd::Memfd>())
    {
        return Ok(if memfd.is_secret() {
            crate::memfd::SECRETMEM_MAGIC
        } else {
            paludarium_vfs::TMPFS_MAGIC
        });
    }
    Ok(descriptor_statfs(c, d)?.kind)
}
/// The file system (`f_type`) of the file path `p` names, as `statfs` of it
/// gives it, or of its directory for a symbolic link not followed.
fn path_kind(c: &Context<'_>, p: &[u8], follow: bool) -> u64 {
    let link = !follow
        && c.files
            .fs
            .metadata(p, false)
            .is_ok_and(|s| s.mode & 0o170000 == 0o120000);
    let place = match p.iter().rposition(|&b| b == b'/') {
        Some(at) if link => &p[..at.max(1)],
        _ => p,
    };
    path_statfs(c, place).map_or(0, |s| s.kind)
}
/// What `statfs` reports for path `p`, which it follows: /proc's, a
/// descriptor's for a link in `fd`, the `mqueue` file system's, or that of
/// the mounted directory holding it.
fn path_statfs(c: &Context<'_>, p: &[u8]) -> Result<paludarium_host::FsStats, Errno> {
    Ok(if in_proc(p) {
        // A link in `fd` leads to its descriptor's file; one for a
        // descriptor not open is not there (`ENOENT`).
        if let Some(crate::proc::OwnEntry::Descriptor(n)) = crate::proc::own_entry(p, c.process.pid)
        {
            let d = c
                .files
                .descriptor(u64::from(n))
                .map_err(|_| Errno::ENOENT)?;
            descriptor_statfs(c, &d)?
        } else {
            if generated_stat(c, p, true)?.is_none() {
                c.files.fs.metadata(p, true)?;
            }
            pseudo_fs(PROC_SUPER_MAGIC)
        }
    } else if let Some(name) = paludarium_vfs::normalize_path(p)
        .ok()
        .filter(|p| p.as_slice() == b"/dev/mqueue" || crate::mqueue::mounted_name(p).is_some())
    {
        // `/dev/mqueue` and its queues are the `mqueue` filesystem.
        if let Some(name) = crate::mqueue::mounted_name(&name) {
            crate::mqueue::mounted_file(c, name)?;
        }
        pseudo_fs(MQUEUE_MAGIC)
    } else {
        c.files.fs.statfs(p)?
    })
}
/// The ID of the mount whose device is `device`, as `/proc/self/mountinfo`
/// numbers it: its minor number is its position there, from 21. An internal
/// file system's mount ([`Internal`]) has one of the small IDs below those,
/// as Linux's `kern_mount`s take theirs first, at boot.
fn mount_id(device: u64) -> u64 {
    match Internal::ALL.iter().position(|fs| fs.device() == device) {
        Some(i) => i as u64 + 1,
        None => 20 + (device & 0xff | (device >> 12) & !0xff),
    }
}
/// `struct statx` with what [`encode_stat`] gives a `struct stat`: the basic
/// fields, no birth time, and the mount's number as the device minor.
fn encode_statx(s: FileStat, device: u64, block_size: u32) -> Result<[u8; 256], Errno> {
    let (seconds, nanos) = linux_mtime(s.mtime_ns)?;
    let mut b = [0; 256];
    b[0..4].copy_from_slice(&STATX_BASIC_STATS.to_le_bytes());
    b[4..8].copy_from_slice(&block_size.to_le_bytes());
    b[16..20].copy_from_slice(&u32::try_from(s.links).unwrap_or(u32::MAX).to_le_bytes());
    b[20..24].copy_from_slice(&s.uid.to_le_bytes());
    b[24..28].copy_from_slice(&s.gid.to_le_bytes());
    b[28..30].copy_from_slice(&(s.mode as u16).to_le_bytes());
    b[32..40].copy_from_slice(&s.inode.to_le_bytes());
    b[40..48].copy_from_slice(&s.size.to_le_bytes());
    b[48..56].copy_from_slice(&blocks(&s).to_le_bytes());
    b[112..120].copy_from_slice(&seconds.to_le_bytes());
    b[120..124].copy_from_slice(&(nanos as u32).to_le_bytes());
    // Linux's encoding of a device number into its major and minor.
    let split = |device: u64| {
        (
            ((device >> 8) & 0xfff) as u32,
            ((device & 0xff) | ((device >> 12) & !0xff)) as u32,
        )
    };
    let (rdev_major, rdev_minor) = split(s.rdev);
    b[128..132].copy_from_slice(&rdev_major.to_le_bytes());
    b[132..136].copy_from_slice(&rdev_minor.to_le_bytes());
    let (major, minor) = split(device);
    b[136..140].copy_from_slice(&major.to_le_bytes());
    b[140..144].copy_from_slice(&minor.to_le_bytes());
    Ok(b)
}
/// `stat` of a file at guest `path`: its `st_dev` names the mount holding
/// it, numbered as /proc/self/mountinfo numbers mounts (0:1 is the root).
fn stat(
    c: &Context<'_>,
    addr: u64,
    s: FileStat,
    device: u64,
    block_size: u32,
) -> Result<u64, Errno> {
    let mut bytes = encode_stat(shown(c, s), block_size)?;
    bytes[0..8].copy_from_slice(&device.to_le_bytes());
    output(c, addr, &bytes)?;
    Ok(0)
}
/// Waits up to 10 ms for a lock another holder has, as a blocking `flock` or
/// `F_SETLKW` does between its tries: `EINTR` when a signal, a group exit or
/// a cancellation comes first.
pub(crate) fn pause_for_lock(c: &mut Context<'_>) -> Result<(), Errno> {
    let timer_generation = c.group.timer_generation();
    let receipt = c.inbox.drain(c.process);
    c.group.drain_process(c.process);
    let now = c.host.clock(ClockId::Monotonic)?;
    c.group.expire_timer(c.process, now);
    if c.group.status().is_some()
        || crate::signals::next_pending(c.process, true).is_some()
        || receipt.interrupted
    {
        return Err(Errno(4));
    }
    if !c.inbox.owns_wake(c.cancellation)
        && c.cancellation.load(std::sync::atomic::Ordering::SeqCst)
    {
        return Err(Errno(4));
    }
    let outcome = c.host.wait_until(
        ClockId::Monotonic,
        now.saturating_add(10_000_000),
        c.cancellation,
    )?;
    let receipt = c.inbox.drain(c.process);
    let sent = c.group.drain_process(c.process);
    if c.group.status().is_some()
        || crate::signals::next_pending(c.process, true).is_some()
        || receipt.interrupted
        || (outcome == paludarium_host::WaitOutcome::Interrupted
            && !receipt.timer_changed
            && !receipt.signals
            && !sent
            && c.group.timer_generation() == timer_generation)
    {
        return Err(Errno(4));
    }
    Ok(())
}
/// The file systems Linux keeps on internal mounts that no path reaches.
/// Each has a device of its own, as `get_anon_bdev` gives each superblock
/// one: here from the top of the 20-bit minors down, which no mount takes.
#[derive(Clone, Copy)]
pub(crate) enum Internal {
    /// `shm_mnt`, the tmpfs of memfds.
    Shmem,
    Nsfs,
    Pipefs,
    Sockfs,
    /// The anonymous inodes' (eventfds, epolls, timerfds and the like).
    AnonInodes,
    Pidfs,
    Secretmem,
}
impl Internal {
    const ALL: [Self; 7] = [
        Self::Shmem,
        Self::Nsfs,
        Self::Pipefs,
        Self::Sockfs,
        Self::AnonInodes,
        Self::Pidfs,
        Self::Secretmem,
    ];
    /// Its device, in `stat`'s encoding (`new_encode_dev`).
    pub(crate) const fn device(self) -> u64 {
        let minor = 0xf_ffff - self as u64;
        minor & 0xff | (minor & !0xff) << 12
    }
}
/// The device of the file a descriptor holds: an internal file system's for
/// a memfd, a namespace file, a pipe, a socket, a pidfd or a file of no type
/// (an anonymous inode) that no path opened, else that of the mount holding
/// its path.
pub(crate) fn descriptor_device(c: &Context<'_>, d: &Descriptor) -> u64 {
    let any = d.file.as_any();
    if let Some(memfd) = any.and_then(|v| v.downcast_ref::<crate::memfd::Memfd>()) {
        return crate::memfd::device(memfd);
    }
    if is_namespace(d) {
        return crate::namespaces::DEVICE;
    }
    if !d.path.is_empty() {
        return device(c, &d.path);
    }
    if any.is_some_and(|v| v.is::<crate::processes::PidFd>()) {
        return Internal::Pidfs.device();
    }
    match d.file.stat().map(|stat| stat.mode & 0o170000) {
        Ok(0o010000) => Internal::Pipefs.device(),
        Ok(0o140000) => Internal::Sockfs.device(),
        Ok(0) => Internal::AnonInodes.device(),
        _ => device(c, &d.path),
    }
}
/// The minor number of the mount that holds `path` (the longest matching
/// mount point), so that each mount is its own device.
fn device(c: &Context<'_>, path: &[u8]) -> u64 {
    crate::page_cache::mount_device(&c.files.fs.mounts(), path)
}
/// The block size of a guest's file: `st_blksize`, `stx_blksize`,
/// `FIGETBSZ`, and `f_bsize` of a pipe or a socket, which Linux all take from
/// the superblock. A mounted directory's `statfs` reports the host's own.
pub(crate) const BLOCK_SIZE: u32 = 4096;
/// The block size of procfs and devpts, whose superblocks Linux's
/// `proc_fill_super` and `devpts_fill_super` give an `s_blocksize` of 1024.
const SMALL_BLOCK_SIZE: u32 = 1024;
/// procfs's and devpts's `s_magic`, which their `statfs` gives as `f_type`.
const PROC_SUPER_MAGIC: u64 = 0x9fa0;
const DEVPTS_SUPER_MAGIC: u64 = 0x1cd1;
const MQUEUE_MAGIC: u64 = 0x1980_0202;
/// pidfs's `s_magic`, a pidfd's file system from Linux 6.9.
const PID_FS_MAGIC: u64 = 0x5049_4446;
/// The anonymous inodes' file system, which eventfds, epolls, timerfds,
/// signalfds, inotify instances and the like are on.
const ANON_INODE_FS_MAGIC: u64 = 0x0904_1934;
/// Whether `path` is in `/proc`, which is procfs on Linux.
fn in_proc(path: &[u8]) -> bool {
    path == b"/proc" || path.starts_with(b"/proc/")
}
/// The block size of the file at guest `path`, which is not one of
/// [`generated_stat`]'s: procfs's in `/proc`, else [`BLOCK_SIZE`].
fn path_block_size(path: &[u8]) -> u32 {
    if in_proc(path) {
        SMALL_BLOCK_SIZE
    } else {
        BLOCK_SIZE
    }
}
/// Whether `d` is one of the host's standard streams and a terminal, as
/// `TCGETS` finds it, which on Linux is a pseudo-terminal's devpts file.
fn is_terminal(c: &Context<'_>, d: &Descriptor) -> bool {
    if crate::pty::is_slave(&d.file) {
        return true;
    }
    let stream = match d.file.stdio_channel() {
        Some(0) => paludarium_host::StreamId::Stdin,
        Some(1) => paludarium_host::StreamId::Stdout,
        Some(2) => paludarium_host::StreamId::Stderr,
        _ => return false,
    };
    c.files.terminal_size.is_some() || matches!(c.host.terminal_info(stream), Ok(Some(_)))
}
/// Whether `d` holds a namespace file (nsfs), which a path in /proc opens.
fn is_namespace(d: &Descriptor) -> bool {
    d.file
        .as_any()
        .is_some_and(|v| v.is::<crate::namespaces::NamespaceFile>())
}
/// The block size of the file a descriptor holds: procfs's for one opened
/// in `/proc` but a namespace file, devpts's for a terminal, else
/// [`BLOCK_SIZE`].
pub(crate) fn descriptor_block_size(c: &Context<'_>, d: &Descriptor) -> u32 {
    if in_proc(&d.path) && !is_namespace(d) || is_terminal(c, d) {
        SMALL_BLOCK_SIZE
    } else {
        BLOCK_SIZE
    }
}
/// `st_blocks`: what the file system counts, or the size in 512-byte blocks.
pub(crate) fn blocks(s: &FileStat) -> u64 {
    s.blocks.unwrap_or(s.size.div_ceil(512))
}
/// A file's status with its owner and group as the caller's user
/// namespace shows them (`from_kuid_munged`).
fn shown(c: &Context<'_>, s: FileStat) -> FileStat {
    FileStat {
        uid: c.shown_uid(s.uid),
        gid: c.shown_gid(s.gid),
        ..s
    }
}
fn encode_stat(s: FileStat, block_size: u32) -> Result<[u8; 144], Errno> {
    let (seconds, nanos) = linux_mtime(s.mtime_ns)?;
    let mut b = [0; 144];
    b[8..16].copy_from_slice(&s.inode.to_le_bytes());
    b[16..24].copy_from_slice(&s.links.to_le_bytes());
    b[24..28].copy_from_slice(&s.mode.to_le_bytes());
    b[28..32].copy_from_slice(&s.uid.to_le_bytes());
    b[32..36].copy_from_slice(&s.gid.to_le_bytes());
    b[40..48].copy_from_slice(&s.rdev.to_le_bytes());
    b[48..56].copy_from_slice(&s.size.to_le_bytes());
    b[56..64].copy_from_slice(&u64::from(block_size).to_le_bytes());
    b[64..72].copy_from_slice(&blocks(&s).to_le_bytes());
    b[88..96].copy_from_slice(&seconds.to_le_bytes());
    b[96..104].copy_from_slice(&nanos.to_le_bytes());
    Ok(b)
}
fn linux_mtime(ns: i128) -> Result<(i64, u64), Errno> {
    let seconds = i64::try_from(ns.div_euclid(1_000_000_000)).map_err(|_| Errno(75))?;
    let nanos = u64::try_from(ns.rem_euclid(1_000_000_000)).map_err(|_| Errno(75))?;
    Ok((seconds, nanos))
}
#[cfg(test)]
mod mtime_tests {
    use super::*;
    #[test]
    fn umask_is_shared_exactly_with_clone_fs() {
        let files = Files::default();
        let shared = files.for_clone(false, true);
        let separate = files.for_clone(true, false);
        shared.umask.store(0o077, Ordering::SeqCst);
        assert_eq!(files.umask(), 0o077);
        assert_eq!(separate.umask(), 0o022);
        assert_eq!(files.for_exec().umask(), 0o077);
    }
    #[test]
    fn mtime_stat_codec_signed_boundaries() {
        for (ns, seconds, nanos) in [
            (-1_000_000_000, -1i64, 0u64),
            (-500_000_000, -1, 500_000_000),
            (-1, -1, 999_999_999),
            (0, 0, 0),
            (1, 0, 1),
            (1_500_000_000, 1, 500_000_000),
            (i128::from(u64::MAX), 18_446_744_073, 709_551_615),
        ] {
            let bytes = encode_stat(
                FileStat {
                    mtime_ns: ns,
                    ..FileStat::default()
                },
                BLOCK_SIZE,
            )
            .unwrap();
            assert_eq!(&bytes[88..96], &seconds.to_le_bytes());
            assert_eq!(&bytes[96..104], &nanos.to_le_bytes());
        }
    }
    #[test]
    fn mtime_stat_codec_checked_seconds_overflow() {
        for ns in [
            i128::MIN,
            i128::MAX,
            (i128::from(i64::MAX) + 1) * 1_000_000_000,
            i128::from(i64::MIN) * 1_000_000_000 - 1,
        ] {
            assert_eq!(
                encode_stat(
                    FileStat {
                        mtime_ns: ns,
                        ..FileStat::default()
                    },
                    BLOCK_SIZE
                ),
                Err(Errno(75))
            );
        }
        assert_eq!(
            linux_mtime(i128::from(i64::MIN) * 1_000_000_000),
            Ok((i64::MIN, 0))
        );
        assert_eq!(
            linux_mtime(i128::from(i64::MAX) * 1_000_000_000 + 999_999_999),
            Ok((i64::MAX, 999_999_999))
        );
    }
}
pub(crate) fn dispatch(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    let n = c.number;
    let result = run(c, n, a);
    if c.files.caches.notify.watching() {
        accessed(c, n, a, &result);
    }
    match result {
        Ok(v) => Outcome::Return(v),
        Err(e) => Outcome::Return(e.to_syscall_return()),
    }
}
/// The inotify events of a call that read or wrote files, as Linux's
/// `fsnotify_access` and `fsnotify_modify` follow them: a read or write that
/// moved bytes, `sendfile` and `copy_file_range` (the input's, then the
/// output's), `splice` (the output's first, as `do_splice` has it), `tee`
/// and `vmsplice` that moved bytes (a write end's `IN_MODIFY`, a read end's
/// `IN_ACCESS`), a `fallocate` that succeeded, and every `getdents` and
/// `getdents64` that reached `iterate_dir` (one with too small a buffer too).
/// A pipe has no watches, but a FIFO that a path opened does.
fn accessed(c: &Context<'_>, n: u64, a: [u64; 6], result: &Result<u64, Errno>) {
    use crate::inotify::{ACCESS, MODIFY};
    let moved = matches!(result, Ok(v) if *v > 0);
    let vmspliced;
    let events: &[(u64, u32)] = match n {
        275 if moved => &[(a[2], MODIFY), (a[0], ACCESS)],
        276 if moved => &[(a[0], ACCESS), (a[1], MODIFY)],
        // `vmsplice_to_pipe` for a descriptor open for writing.
        278 if moved => {
            let writes = c
                .files
                .descriptor(a[0])
                .is_ok_and(|d| d.file.flags() & 3 != 0);
            vmspliced = [(a[0], if writes { MODIFY } else { ACCESS })];
            &vmspliced
        }
        0 | 17 | 19 | 295 | 327 if moved => &[(a[0], ACCESS)],
        1 | 18 | 20 | 296 | 328 if moved => &[(a[0], MODIFY)],
        40 if moved => &[(a[1], ACCESS), (a[0], MODIFY)],
        326 if moved => &[(a[0], ACCESS), (a[2], MODIFY)],
        285 if result.is_ok() => &[(a[0], MODIFY)],
        78 | 217 if result.is_ok() || *result == Err(Errno::EINVAL) => &[(a[0], ACCESS)],
        _ => &[],
    };
    for &(fd, mask) in events {
        notify_descriptor(c, fd, mask);
    }
}
/// Tells the inotify watches of `mask` on the open file of descriptor `fd`
/// (`fsnotify_file`). A pipe, a socket or another file no path opened has
/// none, as Linux's pseudo files are `FMODE_NONOTIFY`.
fn notify_descriptor(c: &Context<'_>, fd: u64, mask: u32) {
    let Ok(d) = c.files.descriptor(fd) else {
        return;
    };
    if d.path.is_empty() || d.file.flags() & O_PATH != 0 || d.file.notify_event(mask) {
        return;
    }
    let Ok(stat) = d.file.stat() else {
        return;
    };
    c.files.caches.notify.file_event(
        Some((&*c.files.fs, &d.path, false)),
        descriptor_device(c, &d),
        &stat,
        mask,
    );
}
pub(crate) fn run(c: &mut Context<'_>, n: u64, a: [u64; 6]) -> Result<u64, Errno> {
    refuse_path_only(c, n, a)?;
    match n {
        40 => sendfile(c, a),
        275 => splice::splice(c, a),
        276 => splice::tee(c, a),
        278 => splice::vmsplice(c, a),
        303 => name_to_handle_at(c, a),
        304 => open_by_handle_at(c, a),
        332 => statx(c, a),
        326 => copy_file_range(c, a),
        451 => cachestat(c, a),
        436 => close_range(c, a),
        // One `IN_MODIFY` for the call ([`accessed`]), as Linux's
        // `vfs_fallocate` gives, whatever sizes it changes.
        285 => crate::inotify::unnoticed(|| fallocate(c, a)),
        319 => crate::memfd::memfd_create(c, a),
        447 => crate::memfd::memfd_secret(c, a),
        // pread64, pwrite64, preadv, pwritev: at an offset, leaving the file
        // position. On x86-64 the offset of preadv and pwritev is a[3] alone.
        17 => {
            let file = positioned(c, a[0], a[3], false)?;
            let len = request(&file, a[2], a[3], true)?;
            c.mem
                .check_write(GuestAddr(a[1]), len)
                .map_err(|_| Errno::EFAULT)?;
            let mut b = buffer(len)?;
            let count = read_at(&file, a[3], &mut b)?;
            output(c, a[1], &b[..count])?;
            Ok(count as u64)
        }
        18 => {
            let file = positioned(c, a[0], a[3], true)?;
            let len = request(&file, a[2], a[3], false)?;
            let len = size_limited(c, &file, Some(a[3]), len)?;
            // Check the guest buffer before allocating its copy, as write does.
            c.mem
                .check_read(GuestAddr(a[1]), len)
                .map_err(|_| Errno::EFAULT)?;
            let mut b = buffer(len)?;
            c.mem
                .read(GuestAddr(a[1]), &mut b)
                .map_err(|_| Errno::EFAULT)?;
            let written = write_at(&file, a[3], &b)?;
            if written > 0 {
                crate::permissions::remove_set_ids(&c.process.credentials, &*file);
            }
            Ok(written as u64)
        }
        19 => readv(c, a, 0),
        295 | 296 => positioned_vector(c, a, n == 296, 0),
        327 | 328 => {
            // pos_from_hilo: on x86-64 the high word shifts out, and -1 is
            // the file position, as readv and writev.
            let flags = a[5] as u32;
            match (a[3] == u64::MAX, n == 328) {
                (true, false) => readv(c, a, flags),
                (true, true) => writev(c, a, flags),
                (false, write) => positioned_vector(c, a, write, flags),
            }
        }
        22 | 293 => {
            let flags = if n == 22 {
                0
            } else {
                u32::try_from(a[1]).map_err(|_| Errno::EINVAL)?
            };
            if flags & !(crate::events::NONBLOCK | crate::events::CLOEXEC) != 0 {
                return Err(Errno::EINVAL);
            }
            c.mem
                .check_write(GuestAddr(a[0]), 8)
                .map_err(|_| Errno::EFAULT)?;
            let ends = crate::sockets::PipeEnd::pair(flags, Arc::clone(&c.files.readiness))?;
            let creds = &c.process.credentials;
            ends[0].set_owner(Some(creds.fsuid), Some(creds.fsgid))?;
            let [first, second] = c.files.install_pair(
                ends.map(|end| end as Arc<dyn FileHandle>),
                flags & crate::events::CLOEXEC != 0,
                c.group.nofile(),
            )?;
            let mut bytes = [0; 8];
            bytes[..4].copy_from_slice(&first.to_le_bytes());
            bytes[4..].copy_from_slice(&second.to_le_bytes());
            output(c, a[0], &bytes)?;
            Ok(0)
        }
        20 => writev(c, a, 0),
        0 | 1 => {
            let requested = usize::try_from(a[2].min(0x7fff_f000)).map_err(|_| Errno::EINVAL)?;
            let d = Some(c.files.descriptor(a[0])?);
            if let Some(d) = &d
                && cannot_read_or_write(&d.file)
            {
                return Err(Errno::EINVAL);
            }
            let len = if n == 0 {
                if let Some(d) = &d {
                    let metadata = d.file.stat()?;
                    // A namespace file is regular but has no position.
                    if metadata.mode & 0o170000 != 0o100000 || is_namespace(d) {
                        requested
                    } else {
                        let size = read_limit(&d.file, &metadata);
                        let pos = d.file.seek(0, 1)?;
                        requested
                            .min(usize::try_from(size.saturating_sub(pos)).unwrap_or(usize::MAX))
                    }
                } else {
                    requested
                }
            } else if let Some(d) = &d {
                size_limited(c, &d.file, None, requested)?
            } else {
                requested
            };
            // An inotify instance copies each record out as it takes it.
            if n == 0
                && let Some(d) = &d
                && let Some(instance) = crate::inotify::of(&d.file)
            {
                crate::sockets::access_ok_u64(a[1], a[2])?;
                return crate::inotify::read_guest(c, instance, a[1], len).map(|n| n as u64);
            }
            if n == 1 {
                c.mem
                    .check_read(GuestAddr(a[1]), len)
                    .map_err(|_| Errno::EFAULT)?;
            } else {
                c.mem
                    .check_write(GuestAddr(a[1]), len)
                    .map_err(|_| Errno::EFAULT)?;
            }
            let mut b = Vec::new();
            b.try_reserve(len).map_err(|_| Errno::ENOMEM)?;
            b.resize(len, 0);
            if n == 1 {
                c.mem
                    .read(GuestAddr(a[1]), &mut b)
                    .map_err(|_| Errno::EFAULT)?;
                return write_io(c, &d.ok_or(Errno::EBADF)?.file, &b, false);
            }
            let count = if let Some(d) = d {
                read_blocking(c, &d.file, &mut b)?
            } else if a[0] == 0 {
                c.host.read_stdin(&mut b)?
            } else {
                return Err(Errno::EBADF);
            };
            output(c, a[1], &b[..count])?;
            Ok(count as u64)
        }
        2 | 85 | 257 => {
            let (dir, raw, flags, mode) = match n {
                2 => ((-100i32) as u64, path(c, a[0])?, a[1], a[2]),
                85 => ((-100i32) as u64, path(c, a[0])?, 577, a[1]),
                _ => (a[0], path(c, a[1])?, a[2], a[3]),
            };
            open_at(c, dir, raw, flags, mode as u32, 0)
        }
        437 => openat2(c, a),
        3 => {
            let closed = c
                .files
                .fds
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .remove(&(a[0] as u32))
                .ok_or(Errno::EBADF)?;
            crate::record_locks::closed(c, &closed);
            crate::mqueue::closed(c, &closed);
            crate::inet::linger(c, &closed.file);
            Ok(0)
        }
        4 | 6 | 262 => {
            let (p, out, follow) = if n == 262 {
                if a[3] & !0x1100 != 0 {
                    return Err(Errno::EINVAL);
                }
                let raw = path(c, a[1])?;
                if raw.is_empty() && a[3] & 0x1000 != 0 {
                    let d = c.files.descriptor(a[0])?;
                    return stat(
                        c,
                        a[2],
                        d.file.stat()?,
                        descriptor_device(c, &d),
                        descriptor_block_size(c, &d),
                    );
                }
                let follow = a[3] & 0x100 == 0;
                (lookup(c, a[0], raw, follow)?.0, a[2], follow)
            } else {
                (
                    looked_up(c, (-100i32) as u64, a[0], n == 4)?.0,
                    a[1],
                    n == 4,
                )
            };
            if let Some((generated, device, block_size)) = generated_stat(c, &p, follow)? {
                return stat(c, out, generated, device, block_size);
            }
            stat(
                c,
                out,
                c.files.fs.metadata(&p, follow)?,
                device(c, &p),
                path_block_size(&p),
            )
        }
        5 => {
            let d = c.files.descriptor(a[0])?;
            stat(
                c,
                a[1],
                d.file.stat()?,
                descriptor_device(c, &d),
                descriptor_block_size(c, &d),
            )
        }
        8 => c
            .files
            .descriptor(a[0])?
            .file
            .seek(a[1] as i64, a[2] as u32),
        32 => {
            let d = Descriptor {
                cloexec: false,
                ..c.files.descriptor(a[0])?
            };
            c.files.allocate(d, 0, c.group.nofile()).map(u64::from)
        }
        33 | 292 => {
            // Both take unsigned int descriptors.
            let (old, new) = (a[0] as u32, a[1] as u32);
            if n == 292 && (a[2] & !0x80000 != 0 || old == new) {
                return Err(Errno::EINVAL);
            }
            // dup2 onto itself only checks the descriptor, keeping its flags.
            if old == new {
                return c.files.descriptor(u64::from(old)).map(|_| u64::from(new));
            }
            if u64::from(new) >= c.group.nofile() {
                return Err(Errno::EBADF);
            }
            let d = Descriptor {
                cloexec: n == 292 && a[2] & 0x80000 != 0,
                ..c.files.descriptor(u64::from(old))?
            };
            if let Some(closed) = c.files.replace(new, d)? {
                crate::record_locks::closed(c, &closed);
                crate::mqueue::closed(c, &closed);
                crate::inet::linger(c, &closed.file);
            }
            Ok(u64::from(new))
        }
        72 => {
            let mut d = c.files.descriptor(a[0])?;
            match a[1] {
                0 | 1030 => {
                    d.cloexec = a[1] == 1030;
                    // F_DUPFD takes an int, and a start at or past the limit
                    // is EINVAL rather than EMFILE.
                    let from = a[2] as u32;
                    let limit = c.group.nofile();
                    if u64::from(from) >= limit {
                        return Err(Errno::EINVAL);
                    }
                    c.files.allocate(d, from, limit).map(u64::from)
                }
                1 => Ok(u64::from(d.cloexec)),
                2 => c.files.set_cloexec(a[0], a[2] & 1 != 0).map(|()| 0),
                3 => Ok(u64::from(status_flags(&d))),
                // F_ADD_SEALS and F_GET_SEALS, for memfds only.
                1033 | 1034 => {
                    // A secret file is no shmem file and has no seals.
                    let memfd = d
                        .file
                        .as_any()
                        .and_then(|v| v.downcast_ref::<crate::memfd::Memfd>())
                        .filter(|memfd| !memfd.is_secret());
                    match (a[1], memfd) {
                        (1034, Some(memfd)) => Ok(u64::from(memfd.seals())),
                        (1033, Some(memfd)) => {
                            let key = (crate::memfd::DEVICE, d.file.stat()?.inode);
                            let caches = &c.files.caches;
                            let mapped = || {
                                caches
                                    .find(key)
                                    .is_some_and(|cache| cache.mapped_writable())
                            };
                            memfd.add_seals(d.file.flags() & 3 != 0, a[2] as u32, mapped)?;
                            Ok(0)
                        }
                        // memfd_add_seals checks the access and the bits first.
                        (1033, None) if d.file.flags() & 3 == 0 => Err(Errno::EPERM),
                        _ => Err(Errno::EINVAL),
                    }
                }
                // F_SETPIPE_SZ and F_GETPIPE_SZ, for pipes only.
                1031 | 1032 => {
                    let pipe = d
                        .file
                        .as_any()
                        .and_then(|any| any.downcast_ref::<crate::sockets::PipeEnd>())
                        .ok_or(Errno::EBADF)?;
                    if a[1] == 1031 {
                        pipe.set_size(a[2] as u32)
                    } else {
                        Ok(pipe.size())
                    }
                }
                4 => crate::fasync::set_flags(c, &d.file, a[0], a[2] as u32).map(|()| 0),
                // The owner and signal of signal-driven I/O.
                8..=11 | 15 | 16 => crate::fasync::fcntl(c, &d.file, a[1], a[2]),
                // Byte-range locks: F_GETLK, F_SETLK, F_SETLKW and their OFD forms.
                5..=7 | 36..=38 => crate::record_locks::fcntl(c, &d, a[1], a[2]),
                _ => Err(Errno::EINVAL),
            }
        }
        73 => {
            let d = c.files.descriptor(a[0])?;
            loop {
                let result = d.file.flock(a[1] as u32);
                c.processes
                    .locks()
                    .flocked(&d.file, c.process.pid, a[1] as u32, result);
                match result {
                    Ok(()) => return Ok(0),
                    Err(e) if e == Errno::EAGAIN && a[1] & 4 == 0 => pause_for_lock(c)?,
                    Err(e) => return Err(e),
                }
            }
        }
        76 | 77 => {
            let f = if n == 77 {
                let file = io_descriptor(c, a[0])?;
                // `do_ftruncate`: an append-only file is not truncated
                // (EPERM), after the length and the description's
                // EINVAL, before Landlock's right.
                if a[1] <= i64::MAX as u64
                    && file.flags() & 3 != 0
                    && let Ok(stat) = file.stat()
                    && stat.mode & 0o170000 == 0o100000
                    && attributes::append_only(&stat)
                {
                    return Err(Errno::EPERM);
                }
                // Landlock's right kept from the open (`hook_file_truncate`),
                // for a description open for writing.
                if file.flags() & 3 != 0
                    && c.files.descriptor(a[0])?.landlock & crate::landlock::TRUNCATE == 0
                {
                    return Err(Errno::EACCES);
                }
                file
            } else {
                let (p, found) = looked_up(c, (-100i32) as u64, a[0], true)?;
                // Landlock's TRUNCATE on the file (`hook_path_truncate`).
                if let Some(target) = landlock_target(c, &p, true) {
                    crate::landlock::check(c, &target, crate::landlock::TRUNCATE)?;
                }
                match reached(c, &p, true)? {
                    // A link in `/proc/self/fd` leads to the descriptor's
                    // file, which the call opens for writing again, as
                    // does a queue's path in `/dev/mqueue`.
                    Some(Followed::Path { path, follow }) => {
                        let stat = c.files.fs.metadata(&path, follow)?;
                        crate::permissions::truncate(&c.process.credentials, &stat)?;
                        crate::inotify::unnoticed(|| c.files.fs.open(&path, 1, 0))?
                    }
                    Some(Followed::File(d)) => {
                        crate::permissions::truncate(&c.process.credentials, &d.file.stat()?)?;
                        crate::inotify::unnoticed(|| d.file.reopen(1))?
                    }
                    None => {
                        if let Some(stat) = found.file {
                            crate::permissions::truncate(&c.process.credentials, &stat)?;
                        }
                        crate::inotify::unnoticed(|| c.files.fs.open(&p, 1, 0))?
                    }
                }
            };
            if a[1] > i64::MAX as u64 {
                return Err(Errno::EINVAL);
            }
            // Growing a file past RLIMIT_FSIZE raises SIGXFSZ (inode_newsize_ok).
            if a[1] > c.group.fsize() && f.stat()?.size < a[1] {
                crate::signals::queue(c.process, crate::signals::PendingSignal::user(25, 0));
                return Err(Errno(27));
            }
            f.truncate(a[1])?;
            if n == 77 {
                crate::mqueue::truncated(c, &*f);
            }
            crate::permissions::remove_set_ids(&c.process.credentials, &*f);
            Ok(0)
        }
        79 => {
            let mut p = c
                .files
                .cwd
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone();
            p.push(0);
            if a[1] < p.len() as u64 {
                return Err(Errno::ERANGE);
            }
            output(c, a[0], &p)?;
            Ok(p.len() as u64)
        }
        80 | 81 => {
            let p = if n == 80 {
                let p = looked_up(c, (-100i32) as u64, a[0], true)?.0;
                match followed(c, &p, true)? {
                    // A symbolic link an `O_PATH | O_NOFOLLOW` descriptor
                    // holds is not followed again: it is no directory.
                    Some(Followed::Path { path, follow }) => {
                        if c.files.fs.metadata(&path, follow)?.mode & 0o170000 != 0o040000 {
                            return Err(Errno::ENOTDIR);
                        }
                        path
                    }
                    Some(Followed::File(d)) if d.file.stat()?.mode & 0o170000 != 0o040000 => {
                        return Err(Errno::ENOTDIR);
                    }
                    Some(Followed::File(d)) => d.path,
                    None => p,
                }
            } else {
                c.files.descriptor(a[0])?.path
            };
            let stat = c.files.fs.metadata(&p, true)?;
            if stat.mode & 0o170000 != 0o040000 {
                return Err(Errno::ENOTDIR);
            }
            if !crate::permissions::unchecked(&c.process.credentials) {
                crate::permissions::permission(
                    &c.process.credentials,
                    &stat,
                    crate::permissions::MAY_EXEC,
                )?;
            }
            c.files.change_directory(p);
            Ok(0)
        }
        82 | 264 | 316 => {
            // renameat2's flags, checked as Linux's do_renameat2 checks them
            // before it looks a name up: RENAME_NOREPLACE (1),
            // RENAME_EXCHANGE (2) and RENAME_WHITEOUT (4), which needs
            // CAP_MKNOD and which no filesystem here has (EINVAL).
            let flags = if n == 316 { a[4] } else { 0 };
            if flags & !7 != 0 || flags & 5 != 0 && flags & 2 != 0 {
                return Err(Errno::EINVAL);
            }
            if flags & 4 != 0 && !crate::permissions::may_mknod(&c.process.credentials) {
                return Err(Errno::EPERM);
            }
            let flags = flags as u32;
            let ((old_dir, old_raw), (new_dir, new_raw)) = if n == 82 {
                (
                    ((-100i32) as u64, path(c, a[0])?),
                    ((-100i32) as u64, path(c, a[1])?),
                )
            } else {
                ((a[0], path(c, a[1])?), (a[2], path(c, a[3])?))
            };
            let old = c.files.path(old_dir, old_raw.clone())?;
            let new = c.files.path(new_dir, new_raw.clone())?;
            let names = (queue_name(&old), queue_name(&new));
            if names.0.is_some() || names.1.is_some() {
                let walks = ((old_dir, &old_raw[..]), (new_dir, &new_raw[..]));
                return rename_queue(c, (&old, &new), walks, names, flags);
            }
            crate::permissions::rename(
                c.files,
                &c.process.credentials,
                (old_dir, &old_raw),
                (new_dir, &new_raw),
                flags,
                || device(c, &old) == device(c, &new),
            )?;
            // A filesystem here refuses RENAME_WHITEOUT (EINVAL), but Linux
            // first refuses a name RENAME_NOREPLACE would replace, also for
            // root, whose lookups permissions::rename skips.
            if flags & 5 == 5
                && c.files.fs.metadata(&old, false).is_ok()
                && c.files.fs.metadata(&new, false).is_ok()
            {
                return Err(Errno::EEXIST);
            }
            // Landlock's check (`hook_path_rename`) of names that are there
            // as the flags ask, on one filesystem.
            if c.process.credentials.landlock != Default::default()
                && device(c, &old) == device(c, &new)
                && let (Some((old_path, Some(_))), Some((new_path, new_stat))) =
                    (landlock_named(c, &old), landlock_named(c, &new))
                && (flags & 1 == 0 || new_stat.is_none())
                && (flags & 2 == 0 || new_stat.is_some())
            {
                crate::landlock::refer(c, &old_path, &new_path, true, flags)?;
            }
            c.files.fs.rename_with(&old, &new, flags)?;
            // The paths of descriptors and the working directory under a
            // name that moved; an exchange moves both names.
            let moved = |p: &[u8]| -> Option<Vec<u8>> {
                let under = |from: &[u8], to: &[u8]| {
                    (p == from || p.starts_with(from) && p.get(from.len()) == Some(&b'/')).then(
                        || {
                            let mut q = to.to_vec();
                            q.extend_from_slice(&p[from.len()..]);
                            q
                        },
                    )
                };
                under(&old, &new).or_else(|| (flags == 2).then(|| under(&new, &old)).flatten())
            };
            for d in c
                .files
                .fds
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .values_mut()
            {
                if let Some(p) = moved(&d.path) {
                    d.path = p;
                }
            }
            let mut cwd = c.files.cwd.lock().unwrap_or_else(PoisonError::into_inner);
            if let Some(p) = moved(&cwd) {
                *cwd = p;
            }
            Ok(0)
        }
        83 | 258 => {
            let (dir, raw, mode) = if n == 83 {
                ((-100i32) as u64, path(c, a[0])?, a[1])
            } else {
                (a[0], path(c, a[1])?, a[2])
            };
            let p = c.files.path(dir, raw.clone())?;
            if queue_root(&p) {
                return Err(Errno::EEXIST);
            }
            if let Some(name) = queue_name(&p) {
                return crate::mqueue::make_mounted(c, &name, None, || {
                    landlock_name(c, &p, crate::landlock::MAKE_DIR)
                });
            }
            let created = crate::permissions::create(c.files, &c.process.credentials, dir, &raw)?;
            if landlock_named(c, &p).is_some_and(|(_, there)| there.is_none()) {
                landlock_name(c, &p, crate::landlock::MAKE_DIR)?;
            }
            c.files.fs.mkdir(&p, (mode as u32) & !c.files.umask())?;
            if let Some(parent) = created {
                crate::permissions::own(c.files, &c.process.credentials, &p, false, &parent);
            }
            Ok(0)
        }
        133 | 259 => {
            let (dir, raw, mode, dev) = if n == 133 {
                ((-100i32) as u64, path(c, a[0])?, a[1] as u32, a[2] as u32)
            } else {
                (a[0], path(c, a[1])?, a[2] as u32, a[3] as u32)
            };
            mknod(c, dir, &raw, mode, dev)?;
            Ok(0)
        }
        84 | 87 | 263 => {
            let (at_dir, raw, dir) = if n == 263 {
                if a[2] & !512 != 0 {
                    return Err(Errno::EINVAL);
                }
                (a[0], path(c, a[1])?, a[2] & 512 != 0)
            } else {
                ((-100i32) as u64, path(c, a[0])?, n == 84)
            };
            let p = c.files.path(at_dir, raw.clone())?;
            if let Some(name) = paludarium_vfs::normalize_path(&p)
                .ok()
                .as_deref()
                .and_then(crate::mqueue::mounted_name)
            {
                let request = if dir {
                    crate::landlock::REMOVE_DIR
                } else {
                    crate::landlock::REMOVE_FILE
                };
                return crate::mqueue::unlink_mounted(c, name, dir, || {
                    landlock_name(c, &p, request)
                });
            }
            crate::permissions::delete(c.files, &c.process.credentials, at_dir, &raw)?;
            if landlock_named(c, &p).is_some_and(|(_, there)| there.is_some()) {
                let request = if dir {
                    crate::landlock::REMOVE_DIR
                } else {
                    crate::landlock::REMOVE_FILE
                };
                landlock_name(c, &p, request)?;
            }
            c.files.fs.unlink(&p, dir)?;
            Ok(0)
        }
        86 | 265 => link(c, n, a),
        88 | 266 => {
            let target = string(c, a[0])?;
            let (dir, raw) = if n == 88 {
                ((-100i32) as u64, path(c, a[1])?)
            } else {
                (a[1], path(c, a[2])?)
            };
            let p = c.files.path(dir, raw.clone())?;
            if queue_root(&p) {
                return Err(Errno::EEXIST);
            }
            if let Some(name) = queue_name(&p) {
                return crate::mqueue::make_mounted(c, &name, None, || {
                    landlock_name(c, &p, crate::landlock::MAKE_SYM)
                });
            }
            let created = crate::permissions::create(c.files, &c.process.credentials, dir, &raw)?;
            if landlock_named(c, &p).is_some_and(|(_, there)| there.is_none()) {
                landlock_name(c, &p, crate::landlock::MAKE_SYM)?;
            }
            c.files.fs.symlink(&target, &p)?;
            if let Some(parent) = created {
                crate::permissions::own(c.files, &c.process.credentials, &p, false, &parent);
            }
            Ok(0)
        }
        89 | 267 => {
            // An empty path reads the link an `O_PATH | O_NOFOLLOW`
            // descriptor holds; any other descriptor, and the working
            // directory (AT_FDCWD), is no link (ENOENT), as Linux's
            // `do_readlinkat` finds.
            if n == 267 && path(c, a[1])?.is_empty() {
                if a[3] == 0 {
                    return Err(Errno::EINVAL);
                }
                if a[0] as i32 == -100 {
                    return Err(Errno::ENOENT);
                }
                let d = c.files.descriptor(a[0])?;
                let link = d
                    .file
                    .as_any()
                    .and_then(|v| v.downcast_ref::<LinkPath>())
                    .ok_or(Errno::ENOENT)?;
                let b = link.target(c)?;
                let count = b
                    .len()
                    .min(usize::try_from(a[3]).map_err(|_| Errno::EINVAL)?);
                output(c, a[2], &b[..count])?;
                return Ok(count as u64);
            }
            let (p, buf, len) = if n == 89 {
                (looked_up(c, (-100i32) as u64, a[0], false)?.0, a[1], a[2])
            } else {
                (looked_up(c, a[0], a[1], false)?.0, a[2], a[3])
            };
            if len == 0 {
                return Err(Errno::EINVAL);
            }
            // `/proc/self` is a link to this process's directory, and each
            // entry of its `fd` to a descriptor's file.
            let p = crate::devices::through_link(&p).unwrap_or(p);
            let b = if p == b"/proc/self" {
                c.process.pid.to_string().into_bytes()
            } else if let Some(path) = crate::proc::task_path(&p, c.process.pid, c.tid) {
                let task = tasks::find(c, &path)?;
                tasks::check(c, &task, path.entry)?;
                match tasks::link(&task, path.entry) {
                    Some(target) => target?,
                    None if path.entry == crate::proc::TaskEntry::Missing => {
                        return Err(Errno::ENOENT);
                    }
                    None => return Err(Errno::EINVAL),
                }
            } else if let Some(entry) = crate::devices::entry(&p) {
                let crate::devices::Entry::Link(target) = entry else {
                    return Err(Errno::EINVAL);
                };
                target.to_vec()
            } else if let Some(entry) = crate::proc::own_entry(&p, c.process.pid) {
                if let Some(target) = own_link(c, entry) {
                    target
                } else {
                    let crate::proc::OwnEntry::Descriptor(n) = entry else {
                        return Err(Errno::EINVAL);
                    };
                    let d = c
                        .files
                        .descriptor(u64::from(n))
                        .map_err(|_| Errno::ENOENT)?;
                    link_target(c, &d)?
                }
            } else {
                c.files.fs.readlink(&p)?
            };
            let count = b
                .len()
                .min(usize::try_from(len).map_err(|_| Errno::EINVAL)?);
            output(c, buf, &b[..count])?;
            Ok(count as u64)
        }
        // getdents (the old `linux_dirent`), getdents64
        78 | 217 => directory_entries(c, a[0], a[1], a[2] as u32, n == 78),
        // ustat(dev, ubuf)
        136 => ustat(c, a[0] as u32, a[1]),
        // umask
        95 => Ok(u64::from(
            c.files.umask.swap(a[0] as u32 & 0o777, Ordering::SeqCst),
        )),
        // chmod, fchmod, fchmodat (which has no flags argument)
        90 | 268 => {
            let (p, mode) = if n == 90 {
                (looked_up(c, (-100i32) as u64, a[0], true)?, a[1])
            } else {
                (looked_up(c, a[0], a[1], true)?, a[2])
            };
            let (p, found) = p;
            if let Some(target) = reached(c, &p, true)? {
                return chmod_followed(c, target, mode as u32);
            }
            let mode = match found.file {
                Some(stat) => {
                    crate::permissions::chmod(&c.process.credentials, &stat, mode as u32)?
                }
                None => mode as u32,
            };
            c.files.fs.set_mode(&p, mode).map(|()| 0)
        }
        91 => {
            let file = io_descriptor(c, a[0])?;
            let mode =
                crate::permissions::chmod(&c.process.credentials, &file.stat()?, a[1] as u32)?;
            file.set_mode(mode).map(|()| 0)
        }
        452 => fchmodat2(c, a),
        // Extended attributes.
        188..=199 | 463..=466 => xattrs::call(c, n, a),
        468 | 469 => attributes::call(c, n, a),
        // chown, fchown, lchown, fchownat
        92 | 94 => {
            let (p, _) = looked_up(c, (-100i32) as u64, a[0], n == 92)?;
            chown_path(c, &p, n == 92, a[1], a[2])
        }
        93 => chown_file(c, &io_descriptor(c, a[0])?, a[1], a[2]),
        260 => fchownat(c, a),
        280 => utimensat(c, a),
        132 => utime(c, a[0], a[1]),
        235 => futimesat(c, AT_FDCWD, a[0], a[1]),
        261 => futimesat(c, a[0], a[1], a[2]),
        // statfs, fstatfs
        137 => {
            let (p, _) = looked_up(c, (-100i32) as u64, a[0], true)?;
            let stats = path_statfs(c, &p)?;
            write_statfs(c, a[1], stats)
        }
        138 => {
            let d = c.files.descriptor(a[0])?;
            let stats = descriptor_statfs(c, &d)?;
            write_statfs(c, a[1], stats)
        }
        // access, faccessat, faccessat2
        21 => access(c, (-100i32) as u64, a[0], a[1], 0),
        269 => access(c, a[0], a[1], a[2], 0),
        439 => access(c, a[0], a[1], a[2], a[3]),
        // fsync, fdatasync: both write everything, as nothing is cached; an
        // `O_PATH` descriptor is EBADF, as Linux's `fdget` refuses it.
        74 | 75 => io_descriptor(c, a[0])?.sync().map(|()| 0),
        // sync: nothing is cached, so there is nothing to write
        162 => Ok(0),
        // syncfs: every file is written through already, as after sync.
        306 => io_descriptor(c, a[0]).map(|_| 0),
        // readahead(fd, offset, count), as Linux's `ksys_readahead`: a
        // descriptor open for reading (EBADF), of a regular file or a block
        // device (EINVAL), and a count that is not negative as a `loff_t`
        // (`generic_fadvise`'s EINVAL). There is no cache to fill.
        187 => {
            let file = io_descriptor(c, a[0])?;
            if file.flags() & 3 == 1 {
                return Err(Errno::EBADF);
            }
            let kind = file.stat()?.mode & 0o170000;
            if kind != 0o100000 && kind != 0o060000 || (a[2] as i64) < 0 {
                return Err(Errno::EINVAL);
            }
            Ok(0)
        }
        // sync_file_range(fd, offset, nbytes, flags), checked in the order of
        // Linux's: the descriptor (EBADF, `O_PATH` too), the flags and the
        // range (EINVAL: a negative offset or end, or an end before the
        // offset), then the file's type (ESPIPE for one that is not a regular
        // file, a directory, a block device or a link). Its `stat` writes the
        // stores of shared mappings back to the file; what reaches the host's
        // file is the host's to write out, as for `write`.
        277 => {
            let file = io_descriptor(c, a[0])?;
            let (offset, nbytes) = (a[1] as i64, a[2] as i64);
            let end = offset.wrapping_add(nbytes);
            if a[3] as u32 & !7 != 0 || offset < 0 || end < 0 || end < offset {
                return Err(Errno::EINVAL);
            }
            if !matches!(
                file.stat()?.mode & 0o170000,
                0o100000 | 0o040000 | 0o060000 | 0o120000
            ) {
                return Err(Errno(29)); // ESPIPE
            }
            Ok(0)
        }
        // fadvise64: a hint, checked as Linux checks it
        221 => {
            let file = io_descriptor(c, a[0])?;
            if file.stat()?.mode & 0o170000 == 0o010000 {
                return Err(Errno(29)); // ESPIPE
            }
            if (a[2] as i64) < 0 || a[3] > 5 {
                return Err(Errno::EINVAL);
            }
            Ok(0)
        }
        _ => Err(Errno::ENOSYS),
    }
}
/// Blocking stream writes preserve partial progress across readiness retries.
/// No descriptor-table, stream-state or guest-memory lock spans a Host wait.
pub(crate) fn write_io(
    c: &mut Context<'_>,
    file: &Arc<dyn FileHandle>,
    bytes: &[u8],
    nosignal: bool,
) -> Result<u64, Errno> {
    write_io_with(c, file, bytes, nosignal, false)
}
/// [`write_io`] that, with `dontwait` (`RWF_NOWAIT`), does not wait.
fn write_io_with(
    c: &mut Context<'_>,
    file: &Arc<dyn FileHandle>,
    bytes: &[u8],
    nosignal: bool,
    dontwait: bool,
) -> Result<u64, Errno> {
    // A pseudo-terminal writes all, unless it does not block.
    if let Some(result) = crate::pty::write(c, file, bytes) {
        return result;
    }
    // A socket's writes carry the credentials of their process.
    if let Some(socket) = file
        .as_any()
        .and_then(|a| a.downcast_ref::<crate::sockets::SocketPairEnd>())
    {
        let sender = crate::sockets::Sender::process(c.process.pid, &c.process.credentials);
        return write_with(c, file, bytes, nosignal, dontwait, |b| {
            socket.send(b, &mut Vec::new(), sender)
        });
    }
    let written = write_with(c, file, bytes, nosignal, dontwait, |b| file.write(b))?;
    if written > 0 {
        crate::permissions::remove_set_ids(&c.process.credentials, &**file);
    }
    Ok(written)
}
/// [`write_io`] through `write`, which writes to `file`; with `dontwait`
/// (`MSG_DONTWAIT`) it does not wait, as if `file` were nonblocking.
pub(crate) fn write_with(
    c: &mut Context<'_>,
    file: &Arc<dyn FileHandle>,
    bytes: &[u8],
    nosignal: bool,
    dontwait: bool,
    mut write: impl FnMut(&[u8]) -> Result<usize, Errno>,
) -> Result<u64, Errno> {
    // A socket or pipe write goes on until all is written, as Linux's
    // `unix_stream_sendmsg` and `pipe_write` do.
    let stream = crate::sockets::endpoint(file).is_some()
        || crate::inet::of(file).is_some_and(crate::inet::InetSocket::is_stream);
    // A socket waits no longer than its SO_SNDTIMEO.
    let wait = crate::sockets::deadline(c, file, false)?;
    let mut done = 0;
    let mut blocked = false;
    loop {
        let ticket = c.files.readiness.token.value();
        let nonblocking = dontwait || file.flags() & crate::events::NONBLOCK != 0;
        let result = write(&bytes[done..]);
        // A pipe write that finds the pipe full signals its reader before it
        // waits, as Linux's `pipe_write`, or as it ends; after a part, which
        // signalled itself, a wait it ends is that part's.
        if !blocked && done == 0 && result.is_err_and(|e| e == Errno::EAGAIN) {
            blocked = true;
            crate::sockets::pipe_write_blocked(file);
        }
        match result {
            Ok(count) => {
                done += count;
                if count == 0 || done == bytes.len() || nonblocking || !stream {
                    return Ok(done as u64);
                }
            }
            Err(e) if e == Errno::EAGAIN && file.readiness().is_ok() && !nonblocking => {
                // Read at once, as another thread's send on the socket may
                // change it while this one waits.
                let out_of_room = crate::sockets::out_of_room(file);
                let deadline = match wait.deadline(c)? {
                    Some(deadline) => deadline,
                    None if done != 0 => return Ok(done as u64),
                    None => return Err(Errno::EAGAIN),
                };
                if let Err(e) = crate::events::wait(c, ticket, deadline) {
                    if !wait.forever() {
                        c.process.restart = None;
                    }
                    return if done != 0 { Ok(done as u64) } else { Err(e) };
                }
                // A datagram sender with no room sleeps on until a quarter
                // of its send buffer is free, or its time is up, when it
                // looks once more, as Linux's `sock_alloc_send_pskb` does.
                if out_of_room {
                    loop {
                        let ticket = c.files.readiness.token.value();
                        if !crate::sockets::sleeps_for_room(file) {
                            break;
                        }
                        let Some(deadline) = wait.deadline(c)? else {
                            break;
                        };
                        if let Err(e) = crate::events::wait(c, ticket, deadline) {
                            if !wait.forever() {
                                c.process.restart = None;
                            }
                            return Err(e);
                        }
                    }
                }
            }
            Err(e) => {
                if done != 0 {
                    return Ok(done as u64);
                }
                // A UDP socket's EPIPE raises none, as `sock_alloc_send_pskb`
                // gives it without one.
                let sigpipe = file
                    .as_any()
                    .and_then(|a| a.downcast_ref::<crate::sockets::SocketPairEnd>())
                    .is_none_or(crate::sockets::SocketPairEnd::raises_sigpipe)
                    && crate::inet::of(file).is_none_or(crate::inet::InetSocket::is_stream);
                if e == Errno(32) && !nosignal && sigpipe {
                    crate::signals::queue(c.process, crate::signals::PendingSignal::user(13, 0));
                }
                return Err(e);
            }
        }
    }
}
/// `O_PATH`: only a path, not an open file.
pub(crate) const O_PATH: u32 = 0o10000000;
/// The descriptor `O_PATH | O_NOFOLLOW` gives for a symbolic link: the link
/// itself, as Linux opens it, whose `fstat` is the link's and whose
/// `readlinkat(fd, "")` reads where it points; nothing reads or writes
/// through it.
pub(crate) struct LinkPath {
    stat: FileStat,
    target: LinkTarget,
}
/// Where a [`LinkPath`] points.
enum LinkTarget {
    /// A symbolic link of the filesystem or `/dev`, whose target stays.
    Fixed(Vec<u8>),
    /// A link in `/proc/self/fd`, which names the descriptor's file as it
    /// is when read.
    Descriptor(u32),
    /// `/proc/self`, which names the directory of the process that reads it.
    OwnProcess,
}
impl LinkPath {
    /// The symbolic link `p` names itself, or `None` when it is no link.
    fn of(c: &Context<'_>, p: &[u8]) -> Result<Option<Self>, Errno> {
        if let Some(crate::devices::Entry::Link(target)) = crate::devices::entry(p) {
            return Ok(Some(Self {
                stat: crate::devices::stat(crate::devices::Entry::Link(target)),
                target: LinkTarget::Fixed(target.to_vec()),
            }));
        }
        if let Some(crate::proc::OwnEntry::Descriptor(n)) = crate::proc::own_entry(p, c.process.pid)
        {
            let d = c
                .files
                .descriptor(u64::from(n))
                .map_err(|_| Errno::ENOENT)?;
            return Ok(Some(Self {
                stat: crate::proc::link_stat(d.file.flags() & 3),
                target: LinkTarget::Descriptor(n),
            }));
        }
        if p == b"/proc/self" {
            return Ok(Some(Self {
                stat: crate::proc::self_link_stat(),
                target: LinkTarget::OwnProcess,
            }));
        }
        if let Some(path) = crate::proc::task_path(p, c.process.pid, c.tid) {
            let task = tasks::find(c, &path)?;
            tasks::check(c, &task, path.entry)?;
            return match tasks::link(&task, path.entry) {
                Some(target) => Ok(Some(Self {
                    stat: crate::proc::self_link_stat(),
                    target: LinkTarget::Fixed(target?),
                })),
                None => Ok(None),
            };
        }
        if generated(p) {
            return Ok(None);
        }
        match c.files.fs.metadata(p, false) {
            Ok(stat) if stat.mode & 0o170000 == 0o120000 => Ok(Some(Self {
                stat,
                target: LinkTarget::Fixed(c.files.fs.readlink(p)?),
            })),
            _ => Ok(None),
        }
    }
    /// What `readlink` of the link gives.
    fn target(&self, c: &Context<'_>) -> Result<Vec<u8>, Errno> {
        match &self.target {
            LinkTarget::Fixed(target) => Ok(target.clone()),
            LinkTarget::OwnProcess => Ok(c.process.pid.to_string().into_bytes()),
            LinkTarget::Descriptor(n) => {
                let d = c
                    .files
                    .descriptor(u64::from(*n))
                    .map_err(|_| Errno::ENOENT)?;
                link_target(c, &d)
            }
        }
    }
}
impl FileHandle for LinkPath {
    fn as_any(&self) -> Option<&dyn std::any::Any> {
        Some(self)
    }
    fn read(&self, _: &mut [u8]) -> Result<usize, Errno> {
        Err(Errno::EBADF)
    }
    fn write(&self, _: &[u8]) -> Result<usize, Errno> {
        Err(Errno::EBADF)
    }
    fn seek(&self, _: i64, _: u32) -> Result<u64, Errno> {
        Err(Errno::EBADF)
    }
    fn stat(&self) -> Result<FileStat, Errno> {
        Ok(self.stat)
    }
    fn truncate(&self, _: u64) -> Result<(), Errno> {
        Err(Errno::EBADF)
    }
    fn flock(&self, _: u32) -> Result<(), Errno> {
        Err(Errno::EBADF)
    }
    fn flags(&self) -> u32 {
        O_PATH | 0o400000
    }
    fn set_flags(&self, _: u32) -> Result<(), Errno> {
        Err(Errno::EBADF)
    }
}
pub(crate) struct StandardFile {
    host: Arc<dyn paludarium_host::Host>,
    channel: u32,
    /// For edge-triggered epoll on standard input: how often it has become
    /// ready, and whether it was ready when last asked.
    rises: AtomicU64,
    was_ready: std::sync::atomic::AtomicBool,
    /// The status flags, as `F_SETFL` leaves them: the guest's own, which
    /// never reach the host's descriptor.
    flags: AtomicU32,
    /// Standard input's `O_ASYNC` registration, and whether a thread
    /// watches the host's input for it.
    registration: Mutex<Option<crate::fasync::Registration>>,
    watching: std::sync::atomic::AtomicBool,
    /// The guest was told `EAGAIN`, and may wait for `SIGIO` from now on. The
    /// watcher looks only now and then, and must not miss what comes next.
    refused: std::sync::atomic::AtomicBool,
}
/// The flags `F_SETFL` changes (Linux's `SETFL_MASK` but `O_ASYNC`, which
/// only a file with `fasync` keeps): `O_APPEND`, `O_NONBLOCK`, `O_DIRECT`
/// and `O_NOATIME`.
const SETFL_FLAGS: u32 = 0o2000 | 0o4000 | 0o40000 | 0o1000000;
/// What `F_GETFL` gives for `d`, as Linux keeps a file's `f_flags`: the open
/// flags less `O_CLOEXEC` (`build_open_flags`) and `O_CREAT`, `O_EXCL`,
/// `O_NOCTTY` and `O_TRUNC` (`do_dentry_open`), and `O_LARGEFILE` for a
/// description opened by a path ([`Descriptor`]'s `opened`) or a memfd,
/// which x86-64's `force_o_largefile` adds; an `O_PATH` file keeps only
/// `O_DIRECTORY`, `O_NOFOLLOW` and `O_PATH`. Pipes, sockets, the kernel's
/// own files and the host's standard streams, made with no open by path,
/// have no `O_LARGEFILE`.
fn status_flags(d: &Descriptor) -> u32 {
    const O_LARGEFILE: u32 = 0o100000;
    const O_DIRECTORY: u32 = 0o200000;
    const O_NOFOLLOW: u32 = 0o400000;
    const O_CLOEXEC: u32 = 0o2000000;
    const OPEN_ONLY: u32 = 0o100 | 0o200 | 0o400 | 0o1000 | O_CLOEXEC;
    let flags = d.file.flags();
    if flags & O_PATH != 0 {
        return flags & (O_DIRECTORY | O_NOFOLLOW | O_PATH);
    }
    let any = d.file.as_any();
    let opened = d.opened || any.is_some_and(|v| v.is::<crate::memfd::Memfd>());
    // A pidfd keeps `PIDFD_THREAD`, which is `O_EXCL`: `pidfs_alloc_file`
    // sets it again after `do_dentry_open` drops the flags of the open.
    // One opened by `open_by_handle_at` keeps `O_CLOEXEC` too, as
    // `pidfs_export_open` hands the flags to `dentry_open` as they are.
    let open_only = if any.is_some_and(|v| v.is::<crate::processes::PidFd>()) {
        OPEN_ONLY & !(0o200 | O_CLOEXEC)
    } else {
        OPEN_ONLY
    };
    flags & !open_only | if opened { O_LARGEFILE } else { 0 }
}
/// How often a thread looks at a host's standard stream for `O_ASYNC`.
const STREAM_WATCH: std::time::Duration = std::time::Duration::from_millis(10);
impl StandardFile {
    fn new(host: &Arc<dyn paludarium_host::Host>, channel: u32) -> Self {
        Self {
            host: Arc::clone(host),
            channel,
            rises: AtomicU64::new(0),
            was_ready: std::sync::atomic::AtomicBool::new(false),
            flags: AtomicU32::new(u32::from(channel != 0)),
            registration: Mutex::new(None),
            watching: std::sync::atomic::AtomicBool::new(false),
            refused: std::sync::atomic::AtomicBool::new(false),
        }
    }
    /// Whether the host's standard input has something for a read: bytes,
    /// or its end; where the host cannot tell, always.
    fn stdin_ready(&self) -> bool {
        self.host.stdin_state() != Some(paludarium_host::StdinState::Waiting)
    }
    /// Whether this stream is ready for what its `O_ASYNC` signals: input
    /// to read, or output with room; where the host cannot tell, always.
    fn ready(&self) -> bool {
        if self.channel == 0 {
            self.stdin_ready()
        } else {
            self.host.output_writable(self.channel) != Some(false)
        }
    }
    /// Whether a write of output with `O_NONBLOCK` is `EAGAIN`: the host
    /// has no room for it now. One with some room goes whole, waiting on
    /// the host for the rest, where Linux writes what fits: only the host's
    /// descriptor's own `O_NONBLOCK` could stop it short, and that flag is
    /// shared with the host's other processes.
    pub(crate) fn would_block(&self) -> bool {
        let full = self.channel != 0
            && self.flags() & crate::events::NONBLOCK != 0
            && self.host.output_writable(self.channel) == Some(false);
        if full {
            self.refused.store(true, Ordering::SeqCst);
        }
        full
    }
    /// Whether the host's stream behind this one is a pipe, socket or
    /// terminal, which signals with `O_ASYNC`.
    pub(crate) fn signals(&self) -> bool {
        if self.channel == 0 {
            self.host.stdin_signals()
        } else {
            self.host.output_signals(self.channel)
        }
    }
    /// `F_SETFL` turning `O_ASYNC` on, with its registration, or off. The
    /// host's streams change outside the emulator, so a thread looks at the
    /// stream every [`STREAM_WATCH`] while `O_ASYNC` is on, and sends `SIGIO`
    /// each time it becomes ready ([`StandardFile::ready`]) after it was
    /// not, or after the guest was told `EAGAIN`: `POLL_IN` for input that
    /// comes, as Linux's pipe and terminal do, and `POLL_OUT` for output that
    /// has room again. A host without
    /// threads (WebAssembly) sends none.
    pub(crate) fn set_async(
        &self,
        file: &Arc<dyn FileHandle>,
        registration: Option<crate::fasync::Registration>,
    ) {
        let mut kept = self
            .registration
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        *kept = registration;
        if kept.is_none() || self.watching.swap(true, Ordering::SeqCst) {
            return;
        }
        let file = Arc::downgrade(file);
        // Taken now, so that a change before the thread first looks still
        // counts.
        self.refused.store(false, Ordering::SeqCst);
        let mut was = self.ready();
        let reason = if self.channel == 0 {
            crate::fasync::Reason::In
        } else {
            crate::fasync::Reason::Out
        };
        let started = self.host.spawn_thread(Box::new(move || {
            loop {
                std::thread::sleep(STREAM_WATCH);
                let Some(file) = file.upgrade() else { return };
                let Some(stream) = standard(&file) else {
                    return;
                };
                let to = {
                    let kept = stream
                        .registration
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner);
                    let Some(to) = kept.clone() else {
                        stream.watching.store(false, Ordering::SeqCst);
                        return;
                    };
                    to
                };
                // Read in this order: a refusal after it counts next time.
                let refused = stream.refused.swap(false, Ordering::SeqCst);
                let ready = stream.ready();
                if ready
                    && (!was || refused)
                    && let Some(processes) = to.processes.upgrade()
                {
                    let owner = processes.file_owner(&file);
                    processes.send_io(owner, to.fd, reason);
                }
                was = ready;
            }
        }));
        if started.is_err() {
            self.watching.store(false, Ordering::SeqCst);
        }
    }
}
/// The host's standard stream behind `file`, if it is one.
pub(crate) fn standard(file: &Arc<dyn FileHandle>) -> Option<&StandardFile> {
    file.as_any()?.downcast_ref::<StandardFile>()
}
impl FileHandle for StandardFile {
    /// The same stream as a new open file description: its own status
    /// flags, from this open's `O_NONBLOCK`, and no `O_ASYNC` yet.
    /// Only the access the stream has opens it (`ENXIO`).
    fn reopen(&self, flags: u32) -> Result<Arc<dyn FileHandle>, Errno> {
        const ENXIO: Errno = Errno(6);
        if flags & 3 != u32::from(self.channel != 0) {
            return Err(ENXIO);
        }
        let file = Self::new(&self.host, self.channel);
        file.flags.store(
            u32::from(self.channel != 0) | flags & crate::events::NONBLOCK,
            Ordering::SeqCst,
        );
        Ok(Arc::new(file))
    }
    fn stdio_channel(&self) -> Option<u32> {
        Some(self.channel)
    }
    fn as_any(&self) -> Option<&dyn std::any::Any> {
        Some(self)
    }
    /// For epoll: standard input is readable as `poll` finds it, and hung
    /// up as well at its end; the output streams are writable. A host stream
    /// has no generation of its own, so the input's counts each time it
    /// becomes ready, and an edge-triggered interest sees that.
    fn readiness(&self) -> Result<(u32, u64, u64), Errno> {
        if self.channel != 0 {
            return Ok((4, 0, 0));
        }
        let mask = match self.host.stdin_state() {
            Some(paludarium_host::StdinState::Waiting) => 0,
            Some(paludarium_host::StdinState::Ended) => 1 | 0x10,
            _ => 1,
        };
        let ready = mask != 0;
        if ready && !self.was_ready.swap(true, Ordering::SeqCst) {
            self.rises.fetch_add(1, Ordering::SeqCst);
        } else if !ready {
            self.was_ready.store(false, Ordering::SeqCst);
        }
        Ok((mask, self.rises.load(Ordering::SeqCst), 0))
    }
    /// A read finding nothing yet is `EAGAIN` rather than a wait on the
    /// host: with `O_NONBLOCK` that is the answer, and without it the
    /// caller ([`wait_for_read`]) waits in the kernel, where a signal ends
    /// the wait (`EINTR`, or a restart with `SA_RESTART`) as on Linux. A
    /// host that cannot tell whether input waits reads at once, waiting on
    /// the host as before. An empty read reads nothing at once, as Linux's
    /// `pipe_read`.
    fn read(&self, b: &mut [u8]) -> Result<usize, Errno> {
        if self.channel == 0 {
            if !b.is_empty() && !self.stdin_ready() {
                self.refused.store(true, Ordering::SeqCst);
                return Err(Errno::EAGAIN);
            }
            self.host.read_stdin(b)
        } else {
            Err(Errno::EBADF)
        }
    }
    fn write(&self, b: &[u8]) -> Result<usize, Errno> {
        if !b.is_empty() && self.would_block() {
            return Err(Errno::EAGAIN);
        }
        match self.channel {
            1 => self.host.write_stdout(b),
            2 => self.host.write_stderr(b),
            _ => Err(Errno::EBADF),
        }
    }
    fn seek(&self, _o: i64, _w: u32) -> Result<u64, Errno> {
        Err(Errno::ESPIPE)
    }
    fn stat(&self) -> Result<FileStat, Errno> {
        Ok(FileStat {
            inode: self.channel as u64,
            size: 0,
            mode: 0o010666,
            uid: 0,
            gid: 0,
            links: 1,
            mtime_ns: 0,
            rdev: 0,
            blocks: None,
            attributes: 0,
        })
    }
    fn truncate(&self, _n: u64) -> Result<(), Errno> {
        Err(Errno::EINVAL)
    }
    fn flock(&self, _o: u32) -> Result<(), Errno> {
        Err(Errno::ENOSYS)
    }
    fn flags(&self) -> u32 {
        self.flags.load(Ordering::SeqCst)
    }
    /// `F_SETFL`, as Linux's `setfl`: the access mode stays, and `O_ASYNC`
    /// only with [`StandardFile::signals`].
    fn set_flags(&self, f: u32) -> Result<(), Errno> {
        let kept = if self.signals() {
            SETFL_FLAGS | crate::fasync::O_ASYNC
        } else {
            SETFL_FLAGS
        };
        let access = u32::from(self.channel != 0);
        self.flags.store(access | (f & kept), Ordering::SeqCst);
        Ok(())
    }
}
#[cfg(test)]
mod files_tests {
    use super::*;
    fn entries(names: &[&str]) -> Vec<paludarium_host::DirectoryEntry> {
        names
            .iter()
            .map(|n| paludarium_host::DirectoryEntry {
                name: n.as_bytes().to_vec(),
                inode: 1,
                kind: 8,
            })
            .collect()
    }
    #[test]
    fn listing_past_its_end_passes_nothing_added_later() {
        let mut listed = Listed::default();
        listed.seek(100, &entries(&["a", "b"]));
        assert_eq!(listed.order.len(), 2);
        // The position did not move, so what comes now was not passed.
        listed.seek(100, &entries(&["a", "b", "c"]));
        assert!(!listed.names.contains(b"c".as_slice()));
        listed.returned(&[&b"c".to_vec()]);
        assert_eq!(listed.position, 101);
        // Not a size to allocate.
        let mut far = Listed::default();
        far.seek(usize::MAX, &entries(&["a"]));
        assert_eq!(far.order.len(), 1);
    }
    #[test]
    fn listing_back_forgets_what_came_after() {
        let mut listed = Listed::default();
        let all = entries(&["a", "b", "c"]);
        listed.returned(&[&b"a".to_vec(), &b"b".to_vec()]);
        listed.seek(1, &all);
        assert_eq!(listed.order, [b"a".to_vec()]);
        assert!(!listed.names.contains(b"b".as_slice()));
        listed.seek(0, &all);
        assert!(listed.names.is_empty());
        // Ahead on a new description passes as many of the listing.
        listed.seek(2, &all);
        assert_eq!(listed.order, [b"a".to_vec(), b"b".to_vec()]);
    }
    fn d(fs: &MemFs, p: &[u8]) -> Descriptor {
        Descriptor {
            file: fs.open(p, 66, 0o600).unwrap(),
            path: p.to_vec(),
            cloexec: false,
            opened: true,
            listed: Arc::default(),
            landlock: crate::landlock::FS,
        }
    }
    #[test]
    fn fd_allocate() {
        let fs = MemFs::new();
        let mut f = Files::default();
        assert_eq!(f.allocate(d(&fs, b"/a"), 3, 1024), Ok(3));
        assert_eq!(f.allocate(d(&fs, b"/b"), 3, 1024), Ok(4));
    }
    #[test]
    fn fd_limit() {
        let fs = MemFs::new();
        let mut f = Files::default();
        assert_eq!(f.allocate(d(&fs, b"/a"), 3, 5), Ok(3));
        assert_eq!(f.allocate(d(&fs, b"/b"), 3, 5), Ok(4));
        assert_eq!(f.allocate(d(&fs, b"/c"), 3, 5), Err(Errno::EMFILE));
        assert_eq!(f.reserve(0), Err(Errno::EMFILE));
        // A pair needs two free descriptors; with one (0), neither is taken.
        let [x, y] = crate::sockets::PipeEnd::pair(0, Arc::clone(&f.readiness))
            .unwrap()
            .map(|end| end as Arc<dyn FileHandle>);
        assert_eq!(
            f.install_pair([x.clone(), y.clone()], false, 1),
            Err(Errno::EMFILE)
        );
        assert!(f.descriptor(0).is_err());
        assert_eq!(f.install_pair([x, y], false, 2), Ok([0, 1]));
    }
    #[test]
    fn a_table_keeps_its_number_where_it_stays_the_same_table() {
        let mut f = Files::default();
        // A CLONE_FILES task shares the table; a fork's child has its own.
        let mut shared = f.for_clone(true, true);
        assert_eq!(shared.table(), f.table());
        let forked = f.for_clone(false, false);
        assert_ne!(forked.table(), f.table());
        // Unsharing a shared table copies it; one used by no other task stays.
        let copy = f.unshared(true);
        assert_ne!(copy.table(), f.table());
        let lone = forked.unshared(true);
        assert_eq!(lone.table(), forked.table());
        assert_eq!(forked.for_exec().table(), forked.table());
        // Only the last task to let go gets the table's number, for its locks.
        let table = f.table();
        assert_eq!(f.release_descriptors().0, None);
        assert_ne!(f.table(), table);
        assert_eq!(shared.release_descriptors().0, Some(table));
    }
    #[test]
    fn exec_takes_the_close_on_exec_descriptors_of_a_table_of_its_own() {
        let fs = MemFs::new();
        let f = Files::default();
        f.fill(0, d(&fs, b"/kept"));
        f.fill(
            1,
            Descriptor {
                cloexec: true,
                ..d(&fs, b"/closed")
            },
        );
        // Shared with another task, the table keeps them open there.
        let shared = f.for_clone(true, true);
        assert!(f.take_close_on_exec().is_empty());
        drop(shared);
        let closed = f.take_close_on_exec();
        assert_eq!(closed.len(), 1);
        assert_eq!(closed[0].path, b"/closed");
        assert!(f.descriptor(1).is_err());
        assert_eq!(f.descriptor(0).unwrap().path, b"/kept");
    }
    #[test]
    fn fd_reservation() {
        let fs = MemFs::new();
        let mut f = Files::default();
        // An open's number is taken but not seen until the file is there.
        assert_eq!(f.reserve(1024), Ok(0));
        assert_eq!(f.allocate(d(&fs, b"/a"), 0, 1024), Ok(1));
        assert_eq!(f.reserve(2), Err(Errno::EMFILE));
        assert!(f.descriptor(0).is_err());
        assert_eq!(f.replace(0, d(&fs, b"/b")).err(), Some(Errno(16)));
        f.fill(0, d(&fs, b"/c"));
        assert_eq!(f.descriptor(0).unwrap().path, b"/c");
        // What was there is handed back to be closed.
        assert_eq!(f.replace(0, d(&fs, b"/b")).unwrap().unwrap().path, b"/c");
        // A failed open gives its number back.
        assert_eq!(f.reserve(1024), Ok(2));
        f.unreserve(2);
        assert_eq!(f.allocate(d(&fs, b"/d"), 0, 1024), Ok(2));
        // A process of its own starts with no reservations.
        assert_eq!(f.reserve(1024), Ok(3));
        assert_eq!(
            f.for_clone(false, false).allocate(d(&fs, b"/e"), 0, 1024),
            Ok(3)
        );
    }
    #[test]
    fn fd_minimum() {
        let fs = MemFs::new();
        assert_eq!(Files::default().allocate(d(&fs, b"/a"), 20, 1024), Ok(20));
    }
    #[test]
    fn fd_bad() {
        assert!(matches!(
            Files::default().descriptor(100),
            Err(Errno::EBADF)
        ));
    }
    #[test]
    fn fd_relative() {
        assert_eq!(
            Files::default().path((-100i32) as u64, b"a".to_vec()),
            Ok(b"/a".to_vec())
        );
    }
    #[test]
    fn fd_absolute_ignores_bad_dir() {
        assert_eq!(
            Files::default().path(999, b"/a".to_vec()),
            Ok(b"/a".to_vec())
        );
    }
    #[test]
    fn fd_empty() {
        assert_eq!(
            Files::default().path((-100i32) as u64, vec![]),
            Err(Errno::ENOENT)
        );
    }
    #[test]
    fn fd_directory_type() {
        let fs = MemFs::new();
        let mut f = Files::default();
        f.allocate(d(&fs, b"/a"), 3, 1024).unwrap();
        assert_eq!(f.path(3, b"b".to_vec()), Err(Errno::ENOTDIR));
    }
    #[test]
    fn fd_shared_offset() {
        let fs = MemFs::new();
        let x = d(&fs, b"/a");
        x.file.write(b"abc").unwrap();
        let y = x.clone();
        y.file.seek(0, 0).unwrap();
        let mut b = [0];
        x.file.read(&mut b).unwrap();
        assert_eq!(y.file.seek(0, 1), Ok(1));
    }
}

/// `open`, `creat` and `openat` of `raw` from `dir`, and `openat2` with its
/// `RESOLVE_*` flags `resolve` ([`resolve_scoped`]).
fn open_at(
    c: &mut Context<'_>,
    dir: u64,
    raw: Vec<u8>,
    flags: u64,
    mode: u32,
    resolve: u64,
) -> Result<u64, Errno> {
    let p = c.files.path(dir, raw.clone())?;
    let flags = u32::try_from(flags).map_err(|_| Errno::EINVAL)?;
    if flags & 3 == 3 {
        return Err(Errno::EINVAL);
    }
    // The walk of `openat2` with `RESOLVE_*` flags, which ends at a path
    // the rest of the open takes as it is.
    let (dir, raw, p) = if resolve == 0 {
        (dir, raw, p)
    } else {
        let p = resolve_scoped(c, dir, &raw, flags, resolve)?;
        ((-100i32) as u64, p.clone(), p)
    };
    // Linux takes the descriptor before it opens, so with none free
    // nothing is opened or created.
    let fd = c.files.reserve(c.group.nofile())?;
    let credentials = &c.process.credentials;
    let opened = match crate::permissions::open(c.files, credentials, dir, &raw, flags) {
        Ok(created) => landlock_before_open(c, &p, flags).and_then(|landlock| {
            let opened = open_path(c, &p, flags, mode).inspect(|_| {
                if let Some(parent) = created {
                    crate::permissions::own(c.files, &c.process.credentials, &p, true, &parent);
                }
            })?;
            let landlock = match landlock {
                Some(rights) => rights,
                None => landlock_after_open(c, &p, flags)?,
            };
            Ok((opened, landlock))
        }),
        Err(error) => Err(error),
    };
    match opened {
        Ok(((file, path), landlock)) => {
            let cloexec = flags & 0x80000 != 0;
            c.files.fill(
                fd,
                Descriptor {
                    file,
                    path,
                    cloexec,
                    opened: true,
                    listed: Arc::default(),
                    landlock,
                },
            );
            Ok(u64::from(fd))
        }
        Err(error) => {
            c.files.unreserve(fd);
            Err(error)
        }
    }
}
const EXDEV: Errno = Errno(18);
const RESOLVE_NO_XDEV: u64 = 0x01;
const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
const RESOLVE_NO_SYMLINKS: u64 = 0x04;
const RESOLVE_BENEATH: u64 = 0x08;
const RESOLVE_IN_ROOT: u64 = 0x10;
const RESOLVE_CACHED: u64 = 0x20;
/// A struct a call takes with its size, as Linux's `copy_struct_from_user`
/// copies one whose first version is `first` bytes: a size below that is
/// `EINVAL` and above a page `E2BIG`. What a later version adds must be zero
/// (`E2BIG`), which `check_zeroed_user` reads a page at a time up to the
/// first byte that is not, before the first version is copied.
pub(super) fn copy_struct(
    c: &Context<'_>,
    addr: u64,
    size: u64,
    first: u64,
) -> Result<Vec<u8>, Errno> {
    const PAGE_SIZE: u64 = 4096;
    const E2BIG: Errno = Errno(7);
    if size < first {
        return Err(Errno::EINVAL);
    }
    if size > PAGE_SIZE {
        return Err(E2BIG);
    }
    let mut at = addr.checked_add(first).ok_or(Errno::EFAULT)?;
    let end = addr.checked_add(size).ok_or(Errno::EFAULT)?;
    while at < end {
        // The page's end, which in the last page is past `u64::MAX`.
        let next = end.min((at | (PAGE_SIZE - 1)).saturating_add(1));
        let mut tail = vec![0; (next - at) as usize];
        c.mem
            .read(GuestAddr(at), &mut tail)
            .map_err(|_| Errno::EFAULT)?;
        if tail.iter().any(|&b| b != 0) {
            return Err(E2BIG);
        }
        at = next;
    }
    let mut copied = vec![0; first as usize];
    c.mem
        .read(GuestAddr(addr), &mut copied)
        .map_err(|_| Errno::EFAULT)?;
    Ok(copied)
}
/// `openat2(dirfd, path, how, size)`, as Linux's `do_sys_openat2` takes
/// `struct open_how` (`flags`, `mode` and `resolve`, 24 bytes in its first
/// version) and `build_open_flags` checks it: unlike `openat`, an unknown
/// flag, a mode without `O_CREAT` or `O_TMPFILE` or with more than the
/// permission bits, and `O_PATH` with other flags than `O_DIRECTORY`,
/// `O_NOFOLLOW` and `O_CLOEXEC` are all `EINVAL`.
fn openat2(c: &mut Context<'_>, a: [u64; 6]) -> Result<u64, Errno> {
    const OPEN_HOW_SIZE_VER0: u64 = 24;
    const O_CREAT: u64 = 0o100;
    const O_TRUNC: u64 = 0o1000;
    const O_DSYNC: u64 = 0o10000;
    const O_DIRECTORY: u64 = 0o200000;
    const O_NOFOLLOW: u64 = 0o400000;
    const O_CLOEXEC: u64 = 0o2000000;
    const O_SYNC: u64 = 0o4000000;
    const O_PATH: u64 = 0o10000000;
    const O_TMPFILE: u64 = 0o20000000;
    // Linux's `VALID_OPEN_FLAGS`: the access mode and every flag from
    // `O_CREAT` to `__O_TMPFILE`.
    const VALID_OPEN_FLAGS: u64 = 0o37777703;
    const VALID_RESOLVE_FLAGS: u64 = 0x3f;
    let how = copy_struct(c, a[2], a[3], OPEN_HOW_SIZE_VER0)?;
    let field = |i: usize| u64::from_le_bytes(how[i * 8..i * 8 + 8].try_into().unwrap_or([0; 8]));
    let (flags, mode, resolve) = (field(0), field(1), field(2));
    let mut flags = flags;
    if flags & !O_CLOEXEC & !VALID_OPEN_FLAGS != 0 || resolve & !VALID_RESOLVE_FLAGS != 0 {
        return Err(Errno::EINVAL);
    }
    if resolve & RESOLVE_BENEATH != 0 && resolve & RESOLVE_IN_ROOT != 0 {
        return Err(Errno::EINVAL);
    }
    if flags & (O_CREAT | O_TMPFILE) != 0 {
        if mode & !0o7777 != 0 {
            return Err(Errno::EINVAL);
        }
    } else if mode != 0 {
        return Err(Errno::EINVAL);
    }
    if flags & (O_DIRECTORY | O_CREAT) == O_DIRECTORY | O_CREAT {
        return Err(Errno::EINVAL);
    }
    if flags & O_TMPFILE != 0 && (flags & O_DIRECTORY == 0 || flags & 3 == 0) {
        return Err(Errno::EINVAL);
    }
    if flags & O_PATH != 0 && flags & !(O_DIRECTORY | O_NOFOLLOW | O_PATH | O_CLOEXEC) != 0 {
        return Err(Errno::EINVAL);
    }
    // `RESOLVE_CACHED` would only look in the dentry cache, so an open that
    // may change a file never tries; anything else this walk always finds.
    if resolve & RESOLVE_CACHED != 0 && flags & (O_TRUNC | O_CREAT | O_TMPFILE) != 0 {
        return Err(Errno::EAGAIN);
    }
    if flags & O_SYNC != 0 {
        flags |= O_DSYNC;
    }
    // With `RESOLVE_*` flags its own walk meets each magic link, which they
    // may refuse; without, the path is taken as `openat` takes it.
    let raw = if resolve & !RESOLVE_CACHED == 0 {
        path(c, a[1])?
    } else {
        string(c, a[1])?
    };
    open_at(c, a[0], raw, flags, mode as u32, resolve & !RESOLVE_CACHED)
}
/// The mount `path` is on, for `RESOLVE_NO_XDEV`: procfs, devtmpfs and
/// devpts, which Linux mounts at `/proc`, `/dev` and `/dev/pts`, or the
/// guest's own mounts ([`device`]).
fn mount_of(c: &Context<'_>, path: &[u8]) -> u64 {
    let under = |root: &[u8]| {
        path.strip_prefix(root)
            .is_some_and(|rest| rest.is_empty() || rest[0] == b'/')
    };
    if under(b"/proc") {
        u64::MAX
    } else if under(b"/dev/pts") {
        u64::MAX - 1
    } else if under(b"/dev") {
        u64::MAX - 2
    } else {
        device(c, path)
    }
}
/// The path `openat2` opens for `raw` from `dir` with the `RESOLVE_*` flags
/// `resolve`, as Linux's walk with them (`LOOKUP_NO_XDEV` and the rest)
/// goes one name at a time, at most 40 symbolic links:
/// - `RESOLVE_NO_SYMLINKS` follows no link (`ELOOP`), and
///   `RESOLVE_NO_MAGICLINKS` none in `/proc/self/fd` or `exe` and `cwd`
///   (`ELOOP`, `nd_jump_link`).
/// - `RESOLVE_NO_XDEV` crosses no mount (`EXDEV`), as a name, `..`, a link
///   to an absolute path or a magic link may.
/// - `RESOLVE_BENEATH` stays in `dir`: an absolute path or link, `..` out
///   of it and a magic link are `EXDEV`. `RESOLVE_IN_ROOT` takes `dir` as
///   the root, where those stay, but for a magic link (`EXDEV`).
///
/// The last name is followed as `open` follows it (not with `O_NOFOLLOW`
/// or `O_CREAT | O_EXCL`); a magic link there is left for the open to take
/// ([`reopen`]).
fn resolve_scoped(
    c: &Context<'_>,
    dir: u64,
    raw: &[u8],
    flags: u32,
    resolve: u64,
) -> Result<Vec<u8>, Errno> {
    const O_NOFOLLOW: u32 = 0o400000;
    let join = |parts: &[Vec<u8>]| -> Vec<u8> {
        if parts.is_empty() {
            return b"/".to_vec();
        }
        parts.iter().flat_map(|p| [&b"/"[..], p].concat()).collect()
    };
    let split = |p: &[u8]| -> Vec<Vec<u8>> {
        p.split(|&b| b == b'/')
            .filter(|p| !p.is_empty() && *p != b".")
            .map(<[u8]>::to_vec)
            .collect()
    };
    let scoped = resolve & (RESOLVE_BENEATH | RESOLVE_IN_ROOT) != 0;
    let start = paludarium_vfs::normalize_path(&c.files.path(dir, b".".to_vec())?)?;
    let root = if scoped { split(&start) } else { Vec::new() };
    let mut parts = if raw.first() == Some(&b'/') {
        if resolve & RESOLVE_BENEATH != 0 {
            return Err(EXDEV);
        }
        root.clone()
    } else {
        split(&start)
    };
    // `O_CREAT | O_EXCL` follows no last link either, as `build_open_flags`
    // walks with `O_NOFOLLOW` then.
    let follow_last = flags & O_NOFOLLOW == 0 && flags & 0o300 != 0o300;
    let trailing_slash = raw.last() == Some(&b'/');
    let mut pending: Vec<Vec<u8>> = raw
        .split(|&b| b == b'/')
        .rev()
        .map(<[u8]>::to_vec)
        .collect();
    let mut links = 0;
    while let Some(part) = pending.pop() {
        let here = join(&parts);
        match &part[..] {
            b"" | b"." => continue,
            b".." => {
                if parts.len() <= root.len() {
                    if resolve & RESOLVE_BENEATH != 0 {
                        return Err(EXDEV);
                    }
                    continue;
                }
                let parent = join(&parts[..parts.len() - 1]);
                if resolve & RESOLVE_NO_XDEV != 0 && mount_of(c, &parent) != mount_of(c, &here) {
                    return Err(EXDEV);
                }
                parts.pop();
                continue;
            }
            _ => {}
        }
        parts.push(part);
        let candidate = join(&parts);
        if resolve & RESOLVE_NO_XDEV != 0 && mount_of(c, &candidate) != mount_of(c, &here) {
            return Err(EXDEV);
        }
        let last = pending.iter().all(|p| p.is_empty());
        if last && !follow_last && !trailing_slash {
            break;
        }
        let magic =
            matches!(
                crate::proc::own_entry(&candidate, c.process.pid),
                Some(
                    crate::proc::OwnEntry::Descriptor(_)
                        | crate::proc::OwnEntry::Exe
                        | crate::proc::OwnEntry::Cwd
                )
            ) || crate::proc::task_path(&candidate, c.process.pid, c.tid).is_some_and(|path| {
                matches!(
                    path.entry,
                    crate::proc::TaskEntry::Exe | crate::proc::TaskEntry::Cwd
                )
            });
        if magic {
            // The link of a descriptor that is not open is not there.
            if let Some(crate::proc::OwnEntry::Descriptor(n)) =
                crate::proc::own_entry(&candidate, c.process.pid)
            {
                c.files
                    .descriptor(u64::from(n))
                    .map_err(|_| Errno::ENOENT)?;
            }
            if resolve & (RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS) != 0 {
                return Err(Errno(40)); // ELOOP
            }
            let target = match followed(c, &candidate, true)? {
                Some(Followed::Path { path, .. }) => Some(path),
                Some(Followed::File(_)) => None,
                None => own_link_target(c, &candidate),
            };
            if resolve & RESOLVE_NO_XDEV != 0
                && target
                    .as_deref()
                    .is_none_or(|target| mount_of(c, target) != mount_of(c, &here))
            {
                return Err(EXDEV);
            }
            if scoped {
                return Err(EXDEV);
            }
            if last {
                break;
            }
            parts = split(&target.ok_or(Errno::ENOTDIR)?);
            continue;
        }
        let Some(link) = LinkPath::of(c, &candidate)? else {
            continue;
        };
        if resolve & RESOLVE_NO_SYMLINKS != 0 {
            return Err(Errno(40)); // ELOOP
        }
        links += 1;
        if links > 40 {
            return Err(Errno(40));
        }
        let target = link.target(c)?;
        parts.pop();
        if target.first() == Some(&b'/') {
            if resolve & RESOLVE_BENEATH != 0 {
                return Err(EXDEV);
            }
            if resolve & RESOLVE_NO_XDEV != 0
                && mount_of(c, &join(&parts)) != mount_of(c, &join(&root))
            {
                return Err(EXDEV);
            }
            parts = root.clone();
        }
        pending.extend(target.split(|&b| b == b'/').rev().map(<[u8]>::to_vec));
    }
    let mut p = join(&parts);
    if trailing_slash {
        p.push(b'/');
    }
    Ok(p)
}
/// Where this process's `exe` or `cwd` link at `path` leads, or another
/// task's.
fn own_link_target(c: &Context<'_>, path: &[u8]) -> Option<Vec<u8>> {
    if let Some(entry) = crate::proc::own_entry(path, c.process.pid) {
        return own_link(c, entry);
    }
    let task_path = crate::proc::task_path(path, c.process.pid, c.tid)?;
    let task = tasks::find(c, &task_path).ok()?;
    tasks::link(&task, task_path.entry)?.ok()
}
/// The file that opening guest path `p` gives, and the path its descriptor
/// records: the generated files, a link in `/proc/self/fd` opened again,
/// or the filesystem's file.
fn open_path(
    c: &mut Context<'_>,
    p: &[u8],
    flags: u32,
    mode: u32,
) -> Result<(Arc<dyn FileHandle>, Vec<u8>), Errno> {
    const O_NOFOLLOW: u32 = 0o400000;
    if let Some(target) = crate::devices::through_link(p) {
        return open_path(c, &target, flags, mode);
    }
    if flags & (O_PATH | O_NOFOLLOW) == O_PATH | O_NOFOLLOW
        && let Some(link) = LinkPath::of(c, p)?
    {
        return Ok((Arc::new(link), p.to_vec()));
    }
    // `/dev/tty`: the controlling terminal, when it is one of the
    // emulator's pseudo-terminals.
    if p == b"/dev/tty"
        && let Some(file) = crate::pty::open_controlling(c, flags)
    {
        return Ok((file?, p.to_vec()));
    }
    let file: Arc<dyn FileHandle> = if let Some(entry) = crate::devices::entry(p) {
        const O_DIRECTORY: u32 = 0o200000;
        match entry {
            crate::devices::Entry::Pts if flags & 3 != 0 => return Err(Errno::EISDIR),
            crate::devices::Entry::Pts => {
                Arc::new(crate::proc::OwnDirectory::new(crate::pty::directory_stat()))
            }
            crate::devices::Entry::Slave(None) => return Err(Errno::ENOENT),
            crate::devices::Entry::Mqueue => crate::mqueue::MountedRoot::open(c, flags)?,
            crate::devices::Entry::Queue => {
                let name = crate::mqueue::mounted_name(p).ok_or(Errno::ENOENT)?;
                crate::mqueue::open_mounted(c, name, flags, mode)?
            }
            crate::devices::Entry::Ptmx { .. } | crate::devices::Entry::Slave(_)
                if flags & O_DIRECTORY != 0 =>
            {
                return Err(Errno::ENOTDIR);
            }
            crate::devices::Entry::Ptmx { .. } => crate::pty::open_master(c, flags)?,
            crate::devices::Entry::Slave(Some(n)) => crate::pty::open_named(c, n, flags)?,
            // A directory opens only for reading, a device not as one.
            crate::devices::Entry::Directory if flags & 3 != 0 => return Err(Errno::EISDIR),
            crate::devices::Entry::Directory => Arc::new(crate::proc::OwnDirectory::new(
                crate::devices::directory_stat(),
            )),
            crate::devices::Entry::Device(_) if flags & O_DIRECTORY != 0 => {
                return Err(Errno::ENOTDIR);
            }
            crate::devices::Entry::Device(kind) => Arc::new(crate::devices::Device::new(
                kind,
                flags,
                Some(Arc::clone(c.shared_host)),
            )),
            crate::devices::Entry::Link(_) if flags & O_NOFOLLOW != 0 => {
                return Err(Errno(40)); // ELOOP
            }
            crate::devices::Entry::Link(target) => return open_path(c, target, flags, mode),
        }
    } else if let Some(mountinfo) = crate::proc::mount_table(p) {
        let content = crate::proc::render(&c.files.fs.mounts(), mountinfo);
        Arc::new(crate::proc::GeneratedFile::open(content, flags))
    } else if tasks::is_root(p) {
        if flags & 3 != 0 {
            return Err(Errno::EISDIR);
        }
        Arc::new(crate::proc::OwnDirectory::new(crate::proc::directory_stat()))
    } else if let Some(path) = crate::proc::task_path(p, c.process.pid, c.tid) {
        let task = tasks::find(c, &path)?;
        tasks::check(c, &task, path.entry)?;
        // A link of `ns` leads to its namespace's file, which it opens as
        // Linux's `proc_ns_get_link` does.
        if let crate::proc::TaskEntry::Namespace(entry) = path.entry {
            const O_DIRECTORY: u32 = 0o200000;
            let namespace = tasks::namespace(&task, entry).ok_or(Errno::ENOENT)?;
            if flags & O_NOFOLLOW != 0 && flags & O_PATH == 0 {
                return Err(Errno(40)); // ELOOP
            }
            if flags & 0o300 == 0o300 {
                return Err(Errno::EEXIST);
            }
            if flags & O_DIRECTORY != 0 {
                return Err(Errno::ENOTDIR);
            }
            let file = crate::namespaces::NamespaceFile::new(namespace, flags);
            return Ok((Arc::new(file), p.to_vec()));
        }
        // The user namespace's files take one write, as Linux's
        // `proc_uid_map_write` and `proc_setgroups_write`: opened for writing
        // by whom their mode lets, and `setgroups` only with CAP_SYS_ADMIN
        // in the namespace (`proc_setgroups_open`'s `EACCES`).
        if let crate::proc::TaskEntry::IdMap(_) | crate::proc::TaskEntry::Setgroups = path.entry {
            let content =
                tasks::content(&task, path.entry, &c.process.credentials.user).unwrap_or_default();
            let creds = &c.process.credentials;
            let user = task.user();
            if flags & 3 != 0 {
                let (stat, ..) = tasks::stat(c, p, &task, path.entry, false)?;
                crate::permissions::permission(creds, &stat, crate::permissions::MAY_WRITE)?;
                if path.entry == crate::proc::TaskEntry::Setgroups
                    && !creds.capable_in(crate::credentials::CAP_SYS_ADMIN, &user)
                {
                    return Err(Errno::EACCES);
                }
            }
            let ids = match path.entry {
                crate::proc::TaskEntry::IdMap(ids) => Some(ids),
                _ => None,
            };
            let file = crate::users::MapFile::open(user, ids, content, creds.clone(), flags);
            return Ok((Arc::new(file), p.to_vec()));
        }
        if let Some(content) = tasks::content(&task, path.entry, &c.process.credentials.user) {
            Arc::new(crate::proc::GeneratedFile::open(content, flags))
        } else if let Some(target) = tasks::link(&task, path.entry) {
            // `exe`, `cwd` and `thread-self` are links, which O_NOFOLLOW
            // does not follow; `thread-self`'s is relative to /proc.
            let mut target = target?;
            if flags & O_NOFOLLOW != 0 && flags & O_PATH == 0 {
                return Err(Errno(40)); // ELOOP
            }
            if path.entry == crate::proc::TaskEntry::ThreadLink {
                target = [&b"/proc/"[..], &target].concat();
            }
            return open_path(c, &target, flags, mode);
        } else {
            let (stat, ..) = tasks::stat(c, p, &task, path.entry, false)?;
            if flags & 3 != 0 {
                return Err(Errno::EISDIR);
            }
            Arc::new(crate::proc::OwnDirectory::new(stat))
        }
    } else if let Some(entry) = crate::sysctl::entry(p) {
        crate::sysctl::open(c, entry, flags)?
    } else if let Some(entry) = crate::proc::system_entry(p) {
        Arc::new(crate::proc::GeneratedFile::open(
            system_file(c, entry),
            flags,
        ))
    } else if let Some(entry) = crate::proc::own_entry(p, c.process.pid) {
        if let Some(content) = own_file(c, entry) {
            return Ok((
                Arc::new(crate::proc::GeneratedFile::open(content, flags)),
                p.to_vec(),
            ));
        }
        // `exe` and `cwd` are links, which O_NOFOLLOW does not follow.
        if let Some(target) = own_link(c, entry) {
            if flags & O_NOFOLLOW != 0 && flags & O_PATH == 0 {
                return Err(Errno(40)); // ELOOP
            }
            return open_path(c, &target, flags, mode);
        }
        match entry {
            // `/proc/self` is a link, which O_NOFOLLOW does not follow.
            crate::proc::OwnEntry::Directory if p == b"/proc/self" && flags & O_NOFOLLOW != 0 => {
                return Err(Errno(40)); // ELOOP
            }
            crate::proc::OwnEntry::Directory => {
                Arc::new(crate::proc::OwnDirectory::new(crate::proc::directory_stat()))
            }
            crate::proc::OwnEntry::Descriptors => Arc::new(crate::proc::OwnDirectory::new(
                crate::proc::descriptors_stat(),
            )),
            crate::proc::OwnEntry::DescriptorInfos => {
                Arc::new(crate::proc::OwnDirectory::new(crate::proc::directory_stat()))
            }
            // Opened above while the descriptor is open.
            crate::proc::OwnEntry::DescriptorInfo(_) => return Err(Errno::ENOENT),
            crate::proc::OwnEntry::Status => {
                Arc::new(crate::proc::GeneratedFile::open(status(c), flags))
            }
            // Opened above.
            crate::proc::OwnEntry::Stat
            | crate::proc::OwnEntry::Cmdline
            | crate::proc::OwnEntry::Environ
            | crate::proc::OwnEntry::Comm
            | crate::proc::OwnEntry::Exe
            | crate::proc::OwnEntry::Cwd => return Err(Errno::ENOENT),
            crate::proc::OwnEntry::Maps => Arc::new(crate::proc::MapsFile::open(
                c.mem.view(),
                c.group.start_stack(),
                flags,
            )),
            crate::proc::OwnEntry::Smaps => Arc::new(crate::proc::MapsFile::open_as(
                c.mem.view(),
                c.group.start_stack(),
                flags,
                true,
            )),
            crate::proc::OwnEntry::Descriptor(n) => {
                // A link for a descriptor that is not open is not there
                // (ENOENT), whatever the flags. One that is, is a symbolic
                // link that names a file there is: O_NOFOLLOW does not follow
                // it (ELOOP) but with O_PATH, and O_CREAT | O_EXCL finds it
                // there (EEXIST).
                c.files
                    .descriptor(u64::from(n))
                    .map_err(|_| Errno::ENOENT)?;
                if flags & 0o300 == 0o300 {
                    return Err(Errno::EEXIST);
                }
                if flags & O_NOFOLLOW != 0 && flags & O_PATH == 0 {
                    return Err(Errno(40)); // ELOOP
                }
                return reopen(c, n, flags, mode);
            }
        }
    } else {
        // A FIFO opens as the pipe every opener of the node shares, except
        // with O_PATH, which takes only its path.
        if flags & O_PATH == 0
            && let Ok(node) = c.files.fs.metadata(p, flags & O_NOFOLLOW == 0)
            && node.mode & 0o170000 == 0o010000
        {
            const O_DIRECTORY: u32 = 0o200000;
            if flags & 0o300 == 0o300 {
                return Err(Errno::EEXIST);
            }
            if flags & O_DIRECTORY != 0 {
                return Err(Errno::ENOTDIR);
            }
            let key = (device(c, p), node.inode);
            return Ok((crate::fifo::open(c, p, key, &node, flags)?, p.to_vec()));
        }
        let file = c.files.fs.open(p, flags, mode & !c.files.umask())?;
        const O_TRUNC: u32 = 0o1000;
        if flags & O_TRUNC != 0 && flags & O_PATH == 0 {
            crate::permissions::remove_set_ids(&c.process.credentials, &*file);
        }
        file
    };
    Ok((file, p.to_vec()))
}
/// Opening `/proc/self/fd/<n>`: a new handle on the file descriptor `n`
/// holds, as Linux opens the link's file again. A file with a path is opened
/// again by it while the path still names that file, and a removed one of
/// the guest's own filesystem through its handle ([`FileHandle::reopen`]); a
/// memfd gets a new handle on its file; a pipe or the standard streams give
/// the same handle for the access it has, and a pidfd another description
/// of its process, as root opens it. The rest cannot be opened again: a
/// socket gives ENXIO, as on Linux, and so do the anonymous inodes
/// (eventfd, epoll, timerfd), whose `open` is Linux's `no_open`.
fn reopen(
    c: &mut Context<'_>,
    n: u32,
    flags: u32,
    mode: u32,
) -> Result<(Arc<dyn FileHandle>, Vec<u8>), Errno> {
    const ENXIO: Errno = Errno(6);
    let d = c
        .files
        .descriptor(u64::from(n))
        .map_err(|_| Errno::ENOENT)?;
    // The descriptor of a symbolic link itself: following its link reaches
    // that symbolic link, which an open does not follow again (ELOOP).
    if d.file.as_any().is_some_and(|v| v.is::<LinkPath>()) {
        return Err(Errno(40));
    }
    if let Some(memfd) = d
        .file
        .as_any()
        .and_then(|v| v.downcast_ref::<crate::memfd::Memfd>())
    {
        // An open for writing counts as a writer, as through
        // `do_dentry_open`, unlike `memfd_create`'s own descriptor.
        let file = crate::page_cache::CoherentFile::with_device(
            memfd.reopen(flags)?,
            Arc::clone(&c.files.caches),
            crate::memfd::device(memfd),
        )
        .writing(flags)?;
        return Ok((Arc::new(file), Vec::new()));
    }
    let is_pidfd = d
        .file
        .as_any()
        .is_some_and(|v| v.is::<crate::processes::PidFd>());
    let stat = d.file.stat()?;
    // `may_open` of the inode the link leads to.
    if !matches!(stat.mode & 0o170000, 0o040000 | 0o120000) {
        attributes::may_open(&stat, flags)?;
    }
    // A FIFO a path opened: its node opened again, at the same dentry.
    if stat.mode & 0o170000 == 0o010000
        && let Some(result) = crate::fifo::reopen(c, &d.file, &stat, flags)
    {
        return Ok((result?, d.path.clone()));
    }
    match stat.mode & 0o170000 {
        // A pipe or a standard stream: a description of its own, which
        // checks the access it is opened with.
        0o010000 if d.path.is_empty() => Ok((d.file.reopen(flags)?, Vec::new())),
        // A pidfd: another description of the same process.
        _ if d.path.is_empty() && is_pidfd => Ok((d.file.reopen(flags)?, Vec::new())),
        // A queue `mq_open` gave: its inode, opened again.
        _ if crate::mqueue::is_queue(&*d.file) => {
            Ok((crate::mqueue::reopened(c, &d.file, flags)?, d.path.clone()))
        }
        _ if d.path.is_empty() => Err(ENXIO),
        _ if generated(&d.path) => open_path(c, &d.path.clone(), flags, mode),
        _ => match current_path(c.files, &d, stat.inode) {
            Some(path) => open_path(c, &path, flags, mode),
            None => Ok((d.file.reopen(flags)?, d.path.clone())),
        },
    }
}
/// Whether `path` is one of the generated files, which no filesystem holds.
/// The resolved path an open of `p` reaches: its last component followed
/// unless `O_NOFOLLOW`, and kept when it does not exist, for the file the
/// open would make. `None` when its directory does not exist.
fn landlock_target(c: &Context<'_>, p: &[u8], follow: bool) -> Option<Vec<u8>> {
    // /proc and /dev are named as given: no name there is a mounted file.
    if let Ok(normal) = paludarium_vfs::normalize_path(p)
        && (normal == b"/proc" || generated(&normal))
    {
        return Some(normal);
    }
    if follow && let Some(path) = resolved(c.files, p) {
        return Some(path);
    }
    let normal = paludarium_vfs::normalize_path(p).ok()?;
    let at = normal.iter().rposition(|&b| b == b'/')?;
    let dir = resolved(c.files, if at == 0 { b"/" } else { &normal[..at] })?;
    let mut path = dir;
    if path != b"/" {
        path.push(b'/');
    }
    path.extend_from_slice(&normal[at + 1..]);
    Some(path)
}
/// The status of the file at the resolved `path`, `/proc` and `/dev` too.
fn landlock_stat(c: &Context<'_>, path: &[u8]) -> Option<FileStat> {
    match generated_stat(c, path, false) {
        Ok(Some((stat, _, _))) => Some(stat),
        _ => c.files.fs.metadata(path, false).ok(),
    }
}
/// Landlock's checks of an open of `p` with `flags` before it happens: of
/// opening the file there (and truncating it with `O_TRUNC`), which gives
/// the rights its description keeps, or of making a regular file in its
/// directory, in which case the open's own check waits for the file
/// (`None`, [`landlock_after_open`]). `O_PATH` checks nothing.
fn landlock_before_open(c: &Context<'_>, p: &[u8], flags: u32) -> Result<Option<u64>, Errno> {
    if flags & O_PATH != 0 || c.process.credentials.landlock == Default::default() {
        return Ok(Some(crate::landlock::FS));
    }
    let Some(target) = landlock_target(c, p, flags & 0x20000 == 0) else {
        return Ok(Some(crate::landlock::FS));
    };
    match landlock_stat(c, &target) {
        // O_CREAT | O_EXCL on a file that is there is EEXIST first.
        Some(_) if flags & 192 == 192 => Ok(None),
        Some(stat) => {
            let mode = flags & 3;
            let rights = crate::landlock::open(c, &target, &stat, mode != 1, mode != 0, false)?;
            if flags & 512 != 0
                && stat.mode & 0o170000 == 0o100000
                && rights & crate::landlock::TRUNCATE == 0
            {
                return Err(Errno::EACCES);
            }
            Ok(Some(rights))
        }
        None if flags & 64 != 0 => {
            let dir = match target.iter().rposition(|&b| b == b'/') {
                Some(0) | None => b"/".to_vec(),
                Some(at) => target[..at].to_vec(),
            };
            crate::landlock::check(c, &dir, crate::landlock::MAKE_REG)?;
            Ok(None)
        }
        None => Ok(Some(crate::landlock::FS)),
    }
}
/// Landlock's check of making or removing the name `p`: `request` on the
/// directory that holds it. Nothing when the thread has no domain.
pub(crate) fn landlock_name(c: &Context<'_>, p: &[u8], request: u64) -> Result<(), Errno> {
    if c.process.credentials.landlock == Default::default() {
        return Ok(());
    }
    match landlock_target(c, p, false) {
        Some(target) => crate::landlock::check(c, crate::landlock::parent(&target), request),
        None => Ok(()),
    }
}
/// The resolved path of the name `p` itself, and whether a file is there.
fn landlock_named(c: &Context<'_>, p: &[u8]) -> Option<(Vec<u8>, Option<FileStat>)> {
    let target = landlock_target(c, p, false)?;
    let stat = landlock_stat(c, &target);
    Some((target, stat))
}
/// Landlock's check of an open that made the file at `p`.
fn landlock_after_open(c: &Context<'_>, p: &[u8], flags: u32) -> Result<u64, Errno> {
    let Some(target) = landlock_target(c, p, flags & 0x20000 == 0) else {
        return Ok(crate::landlock::FS);
    };
    let Some(stat) = landlock_stat(c, &target) else {
        return Ok(crate::landlock::FS);
    };
    let mode = flags & 3;
    crate::landlock::open(c, &target, &stat, mode != 1, mode != 0, false)
}
/// The device and inode `stat` gives the file at the resolved `path`, which
/// Landlock's rules name ([`crate::landlock`]); `None` when there is none.
pub(crate) fn identity(c: &Context<'_>, path: &[u8]) -> Option<crate::landlock::Object> {
    if let Ok(Some((stat, device, _))) = generated_stat(c, path, false) {
        return Some((device, stat.inode));
    }
    file_identity(c.files, path)
}
/// [`identity`] of a file outside `/proc` and `/dev`, for a caller with
/// only the files.
pub(crate) fn file_identity(files: &Files, path: &[u8]) -> Option<crate::landlock::Object> {
    let stat = files.fs.metadata(path, false).ok()?;
    Some((
        crate::page_cache::mount_device(&files.fs.mounts(), path),
        stat.inode,
    ))
}
/// The object of a Landlock rule's `parent_fd`, and whether it is a
/// directory: the file a descriptor (`O_PATH` too) holds. A ruleset, a pipe,
/// a socket or another file of no path is `EBADFD`, as Linux refuses
/// internal filesystems.
pub(crate) fn rule_object(
    c: &Context<'_>,
    fd: i32,
) -> Result<(crate::landlock::Object, bool), Errno> {
    let d = c.files.descriptor(u64::from(fd as u32))?;
    if d.path.is_empty() {
        return Err(Errno(77));
    }
    let stat = d.file.stat()?;
    let directory = stat.mode & 0o170000 == 0o040000;
    // The file the descriptor holds, as `fstat` names it, wherever it is
    // now; a file of /proc or /dev by its path, which nothing renames.
    let object = if generated(&d.path) {
        identity(c, &d.path).ok_or(Errno(77))?
    } else {
        (descriptor_device(c, &d), stat.inode)
    };
    Ok((object, directory))
}
pub(crate) fn generated(path: &[u8]) -> bool {
    crate::devices::entry(path).is_some() || path.starts_with(b"/proc/")
}
/// `path` as `realpath` gives it: absolute, with `.`, `..` and every
/// symbolic link resolved one component at a time (at most 40 links, as
/// Linux follows), or `None` when a component is missing.
pub(crate) fn resolved(files: &Files, path: &[u8]) -> Option<Vec<u8>> {
    resolved_in(&*files.fs, path)
}
/// [`resolved`] in the file system `fs`.
pub(crate) fn resolved_in(fs: &dyn HostFs, path: &[u8]) -> Option<Vec<u8>> {
    const SYMLINK: u32 = 0o120000;
    let mut pending: Vec<Vec<u8>> = path
        .split(|&b| b == b'/')
        .rev()
        .map(<[u8]>::to_vec)
        .collect();
    let mut parts: Vec<Vec<u8>> = Vec::new();
    let mut links = 0;
    let join = |parts: &[Vec<u8>]| -> Vec<u8> {
        let joined = parts
            .iter()
            .flat_map(|p| [&b"/"[..], p].concat())
            .collect::<Vec<_>>();
        if joined.is_empty() {
            b"/".to_vec()
        } else {
            joined
        }
    };
    while let Some(part) = pending.pop() {
        match &part[..] {
            b"" | b"." => continue,
            b".." => {
                parts.pop();
                continue;
            }
            _ => {}
        }
        parts.push(part);
        let candidate = join(&parts);
        if fs.metadata(&candidate, false).ok()?.mode & 0o170000 == SYMLINK {
            links += 1;
            if links > 40 {
                return None;
            }
            let target = fs.readlink(&candidate).ok()?;
            parts.pop();
            if target.first() == Some(&b'/') {
                parts.clear();
            }
            pending.extend(target.split(|&b| b == b'/').rev().map(<[u8]>::to_vec));
        }
    }
    Some(join(&parts))
}
/// The path that still names the file of `d` (its recorded path resolved),
/// or `None` once nothing does.
fn current_path(files: &Files, d: &Descriptor, inode: u64) -> Option<Vec<u8>> {
    let path = resolved(files, &d.path)?;
    files
        .fs
        .metadata(&path, false)
        .is_ok_and(|s| s.inode == inode)
        .then_some(path)
}
/// Where a call that follows a link in `/proc/self/fd` (or one of `/dev`'s
/// links to it) gets to: Linux's link is a "magic link", which leads to the
/// descriptor's file itself, as `open` takes it ([`reopen`]).
pub(crate) enum Followed {
    /// A file a path still names, or a symbolic link itself, which an
    /// `O_PATH | O_NOFOLLOW` descriptor holds and which is not followed
    /// again (`follow` false).
    Path { path: Vec<u8>, follow: bool },
    /// A file no path names: a removed one, a memfd, a pipe or a socket,
    /// which the call reaches through the descriptor's own file.
    File(Descriptor),
}
/// What a call that follows path `p` (with `follow`) reaches, when `p` is a
/// link in the `fd` directory of process `pid`: `None` for any other path,
/// or when the call does not follow, and `ENOENT` for a descriptor that is
/// not open, whose link is not there.
pub(crate) fn through_descriptor(
    files: &Files,
    pid: u32,
    p: &[u8],
    follow: bool,
) -> Result<Option<Followed>, Errno> {
    if !follow {
        return Ok(None);
    }
    let p = crate::devices::through_link(p).unwrap_or_else(|| p.to_vec());
    let p = match crate::devices::entry(&p) {
        Some(crate::devices::Entry::Link(target)) => target.to_vec(),
        _ => p,
    };
    let Some(crate::proc::OwnEntry::Descriptor(n)) = crate::proc::own_entry(&p, pid) else {
        return Ok(None);
    };
    let d = files.descriptor(u64::from(n)).map_err(|_| Errno::ENOENT)?;
    descriptor_followed(files, d).map(Some)
}
/// Where the file descriptor `d` holds is reached: by the path that still
/// names it, or through the descriptor itself.
fn descriptor_followed(files: &Files, d: Descriptor) -> Result<Followed, Errno> {
    let any = d.file.as_any();
    if any.is_some_and(|v| v.is::<LinkPath>()) {
        return Ok(Followed::Path {
            path: opened_path(&d),
            follow: false,
        });
    }
    if d.path.is_empty() || any.is_some_and(|v| v.is::<crate::memfd::Memfd>()) {
        return Ok(Followed::File(d));
    }
    if generated(&d.path) {
        return Ok(Followed::Path {
            path: d.path.clone(),
            follow: true,
        });
    }
    let inode = d.file.stat()?.inode;
    Ok(match current_path(files, &d, inode) {
        Some(path) => Followed::Path {
            path,
            follow: false,
        },
        None => Followed::File(d),
    })
}
/// The program `execveat(dir, raw, .., flags)` runs: a file a path names
/// (`dir` and `raw` taken as Linux's `do_open_execat` takes them, a link in
/// `/proc/self/fd` followed to the descriptor's file), or one no path names,
/// a memfd or a removed file, which runs from its descriptor. An empty `raw`
/// takes the file `dir` holds with `AT_EMPTY_PATH` (ENOENT without), and
/// `AT_SYMLINK_NOFOLLOW` refuses a symbolic link (ELOOP), as `may_open`
/// refuses the one an `O_PATH | O_NOFOLLOW` descriptor holds.
pub(crate) enum Program {
    Path(Vec<u8>),
    File {
        file: Arc<dyn FileHandle>,
        /// What `/proc/self/exe` reads.
        name: Vec<u8>,
        /// The name of its directory entry, which names the process.
        entry: Vec<u8>,
        /// The path a removed file had, whose directories Landlock still
        /// walks from its dentry; none for a memfd.
        removed: Option<Vec<u8>>,
    },
}
pub(crate) fn exec_program(
    files: &Files,
    pid: u32,
    dir: u64,
    raw: &[u8],
    flags: u64,
) -> Result<Program, Errno> {
    const ELOOP: Errno = Errno(40);
    let symlink = |path: &[u8]| {
        files
            .fs
            .metadata(path, false)
            .is_ok_and(|s| s.mode & 0o170000 == 0o120000)
    };
    let target = if raw.is_empty() {
        if flags & AT_EMPTY_PATH == 0 {
            return Err(Errno::ENOENT);
        }
        if dir as i32 == -100 {
            return Ok(Program::Path(files.path(dir, b".".to_vec())?));
        }
        descriptor_followed(files, files.descriptor(dir)?)?
    } else {
        let path = files.path(dir, raw.to_vec())?;
        let follow = flags & AT_SYMLINK_NOFOLLOW == 0;
        if !follow && symlink(&path) {
            return Err(ELOOP);
        }
        match through_descriptor(files, pid, &path, follow)? {
            Some(target) => target,
            None => return Ok(Program::Path(path)),
        }
    };
    Ok(match target {
        Followed::Path {
            path,
            follow: false,
        } if symlink(&path) => return Err(ELOOP),
        Followed::Path { path, .. } => Program::Path(path),
        Followed::File(d) => {
            let memfd = d
                .file
                .as_any()
                .and_then(|v| v.downcast_ref::<crate::memfd::Memfd>());
            let (name, entry) = match memfd {
                Some(memfd) => {
                    let name = memfd.link_target();
                    let entry = name
                        .strip_prefix(b"/")
                        .and_then(|n| n.strip_suffix(b" (deleted)"))
                        .unwrap_or(&name)
                        .to_vec();
                    (name, entry)
                }
                None => (
                    [&d.path[..], b" (deleted)"].concat(),
                    d.path
                        .rsplit(|&b| b == b'/')
                        .next()
                        .unwrap_or(&d.path)
                        .to_vec(),
                ),
            };
            Program::File {
                removed: memfd.is_none().then(|| d.path.clone()),
                file: d.file,
                name,
                entry,
            }
        }
    })
}
/// [`through_descriptor`] for this thread's process.
fn followed(c: &Context<'_>, p: &[u8], follow: bool) -> Result<Option<Followed>, Errno> {
    through_descriptor(c.files, c.process.pid, p, follow)
}
/// The queue's name a path in `/dev/mqueue` gives, where the `mqueue`
/// filesystem is mounted ([`crate::mqueue::mounted_name`]).
fn queue_name(p: &[u8]) -> Option<Vec<u8>> {
    paludarium_vfs::normalize_path(p)
        .ok()
        .and_then(|p| crate::mqueue::mounted_name(&p).map(<[u8]>::to_vec))
}
/// Whether `p` names `/dev/mqueue` itself, the `mqueue` root, which a new
/// name there finds in use (`EEXIST`).
fn queue_root(p: &[u8]) -> bool {
    paludarium_vfs::normalize_path(p).is_ok_and(|p| p == b"/dev/mqueue")
}
/// The check `filename_parentat` makes of the directory a path's last name
/// is in: it is there (`ENOENT`) and a directory (`ENOTDIR`).
fn parent_there(c: &Context<'_>, p: &[u8]) -> Result<(), Errno> {
    let at = p.iter().rposition(|&b| b == b'/').unwrap_or(0);
    let parent = if at == 0 { b"/".as_slice() } else { &p[..at] };
    if c.files.fs.metadata(parent, true)?.mode & 0o170000 != 0o040000 {
        return Err(Errno::ENOTDIR);
    }
    Ok(())
}
/// `link` with a name in `/dev/mqueue`, the `mqueue` filesystem, as
/// `do_linkat` checks it: the old name is there (`ENOENT`), the new one is
/// not (`EEXIST`), both are on one mount (`EXDEV`), and the `mqueue` root
/// has no `link` (`EPERM`).
fn link_queue(
    c: &Context<'_>,
    (old_dir, old_raw, follow): (u64, Vec<u8>, bool),
    (new_dir, new_raw): (u64, &[u8]),
    (old_name, new_name): (Option<Vec<u8>>, Option<Vec<u8>>),
) -> Result<u64, Errno> {
    match &old_name {
        Some(name) => {
            if !crate::mqueue::mounted_there(c, name)? {
                return Err(Errno::ENOENT);
            }
        }
        None => {
            let (old, _) = lookup(c, old_dir, old_raw, follow)?;
            if generated_stat(c, &old, follow)?.is_none() {
                c.files.fs.metadata(&old, follow)?;
            }
        }
    }
    let new = c.files.path(new_dir, new_raw.to_vec())?;
    match &new_name {
        Some(name) => {
            if crate::mqueue::mounted_there(c, name)? {
                return Err(Errno::EEXIST);
            }
        }
        None => new_name_free(c, new_dir, new_raw, &new)?,
    }
    let (Some(old_name), Some(new_name)) = (old_name, new_name) else {
        return Err(EXDEV);
    };
    // Landlock's check (`hook_path_link`) within the root.
    let old_stat = crate::mqueue::mounted_stat(c, &old_name)?;
    crate::landlock::refer_stated(
        c,
        (&queue_path(&old_name), &queue_path(&new_name)),
        (&old_stat, None),
        false,
        0,
    )?;
    // `vfs_link`'s `may_create` before the root's missing `link`.
    crate::mqueue::may_change_root(c)?;
    Err(Errno::EPERM)
}
/// The path of the queue `name` in `/dev/mqueue`.
fn queue_path(name: &[u8]) -> Vec<u8> {
    [b"/dev/mqueue/".as_slice(), name].concat()
}
/// A path as a call's walk takes it: the directory it starts from
/// (`AT_FDCWD` or a descriptor) and the path as given.
type Walk<'a> = (u64, &'a [u8]);
/// `rename` with a name in `/dev/mqueue`, as `do_renameat2` checks it:
/// both directories are there, each path's walk may search its way
/// (`EACCES`), they are on one mount (`EXDEV`, before the names are
/// looked up), the old name is there (`ENOENT`), the new one too with
/// `RENAME_EXCHANGE` (`ENOENT`) and not with `RENAME_NOREPLACE`
/// (`EEXIST`); a name onto itself does nothing, and the `mqueue` root has
/// no `rename` (`EPERM`).
fn rename_queue(
    c: &Context<'_>,
    (old, new): (&[u8], &[u8]),
    (old_walk, new_walk): (Walk<'_>, Walk<'_>),
    (old_name, new_name): (Option<Vec<u8>>, Option<Vec<u8>>),
    flags: u32,
) -> Result<u64, Errno> {
    // `filename_parentat` of each path in turn: the walk's search
    // permission (`EACCES`), which stops at the generated `/dev` on the
    // `mqueue` side, then the parent itself.
    for (p, (dir, raw), name) in [(old, old_walk, &old_name), (new, new_walk, &new_name)] {
        crate::permissions::search(c.files, &c.process.credentials, dir, raw, false)?;
        if name.is_none() {
            parent_there(c, p)?;
        }
    }
    let (Some(old_name), Some(new_name)) = (old_name, new_name) else {
        return Err(EXDEV);
    };
    if !crate::mqueue::mounted_there(c, &old_name)? {
        return Err(Errno::ENOENT);
    }
    let there = crate::mqueue::mounted_there(c, &new_name)?;
    if flags & 2 != 0 && !there {
        return Err(Errno::ENOENT);
    }
    if flags & 1 != 0 && there {
        return Err(Errno::EEXIST);
    }
    // Landlock's check (`hook_path_rename`) within the root.
    let old_stat = crate::mqueue::mounted_stat(c, &old_name)?;
    let new_stat = crate::mqueue::mounted_stat(c, &new_name).ok();
    crate::landlock::refer_stated(
        c,
        (&queue_path(&old_name), &queue_path(&new_name)),
        (&old_stat, new_stat.as_ref()),
        true,
        flags,
    )?;
    if old_name == new_name {
        return Ok(0);
    }
    // `vfs_rename`'s `may_delete` and `may_create` (or `may_delete` of a
    // name there), whose sticky check also refuses with `EPERM`, before the
    // root's missing `rename`.
    crate::mqueue::may_change_root(c)?;
    Err(Errno::EPERM)
}
/// What a call that changes the file path `p` names reaches ([`followed`]),
/// or the file of the queue a path in `/dev/mqueue` names, which no
/// filesystem here holds ([`crate::mqueue::mounted_file`]).
fn reached(c: &Context<'_>, p: &[u8], follow: bool) -> Result<Option<Followed>, Errno> {
    if let Some(target) = followed(c, p, follow)? {
        return Ok(Some(target));
    }
    if queue_root(p) {
        return Ok(Some(Followed::File(Descriptor {
            file: Arc::new(crate::mqueue::MountedRoot::new(c)),
            path: b"/dev/mqueue".to_vec(),
            cloexec: false,
            opened: true,
            listed: Arc::default(),
            landlock: crate::landlock::FS,
        })));
    }
    let Some(name) = queue_name(p) else {
        return Ok(None);
    };
    let file = crate::mqueue::mounted_file(c, &name)?;
    Ok(Some(Followed::File(Descriptor {
        file,
        path: p.to_vec(),
        cloexec: false,
        opened: true,
        listed: Arc::default(),
        landlock: crate::landlock::FS,
    })))
}
/// What a link in `/proc/self/fd` reads: the path of a file on a mount
/// (marked ` (deleted)` once removed), `pipe:[<inode>]`, `socket:[<inode>]`,
/// `anon_inode:[<kind>]` for a file of no type (`anon_inode:inotify` and
/// `anon_inode:seccomp notify` without brackets), a memfd's own name, or a
/// POSIX message queue's path in its filesystem.
fn link_target(c: &Context<'_>, d: &Descriptor) -> Result<Vec<u8>, Errno> {
    let any = d.file.as_any();
    if let Some(memfd) = any.and_then(|v| v.downcast_ref::<crate::memfd::Memfd>()) {
        return Ok(memfd.link_target());
    }
    if let Some(queue) = any.and_then(|v| v.downcast_ref::<crate::mqueue::QueueFile>()) {
        return Ok(queue.link_target());
    }
    // A namespace file names its namespace, as its link in `ns` reads.
    if let Some(file) = any.and_then(|v| v.downcast_ref::<crate::namespaces::NamespaceFile>()) {
        return Ok(file.namespace.link());
    }
    // `anon_inode_getfd("inotify", ...)` names it without brackets.
    if any.is_some_and(|v| v.is::<crate::inotify::Instance>()) {
        return Ok(b"anon_inode:inotify".to_vec());
    }
    // So is a seccomp listener: "seccomp notify".
    if crate::seccomp::is_listener(&d.file) {
        return Ok(b"anon_inode:seccomp notify".to_vec());
    }
    let stat = d.file.stat()?;
    let anonymous = |kind: &str| format!("anon_inode:[{kind}]").into_bytes();
    Ok(match stat.mode & 0o170000 {
        0o010000 if d.path.is_empty() => format!("pipe:[{}]", stat.inode).into_bytes(),
        0o140000 => format!("socket:[{}]", stat.inode).into_bytes(),
        0 => anonymous(match any {
            Some(v) if v.is::<crate::events::EventCounter>() => "eventfd",
            Some(v) if v.is::<crate::epoll::EpollInstance>() => "eventpoll",
            Some(v) if v.is::<crate::timerfd::TimerFile>() => "timerfd",
            Some(v) if v.is::<crate::signalfd::SignalFile>() => "signalfd",
            Some(v) if v.is::<crate::landlock::Ruleset>() => "landlock-ruleset",
            Some(v) if v.is::<crate::io_uring::Ring>() => "io_uring",
            // The last kind of no type; Linux 6.9 and later name it from
            // pidfs instead.
            _ => "pidfd",
        }),
        // `/proc/self` opened itself names itself, as Linux's link does.
        _ if d.path == b"/proc/self" && any.is_some_and(|v| v.is::<LinkPath>()) => {
            b"/proc/self".to_vec()
        }
        _ if generated(&d.path) => match d.path.strip_prefix(b"/proc/self") {
            Some(rest) => [format!("/proc/{}", c.process.pid).as_bytes(), rest].concat(),
            None => d.path.clone(),
        },
        // The descriptor of a symbolic link itself names the link.
        _ if any.is_some_and(|v| v.is::<LinkPath>()) => {
            paludarium_vfs::normalize_path(&d.path).unwrap_or_else(|_| d.path.clone())
        }
        _ => current_path(c.files, d, stat.inode).unwrap_or_else(|| {
            let mut path = opened_path(d);
            path.extend_from_slice(b" (deleted)");
            path
        }),
    })
}
/// The path `d` was opened by, made plain.
fn opened_path(d: &Descriptor) -> Vec<u8> {
    paludarium_vfs::normalize_path(&d.path).unwrap_or_else(|_| d.path.clone())
}
/// The path of the file `d` holds, for a mapping of it to name: where the
/// file is now, or where it was opened if no name reaches it there (the
/// mapping marks that itself), or a memfd's own path. `None` if the file
/// cannot tell.
pub(crate) fn mapped_path(c: &Context<'_>, d: &Descriptor) -> Option<Vec<u8>> {
    if let Some(memfd) = d
        .file
        .as_any()
        .and_then(|v| v.downcast_ref::<crate::memfd::Memfd>())
    {
        return Some(memfd.mapped_name());
    }
    let stat = d.file.stat().ok()?;
    Some(current_path(c.files, d, stat.inode).unwrap_or_else(|| opened_path(d)))
}
/// The entries of `/proc/self/fd`: `.`, `..` and a link per descriptor, in
/// order, as Linux lists them.
/// The names in `fd`, links, or with `info` in `fdinfo`, regular files.
fn descriptor_entries(c: &Context<'_>, info: bool) -> Vec<paludarium_host::DirectoryEntry> {
    const DT_DIR: u8 = 4;
    const DT_REG: u8 = 8;
    const DT_LNK: u8 = 10;
    let kind = if info { DT_REG } else { DT_LNK };
    let fds = c.files.fds.lock().unwrap_or_else(PoisonError::into_inner);
    [b".".to_vec(), b"..".to_vec()]
        .into_iter()
        .map(|name| (name, DT_DIR))
        .chain(fds.keys().map(|n| (n.to_string().into_bytes(), kind)))
        .enumerate()
        .map(|(i, (name, kind))| paludarium_host::DirectoryEntry {
            name,
            inode: i as u64 + 1,
            kind,
        })
        .collect()
}
/// The `stat` of a file paludarium makes itself (`/dev`, `/proc`), with its
/// device and block size (devtmpfs's for `/dev`, devpts's for `/dev/pts`,
/// procfs's for `/proc`), or `None` for any other path and for a link to a
/// descriptor that is not open. A link in `/proc/self/fd` is followed to its
/// file, whose block size it takes, unless `follow` is false.
fn generated_stat(
    c: &Context<'_>,
    path: &[u8],
    follow: bool,
) -> Result<Option<(FileStat, u64, u32)>, Errno> {
    // Under another process's directory or `task`: ENOENT for what is not
    // there, rather than whatever a mounted directory holds at the path.
    if let Some(task_path) = crate::proc::task_path(path, c.process.pid, c.tid) {
        let task = tasks::find(c, &task_path)?;
        return tasks::stat(c, path, &task, task_path.entry, follow).map(Some);
    }
    known_stat(c, path, follow)
}
/// [`generated_stat`] of the files that are always there. A name in
/// `/dev/pts` that no slave has is `ENOENT`, as devpts holds no other.
fn known_stat(
    c: &Context<'_>,
    path: &[u8],
    follow: bool,
) -> Result<Option<(FileStat, u64, u32)>, Errno> {
    if let Some(target) = crate::devices::through_link(path) {
        return known_stat(c, &target, follow);
    }
    match crate::devices::entry(path) {
        Some(crate::devices::Entry::Link(target)) if follow => known_stat(c, target, follow),
        Some(crate::devices::Entry::Slave(number)) => {
            let stat = crate::pty::slave_stat(c, number.ok_or(Errno::ENOENT)?)?;
            Ok(Some((stat, device(c, path), SMALL_BLOCK_SIZE)))
        }
        Some(crate::devices::Entry::Mqueue) => Ok(Some((
            crate::mqueue::mounted_root_stat(c),
            device(c, path),
            BLOCK_SIZE,
        ))),
        Some(crate::devices::Entry::Queue) => {
            let name = crate::mqueue::mounted_name(path).ok_or(Errno::ENOENT)?;
            let stat = crate::mqueue::mounted_stat(c, name)?;
            Ok(Some((stat, device(c, path), BLOCK_SIZE)))
        }
        Some(
            entry @ (crate::devices::Entry::Pts | crate::devices::Entry::Ptmx { devpts: true }),
        ) => Ok(Some((
            crate::devices::stat(entry),
            device(c, path),
            SMALL_BLOCK_SIZE,
        ))),
        Some(entry) => Ok(Some((
            crate::devices::stat(entry),
            device(c, path),
            BLOCK_SIZE,
        ))),
        None => Ok(other_generated_stat(c, path, follow)),
    }
}
/// [`generated_stat`] of a path outside `/dev`.
fn other_generated_stat(
    c: &Context<'_>,
    path: &[u8],
    follow: bool,
) -> Option<(FileStat, u64, u32)> {
    if let Some(mountinfo) = crate::proc::mount_table(path) {
        let length = crate::proc::render(&c.files.fs.mounts(), mountinfo).len();
        return Some((crate::proc::stat(length), device(c, path), SMALL_BLOCK_SIZE));
    }
    // `/proc/self` itself, not followed, is the link to this process's
    // directory; `/proc/self/` follows it.
    if path == b"/proc/self" && !follow {
        return Some((
            crate::proc::self_link_stat(),
            device(c, path),
            SMALL_BLOCK_SIZE,
        ));
    }
    if let Some(entry) = crate::sysctl::entry(path) {
        return Some((
            crate::sysctl::stat(c, entry),
            device(c, path),
            SMALL_BLOCK_SIZE,
        ));
    }
    if let Some(entry) = crate::proc::system_entry(path) {
        let length = system_file(c, entry).len();
        return Some((crate::proc::stat(length), device(c, path), SMALL_BLOCK_SIZE));
    }
    if tasks::is_root(path) {
        return Some((
            crate::proc::directory_stat(),
            device(c, path),
            SMALL_BLOCK_SIZE,
        ));
    }
    let entry = crate::proc::own_entry(path, c.process.pid)?;
    if let Some(target) = own_link(c, entry) {
        if follow {
            let stat = c.files.fs.metadata(&target, true).ok()?;
            return Some((stat, device(c, &target), BLOCK_SIZE));
        }
        return Some((
            crate::proc::self_link_stat(),
            device(c, path),
            SMALL_BLOCK_SIZE,
        ));
    }
    let stat = match entry {
        crate::proc::OwnEntry::Directory => crate::proc::directory_stat(),
        crate::proc::OwnEntry::Descriptors => crate::proc::descriptors_stat(),
        crate::proc::OwnEntry::DescriptorInfos => crate::proc::directory_stat(),
        // As Linux's, of size 0, while the descriptor is open.
        crate::proc::OwnEntry::DescriptorInfo(n) => {
            c.files.descriptor(u64::from(n)).ok()?;
            crate::proc::stat(0)
        }
        crate::proc::OwnEntry::Status => crate::proc::stat(status(c).len()),
        crate::proc::OwnEntry::Stat
        | crate::proc::OwnEntry::Cmdline
        | crate::proc::OwnEntry::Comm => {
            crate::proc::stat(own_file(c, entry).map_or(0, |content| content.len()))
        }
        crate::proc::OwnEntry::Environ => {
            crate::proc::private_stat(own_file(c, entry).map_or(0, |content| content.len()))
        }
        crate::proc::OwnEntry::Exe | crate::proc::OwnEntry::Cwd => return None,
        crate::proc::OwnEntry::Maps | crate::proc::OwnEntry::Smaps => crate::proc::stat(0),
        crate::proc::OwnEntry::Descriptor(n) => {
            let d = c.files.descriptor(u64::from(n)).ok()?;
            if follow {
                return Some((
                    d.file.stat().ok()?,
                    descriptor_device(c, &d),
                    descriptor_block_size(c, &d),
                ));
            }
            crate::proc::link_stat(d.file.flags() & 3)
        }
    };
    Some((stat, device(c, path), SMALL_BLOCK_SIZE))
}

/// The names in this process's /proc directory.
fn own_entries() -> Vec<paludarium_host::DirectoryEntry> {
    const DT_DIR: u8 = 4;
    [(&b"."[..], DT_DIR), (&b".."[..], DT_DIR)]
        .into_iter()
        .chain(crate::proc::OWN_NAMES)
        .enumerate()
        .map(|(i, (name, kind))| paludarium_host::DirectoryEntry {
            name: name.to_vec(),
            inode: i as u64 + 1,
            kind,
        })
        .collect()
}
/// Where this process's `exe` or `cwd` link leads: the program it runs and
/// its current directory. `None` for any other entry.
fn own_link(c: &Context<'_>, entry: crate::proc::OwnEntry) -> Option<Vec<u8>> {
    match entry {
        crate::proc::OwnEntry::Exe => Some(c.group.executable()),
        crate::proc::OwnEntry::Cwd => Some(
            c.files
                .cwd
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone(),
        ),
        _ => None,
    }
}
/// The contents of this process's `stat`, `cmdline` or `comm`; `None` for
/// any other entry.
fn own_file(c: &Context<'_>, entry: crate::proc::OwnEntry) -> Option<Vec<u8>> {
    let start_stack = c.group.start_stack();
    let (arguments, environment) = crate::coredump::string_ranges(c.mem, start_stack);
    Some(match entry {
        crate::proc::OwnEntry::Comm => crate::proc::render_comm(&c.process.name),
        // The argument or environment strings as they are in memory now, as
        // Linux reads them.
        crate::proc::OwnEntry::Cmdline | crate::proc::OwnEntry::Environ => {
            let (start, end) = if entry == crate::proc::OwnEntry::Cmdline {
                arguments
            } else {
                environment
            };
            let length = usize::try_from(end - start).unwrap_or(0);
            let mut bytes = vec![0; length];
            if c.mem.read(GuestAddr(start), &mut bytes).is_err() {
                bytes.clear();
            }
            bytes
        }
        crate::proc::OwnEntry::Stat => {
            let (parent, group, session, children_cpu, rss_limit) =
                c.processes.stat_of(c.process.pid);
            let mask = |handled: &dyn Fn(u64) -> bool| {
                c.process
                    .signal_actions
                    .iter()
                    .filter(|(n, a)| (1..=64).contains(*n) && handled(a.handler))
                    .fold(0u64, |mask, (&n, _)| mask | 1 << (n - 1))
            };
            crate::proc::render_stat(&crate::proc::ProcessStat {
                pid: c.process.pid,
                name: &c.process.name,
                // Running, reading this.
                state: 'R',
                waiting: false,
                exit_signal: 17,
                parent,
                group,
                session,
                terminal: crate::pty::stat_fields(c.processes.terminal(c.process.pid).as_deref()),
                cpu: c.group.process_cpu(),
                children_cpu,
                nice: c.group.nice(c.process.pid).unwrap_or(0),
                threads: c.group.active_threads(),
                virtual_size: c.mem.mappings().map(|m| m.length).sum(),
                rss_limit,
                start_stack,
                start_brk: c.mem.initial_break().0,
                arguments,
                environment,
                pending: c
                    .process
                    .pending
                    .iter()
                    .filter(|s| (1..=64).contains(&s.number))
                    .fold(0, |mask, s| mask | 1 << (s.number - 1)),
                blocked: c.process.signal_mask,
                ignored: mask(&|handler| handler == 1),
                caught: mask(&|handler| handler > 1),
            })
        }
        crate::proc::OwnEntry::DescriptorInfo(n) => descriptor_info(c, n)?,
        _ => return None,
    })
}
/// `/proc/self/fdinfo/<n>` while descriptor `n` is open, as Linux's
/// `seq_show` writes it: the description's position, its flags in octal
/// (`F_GETFL`'s, and `O_CLOEXEC` for the descriptor), the ID of its mount
/// (as `statx` gives it) and its inode; then a `lock:` line for the
/// description's `flock` lock and each record lock set through it
/// ([`crate::record_locks::fdinfo`]), and the lines of an inotify instance,
/// an eventfd, a signalfd, a timerfd or an epoll.
fn descriptor_info(c: &Context<'_>, n: u32) -> Option<Vec<u8>> {
    const O_CLOEXEC: u32 = 0o2000000;
    let d = c.files.descriptor(u64::from(n)).ok()?;
    let flags = status_flags(&d) | if d.cloexec { O_CLOEXEC } else { 0 };
    // A file that cannot seek (a pipe, a socket) is at 0.
    let pos = d.file.seek(0, 1).unwrap_or(0);
    let ino = d.file.stat().map_or(0, |stat| stat.inode);
    let mount = mount_id(descriptor_device(c, &d));
    let mut out =
        format!("pos:\t{pos}\nflags:\t0{flags:o}\nmnt_id:\t{mount}\nino:\t{ino}\n").into_bytes();
    out.extend(crate::record_locks::fdinfo(c, &d));
    let any = d.file.as_any();
    if let Some(instance) = crate::inotify::of(&d.file) {
        out.extend(instance.fdinfo());
    } else if let Some(counter) = any.and_then(|a| a.downcast_ref::<crate::events::EventCounter>())
    {
        out.extend(counter.fdinfo());
    } else if let Some(signals) = any.and_then(|a| a.downcast_ref::<crate::signalfd::SignalFile>())
    {
        out.extend(signals.fdinfo());
    } else if let Some(timer) = any.and_then(|a| a.downcast_ref::<crate::timerfd::TimerFile>()) {
        out.extend(timer.fdinfo());
    } else if let Some(epoll) = any.and_then(|a| a.downcast_ref::<crate::epoll::EpollInstance>()) {
        out.extend(epoll_fdinfo(c, epoll));
    }
    Some(out)
}
/// An epoll's lines in `/proc/self/fdinfo`, as Linux's `ep_show_fdinfo`
/// writes one for each file it watches: the descriptor it was added with,
/// the events, the data, and the file's position, inode and device (the
/// device of a descriptor this process has of it, or 0). They come by
/// descriptor, where Linux's order follows its files' addresses.
fn epoll_fdinfo(c: &Context<'_>, epoll: &crate::epoll::EpollInstance) -> Vec<u8> {
    let descriptors: Vec<Descriptor> = c
        .files
        .fds
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .values()
        .cloned()
        .collect();
    let mut out = Vec::new();
    for (fd, events, data, file) in epoll.targets() {
        let pos = file.seek(0, 1).unwrap_or(0);
        let ino = file.stat().map_or(0, |stat| stat.inode);
        let device = descriptors
            .iter()
            .find(|d| Arc::ptr_eq(&d.file, &file))
            .map_or(0, |d| descriptor_device(c, d));
        // `new_encode_dev` undone, then `MKDEV`.
        let major = (device >> 8) & 0xfff;
        let minor = (device & 0xff) | ((device >> 12) & !0xff);
        out.extend_from_slice(
            format!(
                "tfd: {fd:8} events: {events:8x} data: {data:16x}  pos:{pos} ino:{ino:x} sdev:{:x}\n",
                major << 20 | minor
            )
            .as_bytes(),
        );
    }
    out
}
/// The contents of a system-wide /proc file, from what `sysinfo` reports.
fn system_file(c: &Context<'_>, entry: crate::proc::SystemEntry) -> Vec<u8> {
    match entry {
        crate::proc::SystemEntry::Loadavg => {
            let (tasks, last_pid) = c.processes.task_counts();
            crate::proc::render_loadavg(1, tasks, last_pid)
        }
        crate::proc::SystemEntry::Meminfo => {
            crate::proc::render_meminfo(crate::syscalls::SYSINFO_RAM)
        }
        crate::proc::SystemEntry::Stat => {
            let (_, forks) = c.processes.task_counts();
            let clock = |id| c.host.clock(id).unwrap_or(0);
            let boot = clock(paludarium_host::ClockId::Realtime)
                .saturating_sub(clock(paludarium_host::ClockId::Monotonic));
            crate::proc::render_system_stat(&crate::proc::SystemStat {
                cpus: crate::syscalls::active_cpus(c),
                boot_time: boot / 1_000_000_000,
                forks,
                running: 1,
            })
        }
        crate::proc::SystemEntry::Uptime => crate::proc::render_uptime(
            c.host
                .clock(paludarium_host::ClockId::Monotonic)
                .unwrap_or(0),
        ),
    }
}
/// `mknod` and `mknodat`, as Linux's `do_mknodat`: a regular file (type 0
/// too), a FIFO or a socket node, with the permission bits of `mode` less
/// the umask. A directory's type is `EPERM` and an unknown one `EINVAL`. A
/// device needs a device to stand for, which paludarium has none of: `EPERM`,
/// as for a process without `CAP_MKNOD`. Landlock's check (`hook_path_mknod`)
/// of a device, a whiteout too, comes before that refusal, as in Linux.
fn mknod(c: &mut Context<'_>, dir: u64, raw: &[u8], mode: u32, dev: u32) -> Result<(), Errno> {
    const S_IFMT: u32 = 0o170000;
    let kind = mode & S_IFMT;
    // A name in `/dev/mqueue` is the `mqueue` filesystem's, which makes a
    // queue for a regular file and nothing else.
    if matches!(
        kind,
        0 | 0o100000 | 0o010000 | 0o140000 | 0o020000 | 0o060000
    ) {
        let p = c.files.path(dir, raw.to_vec())?;
        if queue_root(&p) {
            return Err(Errno::EEXIST);
        }
        if let Some(name) = queue_name(&p) {
            let device = matches!(kind, 0o020000 | 0o060000);
            let regular = matches!(kind, 0 | 0o100000).then_some(mode);
            return crate::mqueue::make_mounted(c, &name, regular, || {
                let dev = if device { u64::from(dev) } else { 0 };
                landlock_name(c, &p, crate::landlock::make_access(kind, dev))
            })
            .map(|_| ());
        }
    }
    match kind {
        0 | 0o100000 | 0o010000 | 0o140000 => {}
        0o020000 | 0o060000 => {
            if c.process.credentials.landlock != Default::default() {
                let p = c.files.path(dir, raw.to_vec())?;
                if landlock_named(c, &p).is_some_and(|(_, there)| there.is_none()) {
                    landlock_name(c, &p, crate::landlock::make_access(kind, u64::from(dev)))?;
                }
            }
            return Err(Errno::EPERM);
        }
        0o040000 => return Err(Errno::EPERM),
        _ => return Err(Errno::EINVAL),
    }
    let p = c.files.path(dir, raw.to_vec())?;
    let created = crate::permissions::create(c.files, &c.process.credentials, dir, raw)?;
    if landlock_named(c, &p).is_some_and(|(_, there)| there.is_none()) {
        landlock_name(c, &p, crate::landlock::make_access(kind, 0))?;
    }
    let permissions = mode & 0o7777 & !c.files.umask();
    match kind {
        0o010000 => {
            c.files.fs.make_fifo(&p, permissions)?;
        }
        0o140000 => {
            c.files.fs.make_socket(&p, permissions)?;
        }
        _ => {
            // O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW: a new empty file.
            // Linux's `vfs_create` makes it without opening it.
            crate::inotify::unopened(|| {
                c.files
                    .fs
                    .open(&p, 0o1 | 0o100 | 0o200 | 0o400000, permissions)
            })?;
        }
    }
    if let Some(parent) = created {
        crate::permissions::own(c.files, &c.process.credentials, &p, false, &parent);
    }
    Ok(())
}
/// This process's `/proc/self/status`.
fn status(c: &Context<'_>) -> Vec<u8> {
    let (parent, queue_limit, no_new_privs) = c.processes.status_of(c.process.pid);
    let (group_id, session, space) = c.processes.view(c.process.pid).map_or_else(
        || (0, 0, c.group.namespaces(c.tid).pid.clone()),
        |view| (view.group_id, view.session, view.space),
    );
    let mask = |numbers: &mut dyn Iterator<Item = i32>| {
        numbers
            .filter(|n| (1..=64).contains(n))
            .fold(0u64, |mask, n| mask | 1 << (n - 1))
    };
    let actions = &c.process.signal_actions;
    let descriptors = c
        .files
        .fds
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .keys()
        .next_back()
        .map_or(0, |&fd| fd as usize + 1);
    crate::proc::render_status(&crate::proc::Status {
        name: &c.process.name,
        umask: Some(c.files.umask()),
        state: "R (running)",
        tgid: c.process.pid,
        pid: c.process.pid,
        parent,
        group_id,
        session,
        space: &space,
        descriptors: Some(descriptors),
        locked: Some(c.mem.locked_pages()),
        threads: c.group.active_threads(),
        queued: c.process.pending.len(),
        queue_limit,
        pending: mask(&mut c.process.pending.iter().map(|s| s.number)),
        blocked: c.process.signal_mask,
        ignored: mask(
            &mut actions
                .iter()
                .filter(|(_, a)| a.handler == 1)
                .map(|(&n, _)| n),
        ),
        caught: mask(
            &mut actions
                .iter()
                .filter(|(_, a)| a.handler > 1)
                .map(|(&n, _)| n),
        ),
        no_new_privs,
        seccomp: c.group.seccomp_of(c.process.pid, &c.process.seccomp),
        credentials: &c.process.credentials,
        reader: &c.process.credentials.user,
    })
}
