//! System V shared memory: `shmget`, `shmat`, `shmdt` and `shmctl`, in the
//! calling thread's IPC namespace, as Linux's `ipc/shm.c` has them.
//!
//! A segment is shared memory that every attachment shows, in every process.
//! Each `shmat` is an open file of its own (Linux's clone of the segment's
//! file), which the shared mappings it makes keep alive: a `fork` copies
//! them, and `munmap`, `mprotect` and `mremap` split them as Linux splits
//! their VMAs, which never merge. So the segment's count of attachments
//! (`shm_nattch`) is how many of those mappings live, as Linux's `shm_open`
//! and `shm_close` count its VMAs. A segment marked for removal is removed
//! once that count is 0.
use crate::ipc::{
    self, CAP_IPC_OWNER, CAP_SYS_ADMIN, IPC_CREAT, IPC_EXCL, IPC_INFO, IPC_PRIVATE, IPC_RMID,
    IPC_SET, IPC_STAT, Perm,
};
use crate::namespaces::{KeptPid, Namespace};
use crate::syscalls::{Context, Outcome};
use paludarium_host::Host;
use paludarium_mmu::{
    AddressSpace, Backing, FileSize, MappingKind, PageSource, Placement, Prot, SharedPages,
};
use paludarium_types::{Errno, GuestAddr, USER_ADDRESS_LIMIT};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};

const SHM_HUGETLB: i32 = 0o4000;
const SHM_RDONLY: i32 = 0o10000;
const SHM_RND: i32 = 0o20000;
const SHM_REMAP: i32 = 0o40000;
const SHM_EXEC: i32 = 0o100000;
/// The mode bits of a segment marked for removal and of a locked one.
const SHM_DEST: u32 = 0o1000;
const SHM_LOCKED: u32 = 0o2000;

const SHM_LOCK: i32 = 11;
const SHM_UNLOCK: i32 = 12;
const SHM_STAT: i32 = 13;
const SHM_INFO: i32 = 14;
const SHM_STAT_ANY: i32 = 15;

/// Linux's defaults of `kernel.shmmax`, `kernel.shmall` (in pages) and
/// `kernel.shmmni`, which each IPC namespace starts with ([`Limits`]).
const SHMMIN: u64 = 1;
const SHMMAX: u64 = u64::MAX - (1 << 24);
const SHMALL: u64 = u64::MAX - (1 << 24);
const SHMMNI: usize = 4096;
const PAGE: u64 = 4096;
/// The device a segment's file lies on, which `/proc/<pid>/maps` shows:
/// Linux's internal tmpfs mount, 00:01.
const DEVICE: u64 = 1;

const CAP_IPC_LOCK: u64 = 1 << 14;
const RLIMIT_MEMLOCK: usize = 8;
const ENOMEM: Errno = Errno::ENOMEM;

/// The segments of an IPC namespace.
#[derive(Clone, Default)]
pub(crate) struct Segments(Arc<Mutex<Table>>);

impl std::fmt::Debug for Segments {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Segments")
    }
}

#[derive(Default)]
struct Table {
    /// By index.
    segments: BTreeMap<u32, Segment>,
    ids: ipc::Ids,
    /// The pages of all segments (Linux's `shm_tot`).
    pages: u64,
    limits: Limits,
}

/// An IPC namespace's `kernel.shmmax`, `shmall` and `shmmni` (Linux's
/// `shm_ctlmax`, `shm_ctlall` and `shm_ctlmni`), which a new one has at
/// Linux's defaults (`shm_init_ns`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Limits {
    pub max: u64,
    pub all: u64,
    pub mni: i32,
    /// `kernel.shm_rmid_forced`, 0 or 1 ([`Segments::set_rmid_forced`]).
    pub rmid_forced: i32,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max: SHMMAX,
            all: SHMALL,
            mni: SHMMNI as i32,
            rmid_forced: 0,
        }
    }
}

/// What a thread holds while it runs, which tells the segments it made in
/// one IPC namespace (Linux's `shm_clist` and `shm_creator`): once it is
/// gone, they are orphans, which `kernel.shm_rmid_forced` removes.
pub(crate) struct Creator {
    table: Weak<Mutex<Table>>,
}

impl Creator {
    /// Whether it is for the segments of `segments`.
    pub(crate) fn of(&self, segments: &Segments) -> bool {
        std::ptr::eq(self.table.as_ptr(), Arc::as_ptr(&segments.0))
    }
}

/// A thread leaves the segments it made, as Linux's `exit_shm`: with
/// `kernel.shm_rmid_forced`, those no mapping shows go at once, and the
/// others at their last detach; all of them are orphans from now on.
pub(crate) fn leave(creator: Arc<Creator>) {
    let Some(table) = creator.table.upgrade() else {
        return;
    };
    let mut table = table.lock().unwrap_or_else(PoisonError::into_inner);
    table.purge();
    if table.limits.rmid_forced != 0 {
        let made: Vec<u32> = table
            .segments
            .iter()
            .filter(|(_, segment)| {
                segment.attached() == 0
                    && std::ptr::eq(segment.creator.as_ptr(), Arc::as_ptr(&creator))
            })
            .map(|(&index, _)| index)
            .collect();
        for index in made {
            table.destroy(index);
        }
    }
}

struct Segment {
    id: i32,
    /// Its key, `IPC_PRIVATE` once it is marked for removal, and its
    /// permissions with `SHM_DEST` and `SHM_LOCKED`.
    perm: Perm,
    /// The thread that made it, while it runs in the namespace.
    creator: Weak<Creator>,
    size: u64,
    atime: i64,
    dtime: i64,
    ctime: i64,
    /// The processes that made it and attached or detached it last.
    cpid: KeptPid,
    lpid: KeptPid,
    memory: SharedPages,
    /// `/SYSV<key> (deleted)`, after the key it was made with.
    name: Arc<[u8]>,
    attachments: Vec<Weak<Attachment>>,
    /// The real user whose `RLIMIT_MEMLOCK` its `SHM_LOCK` counts against.
    locker: Option<u32>,
}

impl Segment {
    /// How many shared mappings show it (`shm_nattch`).
    fn attached(&self) -> u64 {
        self.attachments
            .iter()
            .map(|attachment| attachment.strong_count() as u64)
            .sum()
    }
    fn pages(&self) -> u64 {
        self.size.div_ceil(PAGE)
    }
}

/// One `shmat`'s open file of a segment, which its shared mappings hold.
pub(crate) struct Attachment {
    id: i32,
    size: u64,
    /// The same size, which never changes, for the threads' TLBs to check
    /// without holding the attachment, which would count as a mapping
    /// ([`PageSource::file_size`]).
    file_size: Arc<FileSize>,
    name: Arc<[u8]>,
    /// Told when the last mapping goes, to remove a segment marked for it.
    table: Weak<Mutex<Table>>,
}

impl PageSource for Attachment {
    /// A page that has no contents yet is zeros.
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, Errno> {
        let count = usize::try_from(self.size.saturating_sub(offset))
            .map_or(buf.len(), |n| n.min(buf.len()));
        buf[..count].fill(0);
        Ok(count)
    }
    fn size(&self) -> Option<u64> {
        Some(self.size)
    }
    fn file_size(&self) -> Option<Arc<FileSize>> {
        Some(Arc::clone(&self.file_size))
    }
    /// No name links a segment's file, so a core holds its mappings, as
    /// Linux's dump of shared anonymous memory.
    fn linked(&self) -> bool {
        false
    }
    fn name(&self) -> Option<Vec<u8>> {
        Some(self.name.to_vec())
    }
    fn as_any(&self) -> Option<&(dyn std::any::Any + Send + Sync)> {
        Some(self)
    }
    /// Linux gives a segment's file the segment's ID as its inode.
    fn identity(&self) -> (u64, u64) {
        (DEVICE, u64::from(self.id as u32))
    }
    fn open_file(&self) -> usize {
        std::ptr::from_ref(self).addr()
    }
    fn merges(&self) -> bool {
        false
    }
    /// A VMA of it opened (`shm_open`): a split, a `fork` or a move.
    fn opened(&self, by: &paludarium_mmu::Actor) {
        self.touched(by, true);
    }
    /// A VMA of it closed (`shm_close`): an unmap, an `exec` or an exit.
    fn closed(&self, by: &paludarium_mmu::Actor) {
        self.touched(by, false);
    }
}

/// Who acts on an address space that may show System V shared memory: the
/// process, for `shm_lpid`, and the clock, for `shm_atime` and `shm_dtime`,
/// as Linux's `shm_open` and `shm_close` take them from `current`.
pub(crate) struct Actor {
    pid: KeptPid,
    host: Arc<dyn Host>,
}

/// Says that process `pid`, numbered in `space`, acts on `mem` from now on.
pub(crate) fn act(mem: &AddressSpace, space: &Namespace, pid: u32, host: &Arc<dyn Host>) {
    mem.set_actor(Arc::new(Actor {
        pid: space.keep(pid),
        host: Arc::clone(host),
    }));
}

impl Attachment {
    /// A VMA of this attachment opened or closed, by `by`, as Linux's
    /// `__shm_open` and `__shm_close` stamp the segment: the time and the
    /// process, if the segment is still there.
    fn touched(&self, by: &paludarium_mmu::Actor, opened: bool) {
        let (Some(actor), Some(table)) = (by.downcast_ref::<Actor>(), self.table.upgrade()) else {
            return;
        };
        let mut table = table.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(segment) = table
            .segments
            .get_mut(&ipc::index(self.id))
            .filter(|segment| segment.id == self.id)
        else {
            return;
        };
        let now = ipc::seconds(actor.host.as_ref());
        if opened {
            segment.atime = now;
        } else {
            segment.dtime = now;
        }
        segment.lpid = actor.pid.clone();
    }
}

impl Drop for Attachment {
    /// The last mapping of a `shmat` goes (`shm_close`): a segment marked
    /// for removal goes with its last attachment, and so does any with
    /// `kernel.shm_rmid_forced`.
    fn drop(&mut self) {
        if let Some(table) = self.table.upgrade() {
            let mut table = table.lock().unwrap_or_else(PoisonError::into_inner);
            table.purge();
            let index = ipc::index(self.id);
            if table.limits.rmid_forced != 0
                && table
                    .segments
                    .get(&index)
                    .is_some_and(|segment| segment.id == self.id && segment.attached() == 0)
            {
                table.destroy(index);
            }
        }
    }
}

impl Segments {
    /// Its limits, which `/proc/sys/kernel` reads and sets
    /// ([`crate::sysctl`]).
    pub(crate) fn with_limits<R>(&self, f: impl FnOnce(&mut Limits) -> R) -> R {
        f(&mut self.lock().limits)
    }
    /// Its IDs, whose next one `/proc/sys/kernel` reads and sets
    /// ([`crate::sysctl`]).
    pub(crate) fn with_ids<R>(&self, f: impl FnOnce(&mut ipc::Ids) -> R) -> R {
        f(&mut self.lock().ids)
    }
    fn lock(&self) -> MutexGuard<'_, Table> {
        let mut table = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        table.purge();
        table
    }
    /// A new mark for the segments a thread makes here.
    pub(crate) fn creator(&self) -> Arc<Creator> {
        Arc::new(Creator {
            table: Arc::downgrade(&self.0),
        })
    }
    /// Sets `kernel.shm_rmid_forced`; set, it removes the orphans no
    /// mapping shows, as Linux's `shm_destroy_orphaned`.
    pub(crate) fn set_rmid_forced(&self, value: i32) {
        self.lock().limits.rmid_forced = value;
        self.remove_orphans();
    }
    /// With `kernel.shm_rmid_forced` set, removes the orphans no mapping
    /// shows (`shm_destroy_orphaned`), as each write of it does.
    pub(crate) fn remove_orphans(&self) {
        let mut table = self.lock();
        if table.limits.rmid_forced == 0 {
            return;
        }
        let orphans: Vec<u32> = table
            .segments
            .iter()
            .filter(|(_, segment)| segment.attached() == 0 && segment.creator.strong_count() == 0)
            .map(|(&index, _)| index)
            .collect();
        for index in orphans {
            table.destroy(index);
        }
    }
}

impl Table {
    /// Removes the segments marked for removal that nothing shows any more,
    /// as Linux's `shm_destroy` at their last detach.
    fn purge(&mut self) {
        let doomed: Vec<u32> = self
            .segments
            .iter()
            .filter(|(_, segment)| segment.perm.mode & SHM_DEST != 0 && segment.attached() == 0)
            .map(|(&index, _)| index)
            .collect();
        for index in doomed {
            self.destroy(index);
        }
    }
    /// Removes the segment at `index` (`shm_destroy`).
    fn destroy(&mut self, index: u32) {
        if let Some(segment) = self.segments.remove(&index) {
            self.pages -= segment.pages();
        }
    }
    /// The segment with this ID, `EINVAL` for none (Linux's
    /// `ipc_obtain_object_check`).
    fn checked(&mut self, id: i32) -> Result<&mut Segment, Errno> {
        self.segments
            .get_mut(&ipc::index(id))
            .filter(|segment| segment.id == id)
            .ok_or(Errno::EINVAL)
    }
}

/// The segments of the calling thread's IPC namespace.
fn segments(c: &Context<'_>) -> Segments {
    c.group.namespaces(c.tid).ipc.shm.clone()
}

fn result(value: Result<u64, Errno>) -> Outcome {
    Outcome::Return(value.unwrap_or_else(Errno::to_syscall_return))
}

/// `shmget(key, size, shmflg)`, in the order of Linux's `ipcget`: a key in
/// use gives its segment unless `IPC_CREAT | IPC_EXCL` (`EEXIST`), the size
/// is more than it has (`EINVAL`) or the permissions asked for are not
/// granted (`EACCES`); a key not in use is `ENOENT` without `IPC_CREAT`.
/// A new segment's checks are its size, from 1 to `kernel.shmmax`
/// (`EINVAL`), its pages, which a size near the top of 64 bits wraps
/// (`ENOSPC`), the pages of all segments against `kernel.shmall`
/// (`ENOSPC`), `SHM_HUGETLB` (`ENOSYS`, as from a kernel built without
/// hugetlbfs) and the number of segments against `kernel.shmmni`
/// (`ENOSPC`).
pub(crate) fn sys_shmget(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    result(shmget(c, a[0] as i32, a[1], a[2] as i32))
}

fn shmget(c: &Context<'_>, key: i32, size: u64, flag: i32) -> Result<u64, Errno> {
    let credentials = &c.process.credentials;
    let owner = ipc::capable(c, CAP_IPC_OWNER);
    let shm = segments(c);
    let creator = c.group.shm_creator(c.tid, &shm);
    let mut table = shm.lock();
    if key != IPC_PRIVATE {
        if let Some(segment) = table
            .segments
            .values()
            .find(|segment| segment.perm.key == key)
        {
            if flag & IPC_CREAT != 0 && flag & IPC_EXCL != 0 {
                return Err(Errno::EEXIST);
            }
            if segment.size < size {
                return Err(Errno::EINVAL);
            }
            if !segment.perm.permitted(credentials, flag as u32, owner) {
                return Err(Errno::EACCES);
            }
            return Ok(u64::from(segment.id as u32));
        }
        if flag & IPC_CREAT == 0 {
            return Err(Errno::ENOENT);
        }
    }
    let limits = table.limits;
    if !(SHMMIN..=limits.max).contains(&size) {
        return Err(Errno::EINVAL);
    }
    // `newseg`'s page count, which wraps as Linux's does.
    let pages = size.wrapping_add(PAGE - 1) / PAGE;
    if pages.wrapping_mul(PAGE) < size {
        return Err(Errno::ENOSPC);
    }
    if table
        .pages
        .checked_add(pages)
        .is_none_or(|total| total > limits.all)
    {
        return Err(Errno::ENOSPC);
    }
    if flag & SHM_HUGETLB != 0 {
        return Err(Errno::ENOSYS);
    }
    let table = &mut *table;
    let id = table
        .ids
        .allocate(&table.segments, limits.mni.max(0) as usize)?;
    let name = format!("/SYSV{:08x} (deleted)", key as u32);
    table.segments.insert(
        ipc::index(id),
        Segment {
            id,
            perm: Perm::new(key, credentials, flag),
            creator: Arc::downgrade(&creator),
            size,
            atime: 0,
            dtime: 0,
            ctime: ipc::now(c),
            cpid: c.pid_space().keep(c.process.pid),
            lpid: KeptPid::default(),
            memory: SharedPages::new(),
            name: name.into_bytes().into(),
            attachments: Vec::new(),
            locker: None,
        },
    );
    table.pages += pages;
    Ok(u64::from(id as u32))
}

/// `shmat(shmid, shmaddr, shmflg)`, as Linux's `do_shmat`: an address must
/// be page-aligned unless `SHM_RND` rounds it down, and without
/// `SHM_REMAP` the segment's size from it must be free (`EINVAL`); then
/// the segment (`EINVAL`) and the permission to read it, and write it
/// without `SHM_RDONLY` and execute it with `SHM_EXEC` (`EACCES`). The
/// mapping is shared, and may become writable only without `SHM_RDONLY`.
pub(crate) fn sys_shmat(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    result(shmat(c, a[0] as i32, a[1], a[2] as i32))
}

fn shmat(c: &Context<'_>, id: i32, addr: u64, flag: i32) -> Result<u64, Errno> {
    if id < 0 {
        return Err(Errno::EINVAL);
    }
    let fixed = addr != 0;
    let mut addr = addr;
    if fixed {
        if !addr.is_multiple_of(PAGE) {
            if flag & SHM_RND == 0 {
                return Err(Errno::EINVAL);
            }
            addr -= addr % PAGE;
            if addr == 0 && flag & SHM_REMAP != 0 {
                return Err(Errno::EINVAL);
            }
        }
    } else if flag & SHM_REMAP != 0 {
        return Err(Errno::EINVAL);
    }
    let (mut prot, mut access) = if flag & SHM_RDONLY != 0 {
        (Prot::READ, 0o444)
    } else {
        (Prot::READ.union(Prot::WRITE), 0o666)
    };
    if flag & SHM_EXEC != 0 {
        prot = prot.union(Prot::EXEC);
        access |= 0o111;
    }
    let (attachment, size) = {
        let owner = ipc::capable(c, CAP_IPC_OWNER);
        let shm = segments(c);
        let mut table = shm.lock();
        let segment = table.checked(id)?;
        if !segment
            .perm
            .permitted(&c.process.credentials, access, owner)
        {
            return Err(Errno::EACCES);
        }
        let attachment = Arc::new(Attachment {
            id: segment.id,
            size: segment.size,
            file_size: Arc::new(FileSize::new(segment.size)),
            name: Arc::clone(&segment.name),
            table: Arc::downgrade(&shm.0),
        });
        segment
            .attachments
            .retain(|attachment| attachment.strong_count() > 0);
        segment.attachments.push(Arc::downgrade(&attachment));
        let memory = segment.memory.with_source(attachment.clone());
        ((attachment, memory), segment.size)
    };
    let (attachment, memory) = attachment;
    let len = size.div_ceil(PAGE) * PAGE;
    if fixed && addr != 0 && flag & SHM_REMAP == 0 {
        let end = addr.checked_add(size).ok_or(Errno::EINVAL)?;
        if c.mem.mappings().any(|m| m.start.0 < end && m.end() > addr) {
            return Err(Errno::EINVAL);
        }
    }
    let prot = crate::syscalls::read_implies_exec(c.process, prot);
    // The space's VMAs of segments are opened and closed by this process
    // from now on, even those `SHM_REMAP` replaces.
    act(c.mem, &c.pid_space(), c.process.pid, c.shared_host);
    let placement = if fixed {
        if addr
            .checked_add(len)
            .is_none_or(|end| end > USER_ADDRESS_LIMIT - PAGE)
        {
            return Err(ENOMEM);
        }
        Placement::Replacing(GuestAddr(addr))
    } else {
        Placement::Near(None)
    };
    // The mapping and the segment go in under one hold of the address
    // space's lock, so that no other thread sees the mapping without the
    // segment, or maps the range in between.
    let at = c.mem.map_backed(
        placement,
        len,
        prot,
        MappingKind::File,
        Backing::Shared {
            pages: &memory,
            offset: 0,
            writes: if flag & SHM_RDONLY == 0 {
                paludarium_mmu::SharedWrites::Allowed
            } else {
                paludarium_mmu::SharedWrites::ReadOnly
            },
        },
    )?;
    // A new VMA is soft-dirty, and so is one it merged with, as `do_mmap`
    // makes them (`__mmap_complete`).
    c.mem
        .mapped(at, at.0.saturating_add(len.next_multiple_of(4096)));
    c.group.numa().forget(at.0, len);
    drop(memory);
    let shm = segments(c);
    let mut table = shm.lock();
    if let Ok(segment) = table.checked(attachment.id) {
        segment.atime = ipc::now(c);
        segment.lpid = c.pid_space().keep(c.process.pid);
    }
    drop(table);
    drop(attachment);
    Ok(at.0)
}

/// `shmdt(shmaddr)`, as Linux's: the first attachment from `shmaddr` on
/// whose start lies as far from it as the start's offset in the segment
/// (`EINVAL` for none), and then the pieces of the same attachment within
/// the segment's size of `shmaddr` that lie so too, which `munmap` and
/// `mprotect` left.
pub(crate) fn sys_shmdt(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    result(shmdt(c, a[0]))
}

fn shmdt(c: &Context<'_>, addr: u64) -> Result<u64, Errno> {
    if !addr.is_multiple_of(PAGE) {
        return Err(Errno::EINVAL);
    }
    // The segments' attachments, by open file, with the segment's size.
    let attachments: BTreeMap<usize, u64> = segments(c)
        .lock()
        .segments
        .values()
        .flat_map(|segment| {
            segment
                .attachments
                .iter()
                .filter(|attachment| attachment.strong_count() > 0)
                .map(|attachment| (attachment.as_ptr().addr(), segment.size))
        })
        .collect();
    let fragments = c.mem.shared_fragments();
    let lies = |start: u64, offset: u64| start.wrapping_sub(addr) / PAGE == offset / PAGE;
    let mut rest = fragments.iter().skip_while(|f| f.end <= addr);
    let mut found = None;
    // A sealed piece stays (Linux ignores `do_vmi_align_munmap`'s EPERM);
    // the others close, which stamps the segment ([`Attachment::touched`]).
    let unmap = |f: &paludarium_mmu::SharedFragment| {
        if c.mem
            .unmap_shared(GuestAddr(f.start), f.end - f.start)
            .is_ok()
        {
            c.group.numa().forget(f.start, f.end - f.start);
        }
    };
    for f in rest.by_ref() {
        if let Some(&size) = attachments.get(&f.open_file)
            && lies(f.start, f.offset)
        {
            // Linux bounds the pieces by the size rounded up to a page
            // (`size = PAGE_ALIGN(size)` before its second loop).
            found = Some((f.open_file, size.div_ceil(PAGE) * PAGE));
            unmap(f);
            break;
        }
    }
    let Some((file, size)) = found else {
        return Err(Errno::EINVAL);
    };
    for f in rest.take_while(|f| f.end - addr <= size) {
        if f.open_file == file && lies(f.start, f.offset) {
            unmap(f);
        }
    }
    Ok(0)
}

/// `shmctl(shmid, cmd, buf)`, as Linux's on x86-64 (where `cmd` has no
/// `IPC_64`).
pub(crate) fn sys_shmctl(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    result(shmctl(c, a[0] as i32, a[1] as i32, a[2]))
}

fn shmctl(c: &Context<'_>, id: i32, cmd: i32, buf: u64) -> Result<u64, Errno> {
    if cmd < 0 || id < 0 {
        return Err(Errno::EINVAL);
    }
    let write = |bytes: &[u8]| {
        c.mem
            .write(GuestAddr(buf), bytes)
            .map_err(|_| Errno::EFAULT)
    };
    match cmd {
        // `struct shminfo64`, the namespace's limits, `shmseg` its
        // `shmmni` too, and the highest index in use.
        IPC_INFO => {
            let (max, limits) = {
                let shm = segments(c);
                let table = shm.lock();
                (ipc::max_index(&table.segments), table.limits)
            };
            let mni = limits.mni as i64 as u64;
            let mut info = [0u8; 72];
            for (n, value) in [limits.max, SHMMIN, mni, mni, limits.all]
                .into_iter()
                .enumerate()
            {
                info[n * 8..n * 8 + 8].copy_from_slice(&value.to_le_bytes());
            }
            write(&info)?;
            Ok(max)
        }
        // `struct shm_info`, and the highest index in use.
        SHM_INFO => {
            let (max, used, total, resident) = {
                let shm = segments(c);
                let table = shm.lock();
                let resident = table
                    .segments
                    .values()
                    .map(|s| s.memory.resident())
                    .sum::<u64>();
                (
                    ipc::max_index(&table.segments),
                    table.segments.len() as u32,
                    table.pages,
                    resident,
                )
            };
            let mut info = [0u8; 48];
            info[..4].copy_from_slice(&used.to_le_bytes());
            info[8..16].copy_from_slice(&total.to_le_bytes());
            info[16..24].copy_from_slice(&resident.to_le_bytes());
            write(&info)?;
            Ok(max)
        }
        IPC_STAT | SHM_STAT | SHM_STAT_ANY => {
            let (ds, returned) = {
                let shm = segments(c);
                let mut table = shm.lock();
                let segment = if cmd == IPC_STAT {
                    table.checked(id)?
                } else {
                    // An index, of which Linux's `ipc_obtain_object_idr` takes
                    // the low bits (`ipcid_to_idx`), as of an ID.
                    table
                        .segments
                        .get_mut(&ipc::index(id))
                        .ok_or(Errno::EINVAL)?
                };
                if cmd != SHM_STAT_ANY
                    && !segment.perm.permitted(
                        &c.process.credentials,
                        0o444,
                        ipc::capable(c, CAP_IPC_OWNER),
                    )
                {
                    return Err(Errno::EACCES);
                }
                let returned = if cmd == IPC_STAT {
                    0
                } else {
                    u64::from(segment.id as u32)
                };
                (
                    shmid_ds(segment, &c.pid_space(), &c.process.credentials.user),
                    returned,
                )
            };
            write(&ds)?;
            Ok(returned)
        }
        IPC_SET | IPC_RMID => {
            let mut ds = [0u8; 112];
            if cmd == IPC_SET {
                c.mem
                    .read(GuestAddr(buf), &mut ds)
                    .map_err(|_| Errno::EFAULT)?;
            }
            let now = ipc::now(c);
            let admin = ipc::capable(c, CAP_SYS_ADMIN);
            let shm = segments(c);
            let mut table = shm.lock();
            let credentials = &c.process.credentials;
            let segment = table.checked(id)?;
            if !segment.perm.owned_by(credentials) && !admin {
                return Err(Errno::EPERM);
            }
            if cmd == IPC_SET {
                segment.perm.update(&ds, &credentials.user)?;
                segment.ctime = now;
                return Ok(0);
            }
            // Marked for removal while attached, and found by no key; the
            // last detach removes it.
            segment.perm.mode |= SHM_DEST;
            segment.perm.key = IPC_PRIVATE;
            table.purge();
            Ok(0)
        }
        SHM_LOCK | SHM_UNLOCK => lock(c, id, cmd == SHM_LOCK),
        _ => Err(Errno::EINVAL),
    }
}

/// `struct shmid64_ds` of `segment`, as x86-64 lays it out, its PIDs as
/// the caller's PID namespace `space` numbers them (Linux's `pid_vnr`).
/// Its owners as the caller's user namespace `user` shows them.
fn shmid_ds(
    segment: &Segment,
    space: &crate::namespaces::Namespace,
    user: &crate::namespaces::Namespace,
) -> [u8; 112] {
    let mut ds = [0u8; 112];
    segment.perm.put(&mut ds, segment.id, user);
    let mut put = |at: usize, bytes: &[u8]| ds[at..at + bytes.len()].copy_from_slice(bytes);
    put(48, &segment.size.to_le_bytes());
    put(56, &segment.atime.to_le_bytes());
    put(64, &segment.dtime.to_le_bytes());
    put(72, &segment.ctime.to_le_bytes());
    put(80, &space.number_of(&segment.cpid).to_le_bytes());
    put(84, &space.number_of(&segment.lpid).to_le_bytes());
    put(88, &segment.attached().to_le_bytes());
    ds
}

/// `/proc/sysvipc/shm`, as Linux's `sysvipc_shm_proc_show` prints it on a
/// 64-bit kernel: its header, then each segment of the opener's IPC
/// namespace by index, as it is when the read reaches it
/// ([`crate::seq`]), its processes as the opener's PID namespace numbers
/// them and its owners as the opener's user namespace shows them, with the
/// bytes of its pages in memory and none swapped.
pub(crate) fn proc_file(c: &Context<'_>, flags: u32) -> crate::seq::SeqFile {
    let records = ProcRecords {
        shm: segments(c),
        space: c.pid_space(),
        user: c.process.credentials.user.clone(),
    };
    crate::seq::SeqFile::open(Box::new(records), flags)
}
/// What `/proc/sysvipc/shm` shows, as Linux's `ipc_proc_iter` holds it
/// from the open: the segments of an IPC namespace, and the PID and user
/// namespaces they are shown in.
struct ProcRecords {
    shm: Segments,
    space: std::sync::Arc<crate::namespaces::Namespace>,
    user: crate::users::UserNs,
}
impl crate::seq::Records for ProcRecords {
    fn record(&self, index: u64) -> Option<(Vec<u8>, u64)> {
        const HEADER: &str = "       key      shmid perms                  size  cpid  lpid nattch   uid   gid  cuid  cgid      atime      dtime      ctime                   rss                  swap\n";
        let (space, user) = (&self.space, &self.user);
        let (kind, group) = (crate::users::Ids::User, crate::users::Ids::Group);
        let table = self.shm.lock();
        ipc::proc_record(&table.segments, HEADER, index, |s| {
            let perm = &s.perm;
            format!(
                "{:10} {:10}  {:4o} {:21} {:5} {:5}  {:5} {:5} {:5} {:5} {:5} {:10} {:10} {:10} {:21} {:21}\n",
                perm.key,
                s.id,
                perm.mode,
                s.size,
                space.number_of(&s.cpid),
                space.number_of(&s.lpid),
                s.attached(),
                user.shown(kind, perm.uid),
                user.shown(group, perm.gid),
                user.shown(kind, perm.cuid),
                user.shown(group, perm.cgid),
                s.atime,
                s.dtime,
                s.ctime,
                s.memory.resident() * PAGE,
                0,
            )
        })
    }
}

/// `SHM_LOCK` and `SHM_UNLOCK`, as Linux's `shmctl_do_lock`: without
/// `CAP_IPC_LOCK` only for the segment's owner or creator, and a lock
/// needs a `RLIMIT_MEMLOCK` (`EPERM`) with room for the segment among
/// those the real user locked (`ENOMEM`). Nothing is ever swapped out, so
/// a lock changes nothing else.
fn lock(c: &Context<'_>, id: i32, lock: bool) -> Result<u64, Errno> {
    let credentials = &c.process.credentials;
    let capable = ipc::capable(c, CAP_IPC_LOCK);
    let limit = c.processes.soft_limit(c.process.pid, RLIMIT_MEMLOCK);
    let shm = segments(c);
    let mut table = shm.lock();
    let locked_by_user: u64 = table
        .segments
        .values()
        .filter(|segment| segment.locker == Some(credentials.uid))
        .map(Segment::pages)
        .sum();
    let segment = table.checked(id)?;
    if !capable {
        if !segment.perm.owned_by(credentials) {
            return Err(Errno::EPERM);
        }
        if lock && limit == 0 {
            return Err(Errno::EPERM);
        }
    }
    if lock {
        if segment.perm.mode & SHM_LOCKED != 0 {
            return Ok(0);
        }
        let limit = if limit == u64::MAX {
            limit
        } else {
            limit / PAGE
        };
        if locked_by_user + segment.pages() > limit && !capable {
            return Err(ENOMEM);
        }
        segment.perm.mode |= SHM_LOCKED;
        segment.locker = Some(credentials.uid);
    } else if segment.perm.mode & SHM_LOCKED != 0 {
        segment.perm.mode &= !SHM_LOCKED;
        segment.locker = None;
    }
    Ok(0)
}
