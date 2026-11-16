//! System V semaphores: `semget`, `semop`, `semtimedop` and `semctl`, in
//! the calling thread's IPC namespace, as Linux's `ipc/sem.c` has them.
//!
//! An operation that cannot go through waits in one of its set's queues,
//! which are Linux's: each semaphore's for the operations on it alone, and
//! the set's for those on several ([`Queues`]). Whatever changes a set's
//! values then tries them, as Linux's `do_smart_update`: the waits for zero
//! on the semaphores it made 0, then the waits to change values. An
//! operation done for a waiting thread is done as that thread's: with its
//! process ID and its undo list.
//!
//! An undo list (Linux's `sem_undo_list`) is a process's, which
//! `CLONE_SYSVSEM` shares. Each set keeps the adjustments of every list
//! that has `SEM_UNDO` operations on it, which `SETVAL` and `SETALL` clear
//! and `IPC_RMID` takes away. When the last thread that shares a list ends,
//! or leaves it with `unshare` or `setns`, the adjustments are added to the
//! values, cut to 0 and `SEMVMX` (`exit_sem`).
use crate::ipc::{
    self, CAP_IPC_OWNER, CAP_SYS_ADMIN, IPC_CREAT, IPC_EXCL, IPC_INFO, IPC_NOWAIT, IPC_PRIVATE,
    IPC_RMID, IPC_SET, IPC_STAT, Perm,
};
use crate::namespaces::KeptPid;
use crate::syscalls::{Context, Outcome};
use paludarium_host::{ClockId, WaitOutcome, WaitToken};
use paludarium_types::{Errno, GuestAddr};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicI64, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};

const SEM_UNDO: i16 = 0x1000;

const E2BIG: Errno = Errno(7);
const EFBIG: Errno = Errno(27);
const EIDRM: Errno = Errno(43);

const GETPID: i32 = 11;
const GETVAL: i32 = 12;
const GETALL: i32 = 13;
const GETNCNT: i32 = 14;
const GETZCNT: i32 = 15;
const SETVAL: i32 = 16;
const SETALL: i32 = 17;
const SEM_STAT: i32 = 18;
const SEM_INFO: i32 = 19;
const SEM_STAT_ANY: i32 = 20;

/// Linux's defaults of `kernel.sem` (`SEMMSL`, `SEMMNS`, `SEMOPM` and
/// `SEMMNI`), which each IPC namespace starts with ([`Limits`]), and the
/// limits that are fixed.
const SEMMSL: i32 = 32000;
const SEMMNI: usize = 32000;
const SEMMNS: u64 = SEMMSL as u64 * SEMMNI as u64;
const SEMOPM: u32 = 500;
const SEMVMX: i32 = 32767;
const SEMAEM: i32 = SEMVMX;
const SEMUME: i32 = SEMOPM as i32;
const SEMMNU: i32 = SEMMNS as i32;
const SEMMAP: i32 = SEMMNS as i32;
const SEMUSZ: i32 = 20;

/// `struct semid64_ds`'s size on x86-64.
const DS_SIZE: usize = 104;

/// The sets of an IPC namespace.
#[derive(Clone, Default)]
pub(crate) struct Sets(Arc<Mutex<Table>>);

impl std::fmt::Debug for Sets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Sets")
    }
}

impl Sets {
    fn lock(&self) -> MutexGuard<'_, Table> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
    /// Its limits, which `/proc/sys/kernel/sem` reads and sets
    /// ([`crate::sysctl`]).
    pub(crate) fn with_limits<R>(&self, f: impl FnOnce(&mut Limits) -> R) -> R {
        f(&mut self.lock().limits)
    }
    /// Its IDs, whose next one `/proc/sys/kernel` reads and sets
    /// ([`crate::sysctl`]).
    pub(crate) fn with_ids<R>(&self, f: impl FnOnce(&mut ipc::Ids) -> R) -> R {
        f(&mut self.lock().ids)
    }
}

/// An IPC namespace's `kernel.sem`, in its order: `semmsl`, `semmns`,
/// `semopm` and `semmni` (Linux's `sem_ctls`), which a new one has at
/// Linux's defaults (`sem_init_ns`). Only `semmni` is bounded, so the
/// others may be negative.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Limits(pub [i32; 4]);

impl Default for Limits {
    fn default() -> Self {
        Self([SEMMSL, SEMMNS as i32, SEMOPM as i32, SEMMNI as i32])
    }
}

impl Limits {
    fn msl(self) -> i32 {
        self.0[0]
    }
    fn mns(self) -> i32 {
        self.0[1]
    }
    fn opm(self) -> i32 {
        self.0[2]
    }
    fn mni(self) -> i32 {
        self.0[3]
    }
}

#[derive(Default)]
struct Table {
    /// By index.
    sets: BTreeMap<u32, Set>,
    ids: ipc::Ids,
    /// The semaphores of all sets (Linux's `used_sems`).
    used: u64,
    limits: Limits,
}

impl Table {
    /// The set with this ID, `EINVAL` for none (`sem_obtain_object_check`).
    fn checked(&mut self, id: i32) -> Result<&mut Set, Errno> {
        self.sets
            .get_mut(&ipc::index(id))
            .filter(|set| set.id == id)
            .ok_or(Errno::EINVAL)
    }
}

#[derive(Clone, Default)]
struct Semaphore {
    value: i32,
    /// The process that changed it last (`sempid`), kept as Linux keeps
    /// its `struct pid`, so that a PID namespace still numbers it once the
    /// process is reaped.
    pid: KeptPid,
}

/// `struct sembuf`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Op {
    num: u16,
    op: i16,
    flags: i16,
}

/// What a wait is told when its operation is over: [`WAITING`] until
/// then, 0 when it was done, and else its error, negated.
struct Wake {
    status: AtomicI64,
    token: WaitToken,
}
const WAITING: i64 = 1;

impl Wake {
    fn tell(&self, status: i64) {
        self.status.store(status, Ordering::SeqCst);
        self.token.notify();
    }
}

/// An operation waiting in one of a set's queues (`struct sem_queue`).
struct Waiting {
    ops: Vec<Op>,
    /// The undo list it adjusts.
    undo: Option<u64>,
    pid: KeptPid,
    /// Whether it changes a value (any operation not 0).
    alters: bool,
    /// The operation it waits on, which `GETNCNT` and `GETZCNT` count.
    blocking: usize,
    wake: Arc<Wake>,
}

impl Waiting {
    /// Whether it names more than one operation (Linux's complex one).
    fn complex(&self) -> bool {
        self.ops.len() > 1
    }
}

/// A set's waiting operations, in Linux's lists. A simple operation, one
/// that names one semaphore, waits in that semaphore's queue of changes
/// (`pending_alter`) or of waits for zero (`pending_const`); a complex
/// one waits in the set's queue of each kind. While any complex operation
/// waits, the simple changes wait in the set's queue too, which they join
/// in front of the first one (`merge_queues`) and leave once none is left
/// (`unmerge_queues`).
struct Queues {
    /// Each semaphore's simple changes and waits for zero.
    alter: Vec<Vec<Waiting>>,
    zero: Vec<Vec<Waiting>>,
    /// The set's.
    set_alter: Vec<Waiting>,
    set_zero: Vec<Waiting>,
    /// How many complex operations wait (`complex_count`).
    complex: usize,
}

impl Queues {
    fn new(count: usize) -> Self {
        Self {
            alter: (0..count).map(|_| Vec::new()).collect(),
            zero: (0..count).map(|_| Vec::new()).collect(),
            set_alter: Vec::new(),
            set_zero: Vec::new(),
            complex: 0,
        }
    }
    /// Semaphore `n`'s queue, or the set's for `None`, of changes or of
    /// waits for zero.
    fn list(&mut self, n: Option<usize>, zero: bool) -> &mut Vec<Waiting> {
        match (n, zero) {
            (Some(n), false) => &mut self.alter[n],
            (Some(n), true) => &mut self.zero[n],
            (None, false) => &mut self.set_alter,
            (None, true) => &mut self.set_zero,
        }
    }
    fn all(&self) -> impl Iterator<Item = &Waiting> {
        self.alter
            .iter()
            .chain(&self.zero)
            .flatten()
            .chain(&self.set_alter)
            .chain(&self.set_zero)
    }
    #[cfg(test)]
    fn is_empty(&self) -> bool {
        self.all().next().is_none()
    }
    /// Puts a wait at the end of its queue, as `do_semtimedop`.
    fn push(&mut self, waiting: Waiting) {
        if waiting.complex() {
            if self.complex == 0 {
                // Each semaphore's changes go in front of those before,
                // so the last semaphore's come first (`list_splice_init`).
                for alter in &mut self.alter {
                    let mut moved = std::mem::take(alter);
                    moved.append(&mut self.set_alter);
                    self.set_alter = moved;
                }
            }
            self.complex += 1;
            if waiting.alters {
                self.set_alter.push(waiting);
            } else {
                self.set_zero.push(waiting);
            }
        } else {
            let n = usize::from(waiting.ops[0].num);
            if !waiting.alters {
                self.zero[n].push(waiting);
            } else if self.complex > 0 {
                self.set_alter.push(waiting);
            } else {
                self.alter[n].push(waiting);
            }
        }
    }
    /// Takes the wait at `at` out of its queue (`unlink_queue`).
    fn take(&mut self, n: Option<usize>, zero: bool, at: usize) -> Waiting {
        let waiting = self.list(n, zero).remove(at);
        if waiting.complex() {
            self.complex -= 1;
        }
        waiting
    }
    /// Takes the wait that `wake` tells out of its queue, if it is there.
    fn forget(&mut self, wake: &Arc<Wake>) {
        let count = self.alter.len();
        let lists = (0..count)
            .flat_map(|n| [(Some(n), false), (Some(n), true)])
            .chain([(None, false), (None, true)]);
        for (n, zero) in lists {
            if let Some(at) = self
                .list(n, zero)
                .iter()
                .position(|waiting| Arc::ptr_eq(&waiting.wake, wake))
            {
                self.take(n, zero, at);
                return;
            }
        }
    }
    /// Gives the simple changes in the set's queue back to their
    /// semaphores' once no complex operation waits, as Linux does as it
    /// lets go of the set (`unmerge_queues` in `sem_unlock`).
    fn settle(&mut self) {
        if self.complex > 0 {
            return;
        }
        for waiting in std::mem::take(&mut self.set_alter) {
            let n = usize::from(waiting.ops[0].num);
            self.alter[n].push(waiting);
        }
    }
}

/// Tells a wait how its operation went, and whether it was done.
fn tell(waiting: &Waiting, attempt: &Attempt) -> bool {
    match attempt {
        Attempt::Done => {
            waiting.wake.tell(0);
            true
        }
        Attempt::Failed(error) => {
            waiting.wake.tell(-i64::from(error.0));
            false
        }
        Attempt::Blocked(_) => false,
    }
}

struct Set {
    id: i32,
    perm: Perm,
    otime: i64,
    ctime: i64,
    semaphores: Vec<Semaphore>,
    /// The adjustments of each undo list that has any for it, by list.
    undos: BTreeMap<u64, Vec<i32>>,
    queues: Queues,
}

/// How an operation went.
#[derive(Debug, PartialEq, Eq)]
enum Attempt {
    Done,
    /// It waits on the operation at this index.
    Blocked(usize),
    Failed(Errno),
}

/// Does `ops` all at once or none of it, as Linux's
/// `perform_atomic_semop_slow`, which takes them in order: an operation
/// waits while its semaphore is not 0 for a 0, or would go below 0, unless
/// it has `IPC_NOWAIT` (`EAGAIN`); one that would go above `SEMVMX`, or
/// take its adjustment out of the undo range, is `ERANGE`. Done, every
/// semaphore it names was last changed by `pid`.
fn attempt(
    semaphores: &mut [Semaphore],
    undos: &mut BTreeMap<u64, Vec<i32>>,
    ops: &[Op],
    undo: Option<u64>,
    pid: &KeptPid,
) -> Attempt {
    let mut adjust = undo.and_then(|list| undos.get_mut(&list));
    let mut failure = None;
    let mut done = 0;
    for (at, op) in ops.iter().enumerate() {
        let n = usize::from(op.num);
        let current = semaphores[n].value;
        let result = current + i32::from(op.op);
        if op.op == 0 && current != 0 || result < 0 {
            failure = Some(if op.flags & IPC_NOWAIT as i16 != 0 {
                Attempt::Failed(Errno::EAGAIN)
            } else {
                Attempt::Blocked(at)
            });
            break;
        }
        if result > SEMVMX {
            failure = Some(Attempt::Failed(Errno::ERANGE));
            break;
        }
        if op.flags & SEM_UNDO != 0
            && let Some(adjust) = adjust.as_deref_mut()
        {
            let value = adjust[n] - i32::from(op.op);
            if !(-SEMAEM - 1..=SEMAEM).contains(&value) {
                failure = Some(Attempt::Failed(Errno::ERANGE));
                break;
            }
            adjust[n] = value;
        }
        semaphores[n].value = result;
        done = at + 1;
    }
    if let Some(failure) = failure {
        for op in ops[..done].iter().rev() {
            let n = usize::from(op.num);
            semaphores[n].value -= i32::from(op.op);
            if op.flags & SEM_UNDO != 0
                && let Some(adjust) = adjust.as_deref_mut()
            {
                adjust[n] += i32::from(op.op);
            }
        }
        return failure;
    }
    for op in ops {
        semaphores[usize::from(op.num)].pid = pid.clone();
    }
    Attempt::Done
}

impl Set {
    /// Tries the wait at `at` of a queue: one that still waits stays, and
    /// one that is done or fails leaves it, as how it went.
    fn try_wait(&mut self, n: Option<usize>, zero: bool, at: usize) -> (Attempt, Option<Waiting>) {
        let waiting = &mut self.queues.list(n, zero)[at];
        let attempt = attempt(
            &mut self.semaphores,
            &mut self.undos,
            &waiting.ops,
            waiting.undo,
            &waiting.pid,
        );
        if let Attempt::Blocked(blocking) = attempt {
            waiting.blocking = blocking;
            return (attempt, None);
        }
        (attempt, Some(self.queues.take(n, zero, at)))
    }
    /// Tries a queue of waits for zero, each once in order
    /// (`wake_const_ops`). Whether any was done.
    fn wake_zero(&mut self, n: Option<usize>) -> bool {
        let mut completed = false;
        let mut at = 0;
        while at < self.queues.list(n, true).len() {
            match self.try_wait(n, true, at) {
                (_, None) => at += 1,
                (attempt, Some(waiting)) => completed |= tell(&waiting, &attempt),
            }
        }
        completed
    }
    /// Tries the waits for zero on the semaphores that `ops` name, or on
    /// all for `None`, that are 0, then the set's if any was
    /// (`do_smart_wakeup_zero`). Whether any was done.
    fn wake_zeros(&mut self, ops: Option<&[Op]>) -> bool {
        let named: Vec<usize> = match ops {
            Some(ops) => ops.iter().map(|op| usize::from(op.num)).collect(),
            None => (0..self.semaphores.len()).collect(),
        };
        let mut completed = false;
        let mut got_zero = false;
        for n in named {
            if self.semaphores[n].value == 0 {
                got_zero = true;
                completed |= self.wake_zero(Some(n));
            }
        }
        if got_zero {
            completed |= self.wake_zero(None);
        }
        completed
    }
    /// Tries a queue of changes in order (`update_queue`): after each one
    /// done, the waits for zero on what it named, and the queue again
    /// from its start if it was complex or the set's queue of changes has
    /// any. A semaphore's queue stops once its value is 0, as it holds
    /// only decreases. Whether any was done.
    fn update_queue(&mut self, n: Option<usize>) -> bool {
        let mut completed = false;
        let mut at = 0;
        while at < self.queues.list(n, false).len() {
            if n.is_some_and(|n| self.semaphores[n].value == 0) {
                break;
            }
            match self.try_wait(n, false, at) {
                (_, None) => at += 1,
                (attempt, Some(waiting)) => {
                    if tell(&waiting, &attempt) {
                        completed = true;
                        self.wake_zeros(Some(&waiting.ops));
                        if !self.queues.set_alter.is_empty() || waiting.complex() {
                            at = 0;
                        }
                    }
                }
            }
        }
        completed
    }
    /// Tries the waits after a change of the semaphores that `ops` name,
    /// or of any for `None`, at `now`, as Linux's `do_smart_update`: the
    /// waits for zero on those that are 0, then the set's queue of changes
    /// if it has any, else the queues of those that `ops` increase (or of
    /// all). The set's `sem_otime` is `now` if `otime`, or if any was done.
    /// Whether any was.
    fn update(&mut self, ops: Option<&[Op]>, otime: bool, now: i64) -> bool {
        let mut completed = self.wake_zeros(ops);
        if !self.queues.set_alter.is_empty() {
            completed |= self.update_queue(None);
        } else if let Some(ops) = ops {
            for op in ops {
                if op.op > 0 {
                    completed |= self.update_queue(Some(usize::from(op.num)));
                }
            }
        } else {
            for n in 0..self.semaphores.len() {
                completed |= self.update_queue(Some(n));
            }
        }
        if otime || completed {
            self.otime = now;
        }
        self.queues.settle();
        completed
    }
    /// How many waits wait on semaphore `n` going to 0 (`zero`) or up,
    /// as Linux's `count_semcnt` counts them by the operation each waits on.
    fn waiting_on(&self, n: usize, zero: bool) -> u64 {
        self.queues
            .all()
            .filter(|waiting| {
                let op = waiting.ops[waiting.blocking];
                usize::from(op.num) == n && if zero { op.op == 0 } else { op.op < 0 }
            })
            .count() as u64
    }
    /// Tells every wait it is removed (`freeary`).
    fn remove(self) {
        for waiting in self.queues.all() {
            waiting.wake.tell(-i64::from(EIDRM.0));
        }
    }
}

/// A process's undo list (`struct sem_undo_list`): the sets it has
/// adjustments in, which those sets keep under its number.
pub(crate) struct UndoList {
    number: u64,
    /// The threads that share it.
    users: AtomicUsize,
    sets: Mutex<Vec<(Weak<Mutex<Table>>, i32)>>,
}

static UNDO_LISTS: AtomicU64 = AtomicU64::new(1);

impl UndoList {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            number: UNDO_LISTS.fetch_add(1, Ordering::Relaxed),
            users: AtomicUsize::new(1),
            sets: Mutex::default(),
        })
    }
    /// The same list for one more thread (`copy_semundo` with
    /// `CLONE_SYSVSEM`).
    pub fn share(self: &Arc<Self>) -> Arc<Self> {
        self.users.fetch_add(1, Ordering::SeqCst);
        Arc::clone(self)
    }
    /// One thread of process `pid` leaves it, at `now` (`exit_sem`): the
    /// last one adds each set's adjustments to its values, cut to 0 and
    /// `SEMVMX`, as `pid`, and wakes those its change lets through.
    pub(crate) fn leave(&self, pid: &KeptPid, now: i64) {
        if self.users.fetch_sub(1, Ordering::SeqCst) != 1 {
            return;
        }
        let sets = std::mem::take(&mut *self.sets.lock().unwrap_or_else(PoisonError::into_inner));
        for (table, id) in sets {
            let Some(table) = table.upgrade() else {
                continue;
            };
            let mut table = table.lock().unwrap_or_else(PoisonError::into_inner);
            let Ok(set) = table.checked(id) else {
                continue;
            };
            let Some(adjustments) = set.undos.remove(&self.number) else {
                continue;
            };
            for (semaphore, adjustment) in set.semaphores.iter_mut().zip(adjustments) {
                if adjustment != 0 {
                    semaphore.value = (semaphore.value + adjustment).clamp(0, SEMVMX);
                    semaphore.pid = pid.clone();
                }
            }
            set.update(None, true, now);
        }
    }
    /// Keeps adjustments in `set` of `table`, from 0 (`find_alloc_undo`).
    fn join(&self, table: &Arc<Mutex<Table>>, set: &mut Set) {
        if set.undos.contains_key(&self.number) {
            return;
        }
        set.undos.insert(self.number, vec![0; set.semaphores.len()]);
        let mut sets = self.sets.lock().unwrap_or_else(PoisonError::into_inner);
        sets.retain(|(table, _)| table.strong_count() > 0);
        sets.push((Arc::downgrade(table), set.id));
    }
}

/// The sets of the calling thread's IPC namespace.
fn sets(c: &Context<'_>) -> Sets {
    c.group.namespaces(c.tid).ipc.sem.clone()
}

fn result(value: Result<u64, Errno>) -> Outcome {
    Outcome::Return(value.unwrap_or_else(Errno::to_syscall_return))
}

/// `semget(key, nsems, semflg)`, as Linux's `ksys_semget` and `ipcget`: a
/// count above `semmsl` or below 0 is `EINVAL`; a key in use gives its set
/// unless `IPC_CREAT | IPC_EXCL` (`EEXIST`), the count is more than it has
/// (`EINVAL`) or the permissions asked for are not granted (`EACCES`); a
/// key not in use is `ENOENT` without `IPC_CREAT`. A new set's checks are
/// its count (`EINVAL` for 0), the semaphores of all sets against `semmns`
/// (`ENOSPC`) and the number of sets against `semmni` (`ENOSPC`), the
/// limits of `kernel.sem`.
pub(crate) fn sys_semget(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    result(semget(c, a[0] as i32, a[1] as i32, a[2] as i32))
}

fn semget(c: &Context<'_>, key: i32, count: i32, flag: i32) -> Result<u64, Errno> {
    let sets = sets(c);
    let mut table = sets.lock();
    let limits = table.limits;
    if count < 0 || count > limits.msl() {
        return Err(Errno::EINVAL);
    }
    let credentials = &c.process.credentials;
    let owner = ipc::capable(c, CAP_IPC_OWNER);
    if key != IPC_PRIVATE {
        if let Some(set) = table.sets.values().find(|set| set.perm.key == key) {
            if flag & IPC_CREAT != 0 && flag & IPC_EXCL != 0 {
                return Err(Errno::EEXIST);
            }
            if count as usize > set.semaphores.len() {
                return Err(Errno::EINVAL);
            }
            if !set.perm.permitted(credentials, flag as u32, owner) {
                return Err(Errno::EACCES);
            }
            return Ok(u64::from(set.id as u32));
        }
        if flag & IPC_CREAT == 0 {
            return Err(Errno::ENOENT);
        }
    }
    if count == 0 {
        return Err(Errno::EINVAL);
    }
    if table.used as i64 + i64::from(count) > i64::from(limits.mns()) {
        return Err(Errno::ENOSPC);
    }
    let table = &mut *table;
    let id = table
        .ids
        .allocate(&table.sets, limits.mni().max(0) as usize)?;
    table.sets.insert(
        ipc::index(id),
        Set {
            id,
            perm: Perm::new(key, credentials, flag),
            otime: 0,
            ctime: ipc::now(c),
            semaphores: vec![Semaphore::default(); count as usize],
            undos: BTreeMap::new(),
            queues: Queues::new(count as usize),
        },
    );
    table.used += count as u64;
    Ok(u64::from(id as u32))
}

/// `semop(semid, sops, nsops)`: `semtimedop` without a timeout.
pub(crate) fn sys_semop(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    result(semtimedop(c, a[0] as i32, a[1], a[2] as u32, None))
}

/// `semtimedop(semid, sops, nsops, timeout)`: the timeout is read first
/// (`EFAULT`), as Linux's `ksys_semtimedop` does.
pub(crate) fn sys_semtimedop(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    let timeout = if a[3] == 0 {
        None
    } else {
        let mut b = [0u8; 16];
        if c.mem.read(GuestAddr(a[3]), &mut b).is_err() {
            return result(Err(Errno::EFAULT));
        }
        let word = |at: usize| i64::from_le_bytes(b[at..at + 8].try_into().unwrap_or_default());
        Some((word(0), word(8)))
    };
    result(semtimedop(c, a[0] as i32, a[1], a[2] as u32, timeout))
}

/// The operations at `at`, in Linux's order (`do_semtimedop` and
/// `__do_semtimedop`): more than `semopm` of `kernel.sem` is `E2BIG`
/// (compared unsigned, so a negative one bounds nothing) and none `EINVAL`,
/// then the operations are read (`EFAULT`); a negative ID or an invalid
/// timeout is `EINVAL`; then the set (`EINVAL`), a semaphore number beyond
/// it (`EFBIG`) and the permission to change it, or to read it when no
/// operation changes a value (`EACCES`). An operation that cannot go
/// through at once waits, unless the one it would wait on has
/// `IPC_NOWAIT` (`EAGAIN`), until it is done, the set is removed
/// (`EIDRM`), a signal comes (`EINTR`, never restarted) or the timeout
/// passes (`EAGAIN`).
fn semtimedop(
    c: &mut Context<'_>,
    id: i32,
    at: u64,
    count: u32,
    timeout: Option<(i64, i64)>,
) -> Result<u64, Errno> {
    if count > sets(c).lock().limits.opm() as u32 {
        return Err(E2BIG);
    }
    if count < 1 {
        return Err(Errno::EINVAL);
    }
    let mut bytes = vec![0u8; count as usize * 6];
    c.mem
        .read(GuestAddr(at), &mut bytes)
        .map_err(|_| Errno::EFAULT)?;
    let ops: Vec<Op> = bytes
        .as_chunks::<6>()
        .0
        .iter()
        .map(|b| Op {
            num: u16::from_le_bytes([b[0], b[1]]),
            op: i16::from_le_bytes([b[2], b[3]]),
            flags: i16::from_le_bytes([b[4], b[5]]),
        })
        .collect();
    if id < 0 {
        return Err(Errno::EINVAL);
    }
    let deadline = match timeout {
        None => None,
        Some((seconds, nanos)) => {
            if seconds < 0 || !(0..1_000_000_000).contains(&nanos) {
                return Err(Errno::EINVAL);
            }
            let length = (seconds as u64)
                .saturating_mul(1_000_000_000)
                .saturating_add(nanos as u64);
            Some(c.host.clock(ClockId::Monotonic)?.saturating_add(length))
        }
    };
    let max = ops.iter().map(|op| op.num).max().unwrap_or(0);
    let undoes = ops.iter().any(|op| op.flags & SEM_UNDO != 0);
    let alters = ops.iter().any(|op| op.op != 0);
    let undo = undoes.then(|| c.group.sem_undo_list(c.tid));
    let owner = ipc::capable(c, CAP_IPC_OWNER);
    let now = ipc::now(c);
    let pid = c.pid_space().keep(c.process.pid);
    let sets = sets(c);
    let wake = {
        let mut table = sets.lock();
        let set = table.checked(id)?;
        if usize::from(max) >= set.semaphores.len() {
            return Err(EFBIG);
        }
        let access = if alters { 0o222 } else { 0o444 };
        if !set.perm.permitted(&c.process.credentials, access, owner) {
            return Err(Errno::EACCES);
        }
        if let Some(list) = &undo {
            list.join(&sets.0, set);
        }
        let number = undo.as_ref().map(|list| list.number);
        match attempt(&mut set.semaphores, &mut set.undos, &ops, number, &pid) {
            Attempt::Done => {
                if alters {
                    set.update(Some(&ops), true, now);
                } else {
                    set.otime = now;
                }
                return Ok(0);
            }
            Attempt::Failed(error) => return Err(error),
            Attempt::Blocked(blocking) => {
                let wake = Arc::new(Wake {
                    status: AtomicI64::new(WAITING),
                    token: WaitToken::default(),
                });
                set.queues.push(Waiting {
                    ops,
                    undo: number,
                    pid,
                    alters,
                    blocking,
                    wake: Arc::clone(&wake),
                });
                wake
            }
        }
    };
    wait(c, &sets, id, &wake, deadline)
}

/// Waits until `wake` is told, or else ends the wait with `EINTR` for a
/// signal or the end of the thread group, or `EAGAIN` at `deadline`, as
/// Linux's loop in `__do_semtimedop`: an operation done or failed for it
/// meanwhile is its result all the same.
fn wait(
    c: &mut Context<'_>,
    sets: &Sets,
    id: i32,
    wake: &Arc<Wake>,
    deadline: Option<u64>,
) -> Result<u64, Errno> {
    let told = |status: i64| {
        if status == 0 {
            Ok(0)
        } else {
            Err(Errno((-status) as i32))
        }
    };
    let leave = |error: Errno| {
        let mut table = sets.lock();
        let status = wake.status.load(Ordering::SeqCst);
        if status != WAITING {
            return told(status);
        }
        if let Ok(set) = table.checked(id) {
            set.queues.forget(wake);
            set.queues.settle();
        }
        Err(error)
    };
    let mut interrupted = false;
    loop {
        let ticket = wake.token.value();
        let status = wake.status.load(Ordering::SeqCst);
        if status != WAITING {
            return told(status);
        }
        c.group.drain_process(c.process);
        interrupted |= c.inbox.drain(c.process).interrupted;
        interrupted |= !c.inbox.owns_wake(c.cancellation) && c.cancellation.load(Ordering::SeqCst);
        let now = match c.host.clock(ClockId::Monotonic) {
            Ok(now) => now,
            Err(error) => return leave(error),
        };
        c.group.expire_timer(c.process, now);
        if c.group.status().is_some()
            || crate::signals::next_pending(c.process, true).is_some()
            || interrupted
        {
            return leave(Errno(4));
        }
        if deadline.is_some_and(|end| now >= end) {
            return leave(Errno::EAGAIN);
        }
        let end = deadline
            .unwrap_or(u64::MAX)
            .min(now.saturating_add(10_000_000))
            .min(crate::signals::next_deadline(c.process).unwrap_or(u64::MAX));
        let outcome = match c.host.wait_on(
            &wake.token,
            ticket,
            Some((ClockId::Monotonic, end)),
            c.cancellation,
        ) {
            Err(error) if error == Errno::ENOSYS => {
                c.host.wait_until(ClockId::Monotonic, end, c.cancellation)
            }
            outcome => outcome,
        };
        match outcome {
            Ok(WaitOutcome::Interrupted) => {
                interrupted |= c.inbox.drain(c.process).interrupted;
            }
            Ok(_) => {}
            Err(error) => return leave(error),
        }
    }
}

/// `semctl(semid, semnum, cmd, arg)`, as Linux's `ksys_semctl` on x86-64
/// (where `cmd` has no `IPC_64`).
pub(crate) fn sys_semctl(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    result(semctl(c, a[0] as i32, a[1] as i32, a[2] as i32, a[3]))
}

fn semctl(c: &Context<'_>, id: i32, n: i32, cmd: i32, arg: u64) -> Result<u64, Errno> {
    if id < 0 {
        return Err(Errno::EINVAL);
    }
    let write = |bytes: &[u8]| {
        c.mem
            .write(GuestAddr(arg), bytes)
            .map_err(|_| Errno::EFAULT)
    };
    match cmd {
        IPC_INFO | SEM_INFO => {
            let (max, sets_in_use, used, limits) = {
                let sets = sets(c);
                let table = sets.lock();
                (
                    ipc::max_index(&table.sets),
                    table.sets.len() as i32,
                    table.used as i32,
                    table.limits,
                )
            };
            let (usz, aem) = if cmd == SEM_INFO {
                (sets_in_use, used)
            } else {
                (SEMUSZ, SEMAEM)
            };
            // `struct seminfo`.
            let info = [
                SEMMAP,
                limits.mni(),
                limits.mns(),
                SEMMNU,
                limits.msl(),
                limits.opm(),
                SEMUME,
                usz,
                SEMVMX,
                aem,
            ];
            let bytes: Vec<u8> = info.iter().flat_map(|v| v.to_le_bytes()).collect();
            write(&bytes)?;
            Ok(max)
        }
        IPC_STAT | SEM_STAT | SEM_STAT_ANY => {
            let (ds, returned) = {
                let sets = sets(c);
                let mut table = sets.lock();
                let set = if cmd == IPC_STAT {
                    table.checked(id)?
                } else {
                    // An index, as of an ID (`sem_obtain_object`).
                    table.sets.get_mut(&ipc::index(id)).ok_or(Errno::EINVAL)?
                };
                if cmd != SEM_STAT_ANY
                    && !set.perm.permitted(
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
                    u64::from(set.id as u32)
                };
                (semid_ds(set, &c.process.credentials.user), returned)
            };
            write(&ds)?;
            Ok(returned)
        }
        GETALL | GETVAL | GETPID | GETNCNT | GETZCNT | SETALL => main(c, id, n, cmd, arg),
        SETVAL => setval(c, id, n, arg as i32),
        IPC_SET | IPC_RMID => {
            let mut ds = [0u8; DS_SIZE];
            if cmd == IPC_SET {
                c.mem
                    .read(GuestAddr(arg), &mut ds)
                    .map_err(|_| Errno::EFAULT)?;
            }
            let now = ipc::now(c);
            let admin = ipc::capable(c, CAP_SYS_ADMIN);
            let sets = sets(c);
            let mut table = sets.lock();
            let credentials = &c.process.credentials;
            let set = table.checked(id)?;
            if !set.perm.owned_by(credentials) && !admin {
                return Err(Errno::EPERM);
            }
            if cmd == IPC_SET {
                set.perm.update(&ds, &credentials.user)?;
                set.ctime = now;
                return Ok(0);
            }
            if let Some(set) = table.sets.remove(&ipc::index(id)) {
                table.used -= set.semaphores.len() as u64;
                set.remove();
            }
            Ok(0)
        }
        _ => Err(Errno::EINVAL),
    }
}

/// `struct semid64_ds` of `set`, as x86-64 lays it out, its owners as the
/// caller's user namespace `user` shows them.
fn semid_ds(set: &Set, user: &crate::namespaces::Namespace) -> [u8; DS_SIZE] {
    let mut ds = [0u8; DS_SIZE];
    set.perm.put(&mut ds, set.id, user);
    ds[48..56].copy_from_slice(&set.otime.to_le_bytes());
    ds[64..72].copy_from_slice(&set.ctime.to_le_bytes());
    ds[80..88].copy_from_slice(&(set.semaphores.len() as u64).to_le_bytes());
    ds
}

/// `/proc/sysvipc/sem`, as Linux's `sysvipc_sem_proc_show` prints it: its
/// header, then each set of the caller's IPC namespace by index, its owners
/// as the caller's user namespace shows them.
pub(crate) fn proc_file(c: &Context<'_>) -> Vec<u8> {
    let mut out = String::from(
        "       key      semid perms      nsems   uid   gid  cuid  cgid      otime      ctime\n",
    );
    let user = &c.process.credentials.user;
    let (kind, group) = (crate::users::Ids::User, crate::users::Ids::Group);
    let sets = sets(c);
    for set in sets.lock().sets.values() {
        let perm = &set.perm;
        out.push_str(&format!(
            "{:10} {:10}  {:4o} {:10} {:5} {:5} {:5} {:5} {:10} {:10}\n",
            perm.key,
            set.id,
            perm.mode,
            set.semaphores.len(),
            user.shown(kind, perm.uid),
            user.shown(group, perm.gid),
            user.shown(kind, perm.cuid),
            user.shown(group, perm.cgid),
            set.otime,
            set.ctime,
        ));
    }
    out.into_bytes()
}

/// The commands of Linux's `semctl_main`, in its order: the set
/// (`EINVAL`) and the permission to read it, or to change it for `SETALL`
/// (`EACCES`). `GETALL` writes every value (`EFAULT`); `SETALL` reads them
/// (`EFAULT`), and any above `SEMVMX` is `ERANGE`, before it sets them,
/// clears their adjustments and lets waits through. The others need a
/// semaphore of the set (`EINVAL`); `GETPID` gives its process as the
/// caller's PID namespace numbers it.
fn main(c: &Context<'_>, id: i32, n: i32, cmd: i32, arg: u64) -> Result<u64, Errno> {
    let owner = ipc::capable(c, CAP_IPC_OWNER);
    let access = if cmd == SETALL { 0o222 } else { 0o444 };
    let now = ipc::now(c);
    let sets = sets(c);
    let count = {
        let mut table = sets.lock();
        let set = table.checked(id)?;
        if !set.perm.permitted(&c.process.credentials, access, owner) {
            return Err(Errno::EACCES);
        }
        set.semaphores.len()
    };
    match cmd {
        GETALL => {
            let values: Vec<u8> = {
                let mut table = sets.lock();
                let set = table.checked(id).map_err(|_| EIDRM)?;
                set.semaphores
                    .iter()
                    .flat_map(|s| (s.value as u16).to_le_bytes())
                    .collect()
            };
            c.mem
                .write(GuestAddr(arg), &values)
                .map_err(|_| Errno::EFAULT)?;
            Ok(0)
        }
        SETALL => {
            let mut bytes = vec![0u8; count * 2];
            c.mem
                .read(GuestAddr(arg), &mut bytes)
                .map_err(|_| Errno::EFAULT)?;
            let values: Vec<i32> = bytes
                .as_chunks::<2>()
                .0
                .iter()
                .map(|b| i32::from(u16::from_le_bytes([b[0], b[1]])))
                .collect();
            if values.iter().any(|&value| value > SEMVMX) {
                return Err(Errno::ERANGE);
            }
            let pid = c.pid_space().keep(c.process.pid);
            let mut table = sets.lock();
            let set = table.checked(id).map_err(|_| EIDRM)?;
            for (semaphore, value) in set.semaphores.iter_mut().zip(values) {
                semaphore.value = value;
                semaphore.pid = pid.clone();
            }
            for adjustments in set.undos.values_mut() {
                adjustments.fill(0);
            }
            set.ctime = now;
            set.update(None, false, now);
            Ok(0)
        }
        _ => {
            let n = usize::try_from(n)
                .ok()
                .filter(|&n| n < count)
                .ok_or(Errno::EINVAL)?;
            let mut table = sets.lock();
            let set = table.checked(id).map_err(|_| EIDRM)?;
            Ok(match cmd {
                GETVAL => set.semaphores[n].value as u64,
                GETPID => u64::from(c.pid_space().number_of(&set.semaphores[n].pid)),
                GETNCNT => set.waiting_on(n, false),
                _ => set.waiting_on(n, true),
            })
        }
    }
}

/// `SETVAL`, as Linux's `semctl_setval`: a value above `SEMVMX` or below 0
/// is `ERANGE`, before the set (`EINVAL`), the semaphore (`EINVAL`) and
/// the permission to change it (`EACCES`). It clears the semaphore's
/// adjustments and lets waits through.
fn setval(c: &Context<'_>, id: i32, n: i32, value: i32) -> Result<u64, Errno> {
    if !(0..=SEMVMX).contains(&value) {
        return Err(Errno::ERANGE);
    }
    let owner = ipc::capable(c, CAP_IPC_OWNER);
    let now = ipc::now(c);
    let pid = c.pid_space().keep(c.process.pid);
    let sets = sets(c);
    let mut table = sets.lock();
    let set = table.checked(id)?;
    let n = usize::try_from(n)
        .ok()
        .filter(|&n| n < set.semaphores.len())
        .ok_or(Errno::EINVAL)?;
    if !set.perm.permitted(&c.process.credentials, 0o222, owner) {
        return Err(Errno::EACCES);
    }
    for adjustments in set.undos.values_mut() {
        adjustments[n] = 0;
    }
    set.semaphores[n] = Semaphore { value, pid };
    set.ctime = now;
    set.update(None, false, now);
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn op(num: u16, op: i16, flags: i16) -> Op {
        Op { num, op, flags }
    }
    fn set(values: &[i32]) -> Set {
        Set {
            id: 0,
            perm: Perm {
                key: 0,
                uid: 0,
                gid: 0,
                cuid: 0,
                cgid: 0,
                mode: 0o600,
            },
            otime: 0,
            ctime: 0,
            semaphores: values
                .iter()
                .map(|&value| Semaphore {
                    value,
                    pid: KeptPid::default(),
                })
                .collect(),
            undos: BTreeMap::new(),
            queues: Queues::new(values.len()),
        }
    }
    fn values(set: &Set) -> Vec<i32> {
        set.semaphores.iter().map(|s| s.value).collect()
    }
    fn wait_for(set: &mut Set, ops: Vec<Op>, pid: u32) -> Arc<Wake> {
        let pid = KeptPid::of(1, pid);
        let blocking = match attempt(&mut set.semaphores, &mut set.undos, &ops, None, &pid) {
            Attempt::Blocked(at) => at,
            other => panic!("{other:?}"),
        };
        let wake = Arc::new(Wake {
            status: AtomicI64::new(WAITING),
            token: WaitToken::default(),
        });
        set.queues.push(Waiting {
            alters: ops.iter().any(|op| op.op != 0),
            ops,
            undo: None,
            pid,
            blocking,
            wake: Arc::clone(&wake),
        });
        wake
    }

    #[test]
    fn operations_go_through_all_at_once_or_not_at_all() {
        let mut s = set(&[1, 0]);
        let ops = [op(0, -1, 0), op(1, -1, 0)];
        assert_eq!(
            attempt(
                &mut s.semaphores,
                &mut s.undos,
                &ops,
                None,
                &KeptPid::of(1, 7)
            ),
            Attempt::Blocked(1)
        );
        assert_eq!(values(&s), [1, 0]);
        let ops = [op(0, -1, 0), op(1, 1, 0)];
        assert_eq!(
            attempt(
                &mut s.semaphores,
                &mut s.undos,
                &ops,
                None,
                &KeptPid::of(1, 7)
            ),
            Attempt::Done
        );
        assert_eq!(values(&s), [0, 1]);
        assert_eq!(s.semaphores[0].pid, KeptPid::of(1, 7));
        // In order, so a later operation on the same semaphore sees the
        // earlier one's value.
        let ops = [op(1, 1, 0), op(1, -2, 0)];
        assert_eq!(
            attempt(
                &mut s.semaphores,
                &mut s.undos,
                &ops,
                None,
                &KeptPid::of(1, 8)
            ),
            Attempt::Done
        );
        assert_eq!(values(&s), [0, 0]);
    }

    #[test]
    fn nowait_is_the_blocking_operations_and_range_errors_undo_the_rest() {
        let mut s = set(&[0, SEMVMX]);
        let ops = [op(0, 0, 0), op(0, -1, IPC_NOWAIT as i16)];
        assert_eq!(
            attempt(
                &mut s.semaphores,
                &mut s.undos,
                &ops,
                None,
                &KeptPid::of(1, 1)
            ),
            Attempt::Failed(Errno::EAGAIN)
        );
        let ops = [op(0, -1, 0), op(0, 0, IPC_NOWAIT as i16)];
        assert_eq!(
            attempt(
                &mut s.semaphores,
                &mut s.undos,
                &ops,
                None,
                &KeptPid::of(1, 1)
            ),
            Attempt::Blocked(0)
        );
        let ops = [op(0, 5, 0), op(1, 1, 0)];
        assert_eq!(
            attempt(
                &mut s.semaphores,
                &mut s.undos,
                &ops,
                None,
                &KeptPid::of(1, 1)
            ),
            Attempt::Failed(Errno::ERANGE)
        );
        assert_eq!(values(&s), [0, SEMVMX]);
    }

    #[test]
    fn adjustments_stay_within_the_undo_range() {
        let mut s = set(&[0]);
        s.undos.insert(3, vec![0]);
        let up = [op(0, SEMVMX as i16, SEM_UNDO)];
        assert_eq!(
            attempt(
                &mut s.semaphores,
                &mut s.undos,
                &up,
                Some(3),
                &KeptPid::of(1, 1)
            ),
            Attempt::Done
        );
        assert_eq!(s.undos[&3], [-SEMVMX]);
        let down = [op(0, -1, SEM_UNDO)];
        assert_eq!(
            attempt(
                &mut s.semaphores,
                &mut s.undos,
                &down,
                Some(3),
                &KeptPid::of(1, 1)
            ),
            Attempt::Done
        );
        assert_eq!(s.undos[&3], [-SEMVMX + 1]);
        // -32768 is the lowest adjustment.
        s.semaphores[0].value = 2;
        assert_eq!(
            attempt(
                &mut s.semaphores,
                &mut s.undos,
                &[op(0, 2, SEM_UNDO)],
                Some(3),
                &KeptPid::of(1, 1)
            ),
            Attempt::Done
        );
        assert_eq!(s.undos[&3], [-SEMAEM - 1]);
        assert_eq!(
            attempt(
                &mut s.semaphores,
                &mut s.undos,
                &[op(0, 1, SEM_UNDO)],
                Some(3),
                &KeptPid::of(1, 1)
            ),
            Attempt::Failed(Errno::ERANGE)
        );
        assert_eq!(
            (values(&s), s.undos[&3].clone()),
            (vec![4], vec![-SEMAEM - 1])
        );
    }

    #[test]
    fn waits_go_through_in_order_and_are_counted_by_what_they_wait_on() {
        let mut s = set(&[0, 1]);
        let first = wait_for(&mut s, vec![op(0, -2, 0)], 10);
        let second = wait_for(&mut s, vec![op(0, -1, 0)], 11);
        let zero = wait_for(&mut s, vec![op(1, 0, 0)], 12);
        let both = wait_for(&mut s, vec![op(1, -1, 0), op(0, -1, 0)], 13);
        assert_eq!((s.waiting_on(0, false), s.waiting_on(1, true)), (3, 1));
        assert_eq!(s.waiting_on(1, false), 0);
        s.semaphores[0].value = 2;
        assert!(s.update(None, false, 5));
        // The first takes both; the second waits on.
        assert_eq!(first.status.load(Ordering::SeqCst), 0);
        assert_eq!(second.status.load(Ordering::SeqCst), WAITING);
        assert_eq!(s.otime, 5);
        s.semaphores[0].value = 2;
        assert!(s.update(None, false, 6));
        // The second goes through, then the one on both, which makes
        // semaphore 1 zero for the wait for it.
        assert_eq!(second.status.load(Ordering::SeqCst), 0);
        assert_eq!(both.status.load(Ordering::SeqCst), 0);
        assert_eq!(zero.status.load(Ordering::SeqCst), 0);
        assert_eq!(values(&s), [0, 0]);
        assert_eq!(s.semaphores[1].pid, KeptPid::of(1, 12));
        assert!(s.queues.is_empty());
    }

    fn pids(list: &[Waiting]) -> Vec<KeptPid> {
        list.iter().map(|waiting| waiting.pid.clone()).collect()
    }

    #[test]
    fn simple_changes_join_the_set_queue_while_a_complex_operation_waits() {
        let mut s = set(&[0, 0]);
        wait_for(&mut s, vec![op(0, -1, 0)], 1);
        wait_for(&mut s, vec![op(1, -1, 0)], 2);
        // A complex change takes the others in, the last semaphore's
        // first, and a simple one that comes after it waits behind it.
        let complex = wait_for(&mut s, vec![op(0, -1, 0), op(1, -1, 0)], 3);
        let later = wait_for(&mut s, vec![op(1, -1, 0), op(0, -1, 0)], 4);
        wait_for(&mut s, vec![op(0, -2, 0)], 5);
        assert_eq!(
            pids(&s.queues.set_alter),
            [2, 1, 3, 4, 5].map(|pid| KeptPid::of(1, pid))
        );
        assert!(s.queues.alter.iter().all(Vec::is_empty));
        assert_eq!((s.waiting_on(0, false), s.waiting_on(1, false)), (3, 2));
        // Once no complex operation is left, the simple ones go back.
        s.queues.forget(&complex);
        s.queues.settle();
        assert_eq!(s.queues.complex, 1);
        s.queues.forget(&later);
        s.queues.settle();
        assert_eq!(s.queues.complex, 0);
        assert!(s.queues.set_alter.is_empty());
        assert_eq!(
            pids(&s.queues.alter[0]),
            [1, 5].map(|pid| KeptPid::of(1, pid))
        );
        assert_eq!(pids(&s.queues.alter[1]), [KeptPid::of(1, 2)]);
        // A complex wait for zero counts as complex too.
        s.semaphores[1].value = 1;
        let zero = wait_for(&mut s, vec![op(0, 0, 0), op(1, 0, 0)], 6);
        assert_eq!((s.queues.complex, s.queues.set_alter.len()), (1, 3));
        assert_eq!(pids(&s.queues.set_zero), [KeptPid::of(1, 6)]);
        assert_eq!(s.waiting_on(1, true), 1);
        s.queues.forget(&zero);
        s.queues.settle();
        assert_eq!((s.queues.complex, s.queues.set_alter.len()), (0, 0));
    }

    #[test]
    fn a_change_tries_only_the_queues_of_what_it_increases_or_makes_zero() {
        let mut s = set(&[0, 1]);
        let down = wait_for(&mut s, vec![op(0, -1, 0)], 1);
        let zero = wait_for(&mut s, vec![op(1, 0, 0)], 2);
        s.semaphores[0].value = 1;
        s.semaphores[1].value = 0;
        // A decrease of semaphore 0 that left it 1 lets neither through.
        assert!(!s.update(Some(&[op(0, -1, 0)]), true, 3));
        assert_eq!(s.otime, 3);
        assert_eq!(down.status.load(Ordering::SeqCst), WAITING);
        assert_eq!(zero.status.load(Ordering::SeqCst), WAITING);
        assert!(s.update(Some(&[op(1, -1, 0)]), false, 4));
        assert_eq!(zero.status.load(Ordering::SeqCst), 0);
        assert_eq!(down.status.load(Ordering::SeqCst), WAITING);
        assert!(s.update(Some(&[op(0, 1, 0)]), false, 5));
        assert_eq!(down.status.load(Ordering::SeqCst), 0);
        assert_eq!(s.otime, 5);
        assert!(s.queues.is_empty());
    }

    #[test]
    fn a_change_of_unknown_semaphores_tries_every_queue() {
        // As SETVAL, SETALL and an exit's undo: the waits for zero on each
        // semaphore that is 0, then each semaphore's changes in order.
        let mut s = set(&[1, 0, 1]);
        let zero = wait_for(&mut s, vec![op(0, 0, 0)], 1);
        let down = wait_for(&mut s, vec![op(1, -1, 0)], 2);
        let other = wait_for(&mut s, vec![op(2, 0, 0)], 3);
        s.semaphores[0].value = 0;
        s.semaphores[1].value = 1;
        assert!(s.update(None, false, 7));
        assert_eq!(zero.status.load(Ordering::SeqCst), 0);
        assert_eq!(down.status.load(Ordering::SeqCst), 0);
        assert_eq!(other.status.load(Ordering::SeqCst), WAITING);
        assert_eq!((values(&s), s.otime), (vec![0, 0, 1], 7));
        // With nothing done, SETVAL and SETALL leave sem_otime as it was.
        assert!(!s.update(None, false, 8));
        assert_eq!(s.otime, 7);
    }

    #[test]
    fn removal_tells_every_wait() {
        let mut s = set(&[0]);
        let wake = wait_for(&mut s, vec![op(0, -1, 0)], 1);
        s.remove();
        assert_eq!(wake.status.load(Ordering::SeqCst), -i64::from(EIDRM.0));
    }

    #[test]
    fn the_last_user_of_an_undo_list_applies_it_cut_to_the_range() {
        let table: Arc<Mutex<Table>> = Arc::default();
        let list = UndoList::new();
        let shared = list.share();
        {
            let mut guard = table.lock().unwrap();
            let t = &mut *guard;
            let id = t.ids.allocate(&t.sets, SEMMNI).unwrap();
            let mut s = set(&[5, 1]);
            s.id = id;
            list.join(&table, &mut s);
            s.undos.insert(list.number, vec![-9, 3]);
            t.sets.insert(ipc::index(id), s);
        }
        list.leave(&KeptPid::of(1, 42), 9);
        assert_eq!(values(&table.lock().unwrap().sets[&0]), [5, 1]);
        shared.leave(&KeptPid::of(1, 42), 9);
        let t = table.lock().unwrap();
        let s = &t.sets[&0];
        assert_eq!(values(s), [0, 4]);
        assert_eq!((&s.semaphores[0].pid, s.otime), (&KeptPid::of(1, 42), 9));
        assert!(s.undos.is_empty());
    }
}
