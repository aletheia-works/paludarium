//! seccomp, as Linux's `kernel/seccomp.c`: strict mode, which allows only
//! `read`, `write`, `exit` and `rt_sigreturn`, and filter mode, where every
//! system call first runs the thread's classic BPF programs over its
//! `seccomp_data`. The lowest action of all of them decides: kill the
//! process or the thread with SIGSYS, a SIGSYS the thread may handle
//! (TRAP), an errno, ENOSYS for TRACE (no tracer), a wait for the filter's
//! listener to answer (USER_NOTIF, ENOSYS once it has none), or the call
//! itself (LOG, ALLOW).
//!
//! A thread keeps its mode and filters in [`ThreadState`]; a new thread or
//! process takes its creator's, exec keeps them, and
//! `SECCOMP_FILTER_FLAG_TSYNC` gives the caller's to every other thread
//! through the group's [`Threads`], as Linux's `seccomp_sync_threads` does.
//! The same [`Threads`] count each filter's users, the threads that run it,
//! whose end a listener sees as a hang-up.
//!
//! A filter made with `SECCOMP_FILTER_FLAG_NEW_LISTENER` comes with a
//! [`Listener`] file. A call the filter sends to it waits as a
//! [`Notice`] until the listener's `SECCOMP_IOCTL_NOTIF_RECV` takes it and
//! `SECCOMP_IOCTL_NOTIF_SEND` answers, as `seccomp_do_user_notification`
//! does; `SECCOMP_IOCTL_NOTIF_ADDFD` meanwhile has the waiting thread
//! install a file of the listener's process.

use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use paludarium_host::{FileHandle, FileStat};
use paludarium_mmu::AddressSpace;
use paludarium_types::{Errno, GuestAddr};

use crate::ThreadState;
use crate::events::{IN, NONBLOCK, OUT, ReadinessHub};
use crate::files::{Descriptor, Files};
use crate::syscalls::{Context, Outcome};

pub(crate) const MODE_STRICT: u8 = 1;
pub(crate) const MODE_FILTER: u8 = 2;

const RET_KILL_PROCESS: u32 = 0x8000_0000;
const RET_KILL_THREAD: u32 = 0;
const RET_TRAP: u32 = 0x0003_0000;
const RET_ERRNO: u32 = 0x0005_0000;
const RET_USER_NOTIF: u32 = 0x7fc0_0000;
const RET_TRACE: u32 = 0x7ff0_0000;
const RET_LOG: u32 = 0x7ffc_0000;
const RET_ALLOW: u32 = 0x7fff_0000;
const RET_ACTION_FULL: u32 = 0xffff_0000;
const RET_DATA: u32 = 0xffff;

const FLAG_TSYNC: u32 = 1;
const FLAG_LOG: u32 = 2;
const FLAG_NEW_LISTENER: u32 = 8;
const FLAG_TSYNC_ESRCH: u32 = 16;
const FLAG_WAIT_KILLABLE_RECV: u32 = 32;
/// In Linux master's uapi header, after 6.12.
const FLAG_RESTART_BEFORE_RECV: u32 = 64;
const FLAG_MASK: u32 = 127;

/// `AUDIT_ARCH_X86_64`, the `arch` of every call.
const ARCH: u32 = 0xc000_003e;
/// `sizeof(struct seccomp_data)`.
const DATA_SIZE: u32 = 64;
/// `BPF_MAXINSNS`.
const MAX_INSNS: usize = 4096;
/// `MAX_INSNS_PER_PATH`: what all of a thread's filters may add up to, each
/// counted with 4 more.
const MAX_INSNS_PER_PATH: usize = (1 << 18) / 8;
/// `BPF_MEMWORDS`.
const MEMWORDS: u32 = 16;
const SIGSYS: i32 = 31;
/// `SYS_SECCOMP`, the `si_code` of the SIGSYS.
const SYS_SECCOMP: i32 = 1;

/// A classic BPF instruction (`struct sock_filter`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Insn {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

/// The source of an ALU or jump operand.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Src {
    K(u32),
    X,
}

/// An instruction as the filter runs it, after Linux's checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Op {
    /// `A = seccomp_data[k]`, a 32-bit word.
    LoadData(u32),
    LoadImm(u32),
    LoadXImm(u32),
    LoadMem(usize),
    LoadXMem(usize),
    Store(usize),
    StoreX(usize),
    /// The operation's `BPF_OP` bits.
    Alu(u16, Src),
    Neg,
    Tax,
    Txa,
    Ja(u32),
    /// The comparison's `BPF_OP` bits, and the offsets when true and false.
    Jump(u16, Src, u8, u8),
    RetK(u32),
    RetA,
}

/// One filter of a thread's list, newest first, as Linux's
/// `seccomp_filter`: a thread with another filter on top shares this one.
#[derive(Debug)]
pub(crate) struct Filter {
    program: Box<[Op]>,
    prev: Option<Arc<Filter>>,
    /// `SECCOMP_FILTER_FLAG_LOG`, which only changes what is logged.
    #[allow(dead_code)]
    log: bool,
    /// Linux's `users`: the threads whose list has this filter on top, and
    /// the filters on top of it that have users themselves. At 0 no thread
    /// runs it any more.
    users: AtomicUsize,
    /// What its listener answers, for a filter made with one.
    notifier: Option<Arc<Notifier>>,
    /// `SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV`: a call the listener has
    /// received waits for its answer through any signal but a fatal one.
    wait_killable_recv: bool,
    /// `SECCOMP_FILTER_FLAG_RESTART_BEFORE_RECV`: a call a signal takes back
    /// before the listener has received it runs again after any handler.
    restart_before_recv: bool,
}

impl Filter {
    /// A filter of `program` on top of `prev`, which it keeps a user of.
    fn new(program: Box<[Op]>, prev: Option<Arc<Filter>>, log: bool) -> Self {
        if let Some(prev) = &prev {
            prev.users.fetch_add(1, Ordering::SeqCst);
        }
        Self {
            program,
            prev,
            log,
            users: AtomicUsize::new(0),
            notifier: None,
            wait_killable_recv: false,
            restart_before_recv: false,
        }
    }
    /// Whether its listener is still open (Linux's `filter->notif`).
    fn listens(&self) -> bool {
        self.notifier.as_ref().is_some_and(|n| n.lock().open)
    }
}

/// One user fewer of `filter`: at none, as Linux's
/// `__seccomp_filter_orphan` does, its listener hangs up and the filter
/// under it has a user fewer in turn.
fn release(filter: Option<&Arc<Filter>>) {
    let mut walker = filter.map(|f| &**f);
    while let Some(filter) = walker {
        let last = filter
            .users
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |users| {
                users.checked_sub(1)
            })
            .is_ok_and(|users| users == 1);
        if !last {
            break;
        }
        if let Some(notifier) = &filter.notifier {
            notifier.lock().input += 1;
            notifier.hub.changed();
        }
        walker = filter.prev.as_deref();
    }
}

fn hold(state: &Seccomp) {
    if let Some(filter) = &state.filter {
        filter.users.fetch_add(1, Ordering::SeqCst);
    }
}

/// A thread's seccomp mode and filters (Linux's `struct seccomp`).
#[derive(Clone, Debug, Default)]
pub(crate) struct Seccomp {
    pub mode: u8,
    filter: Option<Arc<Filter>>,
}

/// The same mode and the same filters, not equal ones.
impl PartialEq for Seccomp {
    fn eq(&self, other: &Self) -> bool {
        self.mode == other.mode
            && match (&self.filter, &other.filter) {
                (Some(a), Some(b)) => Arc::ptr_eq(a, b),
                (a, b) => a.is_none() && b.is_none(),
            }
    }
}
impl Eq for Seccomp {}

impl Seccomp {
    /// How many filters it has, which `/proc/<pid>/status` shows.
    pub(crate) fn filters(&self) -> u32 {
        let mut count = 0;
        let mut walker = self.filter.as_deref();
        while let Some(filter) = walker {
            count += 1;
            walker = filter.prev.as_deref();
        }
        count
    }
    /// `seccomp_run_filters`: every filter runs, and the lowest action wins,
    /// the newest of equal ones giving the data; with the filter it came
    /// from (`match`).
    fn run(&self, data: &[u8; 64]) -> (u32, Option<&Arc<Filter>>) {
        let mut ret = RET_ALLOW;
        let mut matched = None;
        let mut walker = self.filter.as_ref();
        while let Some(filter) = walker {
            let current = execute(&filter.program, data);
            if action_only(current) < action_only(ret) {
                ret = current;
                matched = Some(filter);
            }
            walker = filter.prev.as_ref();
        }
        (ret, matched)
    }
    /// Whether `ancestor` is this list or one it was built on
    /// (`is_ancestor`); no filter is everyone's.
    fn descends_from(&self, ancestor: &Self) -> bool {
        let Some(ancestor) = ancestor.filter.as_ref() else {
            return true;
        };
        let mut walker = self.filter.as_ref();
        while let Some(filter) = walker {
            if Arc::ptr_eq(filter, ancestor) {
                return true;
            }
            walker = filter.prev.as_ref();
        }
        false
    }
}

/// The action of a return value, compared as Linux's `ACTION_ONLY` does: a
/// signed int, so that KILL_PROCESS is the lowest.
fn action_only(ret: u32) -> i32 {
    (ret & RET_ACTION_FULL).cast_signed()
}

/// The seccomp state of every thread of a process with filters or strict
/// mode, which `SECCOMP_FILTER_FLAG_TSYNC` reads and changes; each thread
/// takes a change made to its own when it next enters the kernel
/// ([`crate::ThreadGroup::take_seccomp`]). Each state is a user of its
/// filter, from when it is recorded until its thread ends.
#[derive(Default)]
pub(crate) struct Threads {
    states: BTreeMap<u32, Seccomp>,
    /// How many `SECCOMP_FILTER_FLAG_TSYNC` have changed other threads.
    pub syncs: u64,
}

impl Threads {
    pub(crate) fn get(&self, tid: u32) -> Option<&Seccomp> {
        self.states.get(&tid)
    }
    /// Thread `tid` has `state` now.
    pub(crate) fn insert(&mut self, tid: u32, state: Seccomp) {
        hold(&state);
        if let Some(old) = self.states.insert(tid, state) {
            release(old.filter.as_ref());
        }
    }
    /// Thread `tid` has ended.
    pub(crate) fn remove(&mut self, tid: u32) {
        if let Some(old) = self.states.remove(&tid) {
            release(old.filter.as_ref());
        }
    }
    pub(crate) fn clear(&mut self) {
        for (_, old) in std::mem::take(&mut self.states) {
            release(old.filter.as_ref());
        }
    }
    fn iter(&self) -> impl Iterator<Item = (&u32, &Seccomp)> {
        self.states.iter()
    }
    /// Every thread recorded has `state` now, as TSYNC gives it.
    fn assign_all(&mut self, state: &Seccomp) {
        let tids: Vec<u32> = self.states.keys().copied().collect();
        for tid in tids {
            self.insert(tid, state.clone());
        }
    }
}

impl Drop for Threads {
    fn drop(&mut self) {
        self.clear();
    }
}

/// What a system call does after the filters have seen it.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// It waits for the listener of the filter that sent it there.
    Notify(Notify),
    /// It runs.
    Allow,
    /// It does not run, and returns this value.
    Return(u64),
    /// It does not run, and SIGSYS with this siginfo is forced on the thread.
    Trap([u8; 48]),
    /// The thread, or the process when `process` or when it is the last
    /// thread, ends by SIGSYS, with this siginfo.
    Kill { process: bool, siginfo: [u8; 48] },
    /// Strict mode refuses it: the thread ends by SIGKILL.
    Strict,
}

/// What `state` makes of system call `number` (the low 32 bits of `rax`),
/// with the argument registers as they are and the address after the
/// `syscall` instruction.
pub(crate) fn check(state: &Seccomp, number: u32, args: [u64; 6], rip: u64) -> Verdict {
    match state.mode {
        MODE_STRICT => {
            // read, write, exit, rt_sigreturn, uretprobe, uprobe
            if matches!(number, 0 | 1 | 60 | 15 | 335 | 336) {
                Verdict::Allow
            } else {
                Verdict::Strict
            }
        }
        MODE_FILTER => {
            // uretprobe and uprobe pass every filter, as Linux's cache
            // allows them (`seccomp_uprobe_exception`).
            if matches!(number, 335 | 336) {
                return Verdict::Allow;
            }
            let mut data = [0u8; 64];
            data[0..4].copy_from_slice(&number.to_le_bytes());
            data[4..8].copy_from_slice(&ARCH.to_le_bytes());
            data[8..16].copy_from_slice(&rip.to_le_bytes());
            for (i, arg) in args.iter().enumerate() {
                data[16 + i * 8..24 + i * 8].copy_from_slice(&arg.to_le_bytes());
            }
            let (ret, matched) = state.run(&data);
            let value = ret & RET_DATA;
            match ret & RET_ACTION_FULL {
                RET_ERRNO => {
                    // Capped at MAX_ERRNO.
                    let errno = value.min(4095);
                    Verdict::Return(u64::from(errno).wrapping_neg())
                }
                RET_TRAP => Verdict::Trap(siginfo(number, value, rip)),
                RET_USER_NOTIF if let Some(filter) = matched.filter(|f| f.notifier.is_some()) => {
                    Verdict::Notify(Notify {
                        filter: Arc::clone(filter),
                        data,
                    })
                }
                // No tracer, or a filter made without a listener.
                RET_TRACE | RET_USER_NOTIF => Verdict::Return(Errno::ENOSYS.to_syscall_return()),
                RET_LOG | RET_ALLOW => Verdict::Allow,
                action => Verdict::Kill {
                    process: action != RET_KILL_THREAD,
                    siginfo: siginfo(number, value, rip),
                },
            }
        }
        _ => Verdict::Allow,
    }
}

/// The SIGSYS siginfo of `force_sig_seccomp`: SYS_SECCOMP, the filter's
/// data as `si_errno`, then `si_call_addr`, `si_syscall` and `si_arch`.
pub(crate) fn siginfo(number: u32, value: u32, rip: u64) -> [u8; 48] {
    let mut info = [0u8; 48];
    info[0..4].copy_from_slice(&SIGSYS.to_le_bytes());
    info[4..8].copy_from_slice(&value.to_le_bytes());
    info[8..12].copy_from_slice(&SYS_SECCOMP.to_le_bytes());
    info[16..24].copy_from_slice(&rip.to_le_bytes());
    info[24..28].copy_from_slice(&number.to_le_bytes());
    info[28..32].copy_from_slice(&ARCH.to_le_bytes());
    info
}

/// Runs a checked program over `data`: A, X and the scratch words start at
/// 0, every jump goes forward and the last instruction returns.
fn execute(program: &[Op], data: &[u8; 64]) -> u32 {
    let (mut a, mut x) = (0u32, 0u32);
    let mut mem = [0u32; MEMWORDS as usize];
    let mut pc = 0;
    loop {
        let op = program[pc];
        pc += 1;
        let operand = |src: Src| match src {
            Src::K(k) => k,
            Src::X => x,
        };
        match op {
            Op::LoadData(k) => {
                let k = k as usize;
                a = u32::from_le_bytes([data[k], data[k + 1], data[k + 2], data[k + 3]]);
            }
            Op::LoadImm(k) => a = k,
            Op::LoadXImm(k) => x = k,
            Op::LoadMem(i) => a = mem[i],
            Op::LoadXMem(i) => x = mem[i],
            Op::Store(i) => mem[i] = a,
            Op::StoreX(i) => mem[i] = x,
            Op::Alu(operation, src) => {
                let v = operand(src);
                a = match operation {
                    0x00 => a.wrapping_add(v),
                    0x10 => a.wrapping_sub(v),
                    0x20 => a.wrapping_mul(v),
                    // Division by an X of 0 ends the program with 0, as
                    // Linux's conversion to eBPF has it.
                    0x30 => match a.checked_div(v) {
                        Some(q) => q,
                        None => return 0,
                    },
                    0x40 => a | v,
                    0x50 => a & v,
                    0xa0 => a ^ v,
                    // A shift by X counts its low 5 bits.
                    0x60 => a.wrapping_shl(v & 31),
                    _ => a.wrapping_shr(v & 31),
                };
            }
            Op::Neg => a = a.wrapping_neg(),
            Op::Tax => x = a,
            Op::Txa => a = x,
            Op::Ja(k) => pc += k as usize,
            Op::Jump(comparison, src, jt, jf) => {
                let v = operand(src);
                let taken = match comparison {
                    0x10 => a == v,
                    0x20 => a > v,
                    0x30 => a >= v,
                    _ => a & v != 0,
                };
                pc += usize::from(if taken { jt } else { jf });
            }
            Op::RetK(k) => return k,
            Op::RetA => return a,
        }
    }
}

/// Whether Linux's `chk_code_allowed` knows `code`.
fn known(code: u16) -> bool {
    matches!(
        code,
        // ALU with K or X: add, sub, mul, div, mod, and, or, xor, lsh, rsh
        0x04 | 0x0c | 0x14 | 0x1c | 0x24 | 0x2c | 0x34 | 0x3c | 0x94 | 0x9c
            | 0x54 | 0x5c | 0x44 | 0x4c | 0xa4 | 0xac | 0x64 | 0x6c | 0x74 | 0x7c
            // neg
            | 0x84
            // ld w/h/b abs, ld w len, ld w/h/b ind, ld imm, ld mem
            | 0x20 | 0x28 | 0x30 | 0x80 | 0x40 | 0x48 | 0x50 | 0x00 | 0x60
            // ldx w len, ldx b msh, ldx imm, ldx mem
            | 0x81 | 0xb1 | 0x01 | 0x61
            // st, stx, tax, txa, ret k, ret a
            | 0x02 | 0x03 | 0x07 | 0x87 | 0x06 | 0x16
            // ja, jeq, jgt, jge, jset with K or X
            | 0x05 | 0x15 | 0x1d | 0x25 | 0x2d | 0x35 | 0x3d | 0x45 | 0x4d
    )
}

/// Linux's `bpf_check_classic` and then `seccomp_check_filter`: EINVAL for
/// an instruction either refuses, a jump past the end, a scratch word read
/// before it is written on some path, or a last instruction that does not
/// return. Gives the program as it runs.
fn prepare(insns: &[Insn]) -> Result<Box<[Op]>, Errno> {
    let len = insns.len();
    for (pc, insn) in insns.iter().enumerate() {
        if !known(insn.code) {
            return Err(Errno::EINVAL);
        }
        let k = insn.k;
        let bad = match insn.code {
            // div, mod by a K of 0
            0x34 | 0x94 => k == 0,
            // lsh, rsh by a K of 32 or more
            0x64 | 0x74 => k >= 32,
            0x60 | 0x61 | 0x02 | 0x03 => k >= MEMWORDS,
            0x05 => k as usize >= len - pc - 1,
            0x15 | 0x1d | 0x25 | 0x2d | 0x35 | 0x3d | 0x45 | 0x4d => {
                pc + usize::from(insn.jt) + 1 >= len || pc + usize::from(insn.jf) + 1 >= len
            }
            _ => false,
        };
        if bad {
            return Err(Errno::EINVAL);
        }
    }
    if !matches!(insns[len - 1].code, 0x06 | 0x16) {
        return Err(Errno::EINVAL);
    }
    loads_after_stores(insns)?;
    insns
        .iter()
        .map(|insn| {
            let k = insn.k;
            let src = |code: u16| {
                if code & 0x08 == 0 { Src::K(k) } else { Src::X }
            };
            Ok(match insn.code {
                0x20 if k < DATA_SIZE && k & 3 == 0 => Op::LoadData(k),
                0x80 => Op::LoadImm(DATA_SIZE),
                0x81 => Op::LoadXImm(DATA_SIZE),
                0x00 => Op::LoadImm(k),
                0x01 => Op::LoadXImm(k),
                0x60 => Op::LoadMem(k as usize),
                0x61 => Op::LoadXMem(k as usize),
                0x02 => Op::Store(k as usize),
                0x03 => Op::StoreX(k as usize),
                0x84 => Op::Neg,
                0x07 => Op::Tax,
                0x87 => Op::Txa,
                0x06 => Op::RetK(k),
                0x16 => Op::RetA,
                0x05 => Op::Ja(k),
                // Every ALU operation but mod.
                code @ (0x04 | 0x0c | 0x14 | 0x1c | 0x24 | 0x2c | 0x34 | 0x3c | 0x54 | 0x5c
                | 0x44 | 0x4c | 0xa4 | 0xac | 0x64 | 0x6c | 0x74 | 0x7c) => {
                    Op::Alu(code & 0xf0, src(code))
                }
                code @ (0x15 | 0x1d | 0x25 | 0x2d | 0x35 | 0x3d | 0x45 | 0x4d) => {
                    Op::Jump(code & 0xf0, src(code), insn.jt, insn.jf)
                }
                _ => return Err(Errno::EINVAL),
            })
        })
        .collect()
}

/// Linux's `check_load_and_stores`: a scratch word is read only where every
/// path to the read has written it.
fn loads_after_stores(insns: &[Insn]) -> Result<(), Errno> {
    let mut masks = vec![u16::MAX; insns.len()];
    let mut valid: u16 = 0;
    for (pc, insn) in insns.iter().enumerate() {
        valid &= masks[pc];
        match insn.code {
            0x02 | 0x03 => valid |= 1 << insn.k,
            0x60 | 0x61 if valid & (1 << insn.k) == 0 => return Err(Errno::EINVAL),
            0x05 => {
                masks[pc + 1 + insn.k as usize] &= valid;
                valid = u16::MAX;
            }
            0x15 | 0x1d | 0x25 | 0x2d | 0x35 | 0x3d | 0x45 | 0x4d => {
                masks[pc + 1 + usize::from(insn.jt)] &= valid;
                masks[pc + 1 + usize::from(insn.jf)] &= valid;
                valid = u16::MAX;
            }
            _ => {}
        }
    }
    Ok(())
}

/// `seccomp(op, flags, args)`.
pub(crate) fn sys_seccomp(c: &mut Context<'_>, a: [u64; 6]) -> Outcome {
    let mut caller = Caller {
        state: c.process,
        tid: c.tid,
        mem: c.mem,
        group: c.group,
        processes: c.processes,
        files: Some((&mut *c.files, c.host)),
    };
    Outcome::Return(
        operate(&mut caller, a[0] as u32, a[1] as u32, a[2])
            .unwrap_or_else(Errno::to_syscall_return),
    )
}

/// The thread a seccomp operation acts for.
pub(crate) struct Caller<'a> {
    pub state: &'a mut ThreadState,
    pub tid: u32,
    pub mem: &'a AddressSpace,
    pub group: &'a crate::ThreadGroup,
    pub processes: &'a crate::processes::Processes,
    /// Its files and host, which a listener needs; prctl, which makes
    /// none, has neither.
    pub files: Option<(&'a mut Files, &'a dyn paludarium_host::Host)>,
}

/// `prctl(PR_SET_SECCOMP, mode, filter)`, which has no flags and takes no
/// filter for strict mode.
pub(crate) fn prctl_set(c: &mut Caller<'_>, mode: u64, filter: u64) -> Result<u64, Errno> {
    match mode {
        1 => operate(c, 0, 0, 0),
        2 => operate(c, 1, 0, filter),
        _ => Err(Errno::EINVAL),
    }
}

/// `do_seccomp`.
fn operate(c: &mut Caller<'_>, op: u32, flags: u32, args: u64) -> Result<u64, Errno> {
    match op {
        // SECCOMP_SET_MODE_STRICT
        0 => {
            if flags != 0 || args != 0 {
                return Err(Errno::EINVAL);
            }
            let mut threads = c.group.seccomp_threads();
            crate::ThreadGroup::refresh_seccomp(&threads, c.tid, c.state);
            if !matches!(c.state.seccomp.mode, 0 | MODE_STRICT) {
                return Err(Errno::EINVAL);
            }
            c.state.seccomp.mode = MODE_STRICT;
            threads.insert(c.tid, c.state.seccomp.clone());
            Ok(0)
        }
        // SECCOMP_SET_MODE_FILTER
        1 => set_filter(c, flags, args),
        // SECCOMP_GET_ACTION_AVAIL
        2 => {
            if flags != 0 {
                return Err(Errno::EINVAL);
            }
            let mut action = [0u8; 4];
            c.mem
                .read(GuestAddr(args), &mut action)
                .map_err(|_| Errno::EFAULT)?;
            match u32::from_le_bytes(action) {
                RET_KILL_PROCESS | RET_KILL_THREAD | RET_TRAP | RET_ERRNO | RET_USER_NOTIF
                | RET_TRACE | RET_LOG | RET_ALLOW => Ok(0),
                _ => Err(Errno::EOPNOTSUPP),
            }
        }
        // SECCOMP_GET_NOTIF_SIZES: seccomp_notif, seccomp_notif_resp and
        // seccomp_data.
        3 => {
            if flags != 0 {
                return Err(Errno::EINVAL);
            }
            let mut sizes = [0u8; 6];
            sizes[0..2].copy_from_slice(&80u16.to_le_bytes());
            sizes[2..4].copy_from_slice(&24u16.to_le_bytes());
            sizes[4..6].copy_from_slice(&64u16.to_le_bytes());
            c.mem
                .write(GuestAddr(args), &sizes)
                .map_err(|_| Errno::EFAULT)?;
            Ok(0)
        }
        _ => Err(Errno::EINVAL),
    }
}

/// `seccomp_set_mode_filter`: 0, or the listener's descriptor with
/// `SECCOMP_FILTER_FLAG_NEW_LISTENER`.
fn set_filter(c: &mut Caller<'_>, flags: u32, args: u64) -> Result<u64, Errno> {
    if flags & !FLAG_MASK != 0 {
        return Err(Errno::EINVAL);
    }
    if flags & FLAG_TSYNC != 0 && flags & FLAG_NEW_LISTENER != 0 && flags & FLAG_TSYNC_ESRCH == 0 {
        return Err(Errno::EINVAL);
    }
    if flags & (FLAG_WAIT_KILLABLE_RECV | FLAG_RESTART_BEFORE_RECV) != 0
        && flags & FLAG_NEW_LISTENER == 0
    {
        return Err(Errno::EINVAL);
    }
    // struct sock_fprog: an unsigned short length and the instructions.
    let mut fprog = [0u8; 16];
    c.mem
        .read(GuestAddr(args), &mut fprog)
        .map_err(|_| Errno::EFAULT)?;
    let len = usize::from(u16::from_le_bytes([fprog[0], fprog[1]]));
    let at = u64::from_le_bytes(fprog[8..16].try_into().unwrap_or_default());
    if len == 0 || len > MAX_INSNS {
        return Err(Errno::EINVAL);
    }
    let no_new_privs = c.processes.status_of(c.state.pid).2;
    if !no_new_privs && c.state.credentials.effective & crate::credentials::CAP_SYS_ADMIN == 0 {
        return Err(Errno::EACCES);
    }
    if at == 0 {
        return Err(Errno::EINVAL);
    }
    let mut raw = vec![0u8; len * 8];
    c.mem
        .read(GuestAddr(at), &mut raw)
        .map_err(|_| Errno::EFAULT)?;
    let insns: Vec<Insn> = raw
        .as_chunks::<8>()
        .0
        .iter()
        .map(|b| Insn {
            code: u16::from_le_bytes([b[0], b[1]]),
            jt: b[2],
            jf: b[3],
            k: u32::from_le_bytes([b[4], b[5], b[6], b[7]]),
        })
        .collect();
    let program = prepare(&insns)?;
    // The listener's descriptor, close-on-exec, is taken before the
    // filter is checked against the thread's (EMFILE first).
    let listener = if flags & FLAG_NEW_LISTENER != 0 {
        let (files, _) = c.files.as_mut().ok_or(Errno::EINVAL)?;
        Some(files.reserve(c.group.nofile())?)
    } else {
        None
    };
    let result = attach(c, flags, program);
    let (Some(fd), Some((files, _))) = (listener, c.files.as_mut()) else {
        return result.map(|attached| attached.0);
    };
    match result {
        Ok((0, Some(filter))) => {
            let file = Arc::new(Listener {
                filter,
                flags: AtomicU32::new(2),
            });
            files.fill(fd, Descriptor::unnamed(file, true));
            Ok(u64::from(fd))
        }
        Ok((tid, _)) => {
            files.unreserve(fd);
            Ok(tid)
        }
        Err(error) => {
            files.unreserve(fd);
            Err(error)
        }
    }
}

/// The rest of `seccomp_set_mode_filter`: `program` goes on top of the
/// thread's filters, and with TSYNC every other thread's. Gives 0 and the
/// new filter, or the thread TSYNC cannot change.
fn attach(
    c: &mut Caller<'_>,
    flags: u32,
    program: Box<[Op]>,
) -> Result<(u64, Option<Arc<Filter>>), Errno> {
    let mut threads = c.group.seccomp_threads();
    crate::ThreadGroup::refresh_seccomp(&threads, c.tid, c.state);
    let own = &c.state.seccomp;
    if !matches!(own.mode, 0 | MODE_FILTER) {
        return Err(Errno::EINVAL);
    }
    // One listener to a list (`has_duplicate_listener`).
    if flags & FLAG_NEW_LISTENER != 0 {
        let mut walker = own.filter.as_deref();
        while let Some(filter) = walker {
            if filter.listens() {
                return Err(EBUSY);
            }
            walker = filter.prev.as_deref();
        }
    }
    let mut total = program.len();
    let mut walker = own.filter.as_deref();
    while let Some(filter) = walker {
        total += filter.program.len() + 4;
        walker = filter.prev.as_deref();
    }
    if total > MAX_INSNS_PER_PATH {
        return Err(Errno::ENOMEM);
    }
    if flags & FLAG_TSYNC != 0
        && let Some((&tid, _)) = threads.iter().find(|&(&tid, other)| {
            tid != c.tid
                && !(other.mode == 0 || other.mode == MODE_FILTER && own.descends_from(other))
        })
    {
        if flags & FLAG_TSYNC_ESRCH != 0 {
            return Err(ESRCH);
        }
        return Ok((u64::from(c.group.namespaces(c.tid).pid.number(tid)), None));
    }
    let mut filter = Filter::new(program, own.filter.clone(), flags & FLAG_LOG != 0);
    if flags & FLAG_NEW_LISTENER != 0
        && let Some((files, host)) = c.files.as_ref()
    {
        let mut start = [0u8; 8];
        let _ = host.random_bytes(&mut start);
        filter.notifier = Some(Arc::new(Notifier {
            state: Mutex::new(Notifications {
                open: true,
                requests: 0,
                next_id: u64::from_le_bytes(start),
                flags: 0,
                notices: Vec::new(),
                input: 0,
                output: 0,
            }),
            hub: Arc::clone(&files.readiness),
        }));
        filter.wait_killable_recv = flags & FLAG_WAIT_KILLABLE_RECV != 0;
        filter.restart_before_recv = flags & FLAG_RESTART_BEFORE_RECV != 0;
    }
    let filter = Arc::new(filter);
    let new = Seccomp {
        mode: MODE_FILTER,
        filter: Some(Arc::clone(&filter)),
    };
    c.state.seccomp = new.clone();
    if flags & FLAG_TSYNC != 0 {
        threads.assign_all(&new);
        threads.syncs += 1;
        c.group.seccomp_synced(threads.syncs);
        c.state.seccomp_sync = threads.syncs;
    }
    threads.insert(c.tid, new);
    Ok((0, Some(filter)))
}

/// The SIGSYS siginfo `Verdict::Kill` and `Verdict::Trap` carry, as the
/// 128 bytes of a frame or a core dump.
pub(crate) fn full_siginfo(info: &[u8; 48]) -> [u8; 128] {
    let mut full = [0u8; 128];
    full[..48].copy_from_slice(info);
    full
}

/// A call a filter sends to its listener, with the `seccomp_data` the
/// filters saw.
#[derive(Debug)]
pub(crate) struct Notify {
    filter: Arc<Filter>,
    data: [u8; 64],
}

/// The same filter and data.
impl PartialEq for Notify {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.filter, &other.filter) && self.data == other.data
    }
}
impl Eq for Notify {}

/// `SECCOMP_IOCTL_NOTIF_RECV`, `_IOWR('!', 0, struct seccomp_notif)`.
const NOTIF_RECV: u32 = 0xc050_2100;
/// `SECCOMP_IOCTL_NOTIF_SEND`, `_IOWR('!', 1, struct seccomp_notif_resp)`.
const NOTIF_SEND: u32 = 0xc018_2101;
/// `SECCOMP_IOCTL_NOTIF_ID_VALID`, `_IOW('!', 2, __u64)`, and the `_IOR`
/// it first was (`SECCOMP_IOCTL_NOTIF_ID_VALID_WRONG_DIR`).
const NOTIF_ID_VALID: u32 = 0x4008_2102;
const NOTIF_ID_VALID_WRONG_DIR: u32 = 0x8008_2102;
/// `SECCOMP_IOCTL_NOTIF_SET_FLAGS`, `_IOW('!', 4, __u64)`.
const NOTIF_SET_FLAGS: u32 = 0x4008_2104;
/// `SECCOMP_IOCTL_NOTIF_ADDFD` without its direction and size, which an
/// extensible argument may have any of.
const NOTIF_ADDFD: u32 = 0x2103;
/// `SECCOMP_USER_NOTIF_FLAG_CONTINUE`.
const USER_NOTIF_FLAG_CONTINUE: u32 = 1;
/// `SECCOMP_USER_NOTIF_FD_SYNC_WAKE_UP`.
const USER_NOTIF_FD_SYNC_WAKE_UP: u64 = 1;
/// `SECCOMP_ADDFD_FLAG_SETFD` and `SECCOMP_ADDFD_FLAG_SEND`.
const ADDFD_FLAG_SETFD: u32 = 1;
const ADDFD_FLAG_SEND: u32 = 2;
/// `SECCOMP_NOTIFY_ADDFD_SIZE_VER0`.
const ADDFD_SIZE: usize = 24;
const O_CLOEXEC: u32 = 0x80000;
const POLLRDNORM: u32 = 0x40;
const POLLWRNORM: u32 = 0x100;
const POLLHUP: u32 = 0x10;
const ENOENT: Errno = Errno(2);
const ESRCH: Errno = Errno(3);
const EINTR: Errno = Errno(4);
const EBUSY: Errno = Errno(16);
const E2BIG: Errno = Errno(7);
const EINPROGRESS: Errno = Errno(115);

/// A filter's listener state (Linux's `struct notification` with the
/// filter's `notify_lock`); the readiness hub stands for its `wqh`.
pub(crate) struct Notifier {
    state: Mutex<Notifications>,
    hub: Arc<ReadinessHub>,
}

impl std::fmt::Debug for Notifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Notifier").finish_non_exhaustive()
    }
}

impl Notifier {
    fn lock(&self) -> MutexGuard<'_, Notifications> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

struct Notifications {
    /// Whether the listener is open; once it is closed, the filter has none.
    open: bool,
    /// Linux's `requests`, a count of calls to receive that a call taken
    /// back by a signal does not lower, so that the next receive finds
    /// nothing (ENOENT).
    requests: u64,
    /// The id of the next call, from a random start.
    next_id: u64,
    /// `SECCOMP_USER_NOTIF_FD_SYNC_WAKE_UP`, which only changes which CPU
    /// a waiter wakes on.
    flags: u64,
    /// The calls waiting, in the order they came.
    notices: Vec<Notice>,
    /// Wake-ups of readers and of writers, as `wake_up_poll` with EPOLLIN
    /// (a call, a hang-up) or EPOLLOUT (a call received) makes them: the
    /// edges of an edge-triggered epoll.
    input: u64,
    output: u64,
}

impl Notifications {
    fn find(&mut self, id: u64) -> Option<&mut Notice> {
        self.notices.iter_mut().find(|n| n.id == id)
    }
}

/// A call waiting for its answer (`struct seccomp_knotif`).
struct Notice {
    id: u64,
    /// The waiting thread.
    tid: u32,
    data: [u8; 64],
    state: State,
    error: i32,
    val: i64,
    flags: u32,
    /// What `SECCOMP_IOCTL_NOTIF_ADDFD` asks of the thread, the last asked
    /// first, as Linux's list takes them.
    addfd: VecDeque<Arc<AddFd>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum State {
    Init,
    Sent,
    Replied,
}

/// A file for a waiting thread to install (`struct seccomp_kaddfd`).
struct AddFd {
    descriptor: Descriptor,
    cloexec: bool,
    /// The descriptor to put it at (`SECCOMP_ADDFD_FLAG_SETFD`), or the
    /// lowest free one.
    at: Option<u32>,
    /// `SECCOMP_ADDFD_FLAG_SEND`: the descriptor answers the call.
    send: bool,
    /// The descriptor installed, once the thread has tried.
    result: Mutex<Option<Result<u32, Errno>>>,
}

impl AddFd {
    fn result(&self) -> Option<Result<u32, Errno>> {
        *self.result.lock().unwrap_or_else(PoisonError::into_inner)
    }
    fn finish(&self, result: Result<u32, Errno>) {
        *self.result.lock().unwrap_or_else(PoisonError::into_inner) = Some(result);
    }
}

/// A listener file, `anon_inode:seccomp notify`, which holds its filter.
/// Closing its last descriptor answers every call waiting with ENOSYS and
/// leaves the filter without a listener (`seccomp_notify_release`).
pub(crate) struct Listener {
    filter: Arc<Filter>,
    flags: AtomicU32,
}

impl Drop for Listener {
    fn drop(&mut self) {
        let Some(notifier) = &self.filter.notifier else {
            return;
        };
        let mut s = notifier.lock();
        for notice in &mut s.notices {
            if notice.state != State::Replied {
                notice.state = State::Replied;
                notice.error = -Errno::ENOSYS.0;
                notice.val = 0;
            }
        }
        s.open = false;
        drop(s);
        notifier.hub.changed();
    }
}

impl FileHandle for Listener {
    /// `seccomp_notify_poll`: readable while a call waits to be received,
    /// writable while one received waits for its answer, hung up once no
    /// thread runs the filter.
    fn readiness(&self) -> Result<(u32, u64, u64), Errno> {
        let Some(notifier) = &self.filter.notifier else {
            return Ok((0, 0, 0));
        };
        let s = notifier.lock();
        let mut mask = 0;
        for notice in &s.notices {
            match notice.state {
                State::Init => mask |= IN | POLLRDNORM,
                State::Sent => mask |= OUT | POLLWRNORM,
                State::Replied => {}
            }
        }
        if self.filter.users.load(Ordering::SeqCst) == 0 {
            mask |= POLLHUP;
        }
        Ok((mask, s.input, s.output))
    }
    fn as_any(&self) -> Option<&dyn std::any::Any> {
        Some(self)
    }
    /// Its file operations have no `read` or `write`.
    fn read(&self, _: &mut [u8]) -> Result<usize, Errno> {
        Err(Errno::EINVAL)
    }
    fn write(&self, _: &[u8]) -> Result<usize, Errno> {
        Err(Errno::EINVAL)
    }
    /// Nor `llseek`.
    fn seek(&self, _: i64, _: u32) -> Result<u64, Errno> {
        Err(Errno::ESPIPE)
    }
    fn stat(&self) -> Result<FileStat, Errno> {
        Ok(FileStat {
            mode: 0o600,
            links: 1,
            ..FileStat::default()
        })
    }
    fn truncate(&self, _: u64) -> Result<(), Errno> {
        Err(Errno::EINVAL)
    }
    fn flock(&self, _: u32) -> Result<(), Errno> {
        Err(Errno::ENOSYS)
    }
    fn flags(&self) -> u32 {
        self.flags.load(Ordering::SeqCst)
    }
    fn set_flags(&self, flags: u32) -> Result<(), Errno> {
        self.flags.store(2 | flags & NONBLOCK, Ordering::SeqCst);
        Ok(())
    }
}

/// Whether `file` is a listener, which `/proc/self/fd` names
/// `anon_inode:seccomp notify`.
pub(crate) fn is_listener(file: &Arc<dyn FileHandle>) -> bool {
    file.as_any().is_some_and(|any| any.is::<Listener>())
}

/// What a call sent to a listener does (`seccomp_do_user_notification`).
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Reply {
    /// It runs (`SECCOMP_USER_NOTIF_FLAG_CONTINUE`).
    Continue,
    /// It returns this.
    Return(u64),
    /// A signal ended the wait: EINTR, which runs the call again after a
    /// stop or a SA_RESTART handler (ERESTARTSYS, whatever the call is),
    /// or after any handler when `always` (ERESTARTNOINTR).
    Interrupted { always: bool },
}

/// Thread `c` waits for the listener of `notify`'s filter to answer its
/// call, installing what `SECCOMP_IOCTL_NOTIF_ADDFD` gives it meanwhile.
/// ENOSYS if the listener has been closed.
pub(crate) fn notify(c: &mut Context<'_>, notify: &Notify) -> Reply {
    let filter = &notify.filter;
    let Some(notifier) = &filter.notifier else {
        return Reply::Return(Errno::ENOSYS.to_syscall_return());
    };
    let id = {
        let mut s = notifier.lock();
        if !s.open {
            return Reply::Return(Errno::ENOSYS.to_syscall_return());
        }
        let id = s.next_id;
        s.next_id = id.wrapping_add(1);
        s.notices.push(Notice {
            id,
            tid: c.tid,
            data: notify.data,
            state: State::Init,
            error: 0,
            val: 0,
            flags: 0,
            addfd: VecDeque::new(),
        });
        s.requests += 1;
        s.input += 1;
        id
    };
    notifier.hub.changed();
    let interrupted = loop {
        let ticket = c.files.readiness.token.value();
        let mut s = notifier.lock();
        let Some(notice) = s.find(id) else {
            break true;
        };
        if let Some(addfd) = notice.addfd.pop_front() {
            let result = install(c, &addfd);
            if addfd.send {
                match result {
                    Ok(fd) => {
                        notice.flags = 0;
                        notice.error = 0;
                        notice.val = i64::from(fd);
                    }
                    Err(_) => notice.state = State::Sent,
                }
            }
            addfd.finish(result);
            drop(s);
            notifier.hub.changed();
            continue;
        }
        if notice.state == State::Replied {
            break false;
        }
        let killable = filter.wait_killable_recv && notice.state >= State::Sent;
        drop(s);
        if killable {
            if fatal_pending(c) {
                break true;
            }
            wait_through_signals(c, ticket);
        } else if crate::events::wait(c, ticket, None).is_err() {
            // A wait that has become killable meanwhile goes on.
            let mut s = notifier.lock();
            if filter.wait_killable_recv && s.find(id).is_some_and(|n| n.state >= State::Sent) {
                continue;
            }
            break true;
        }
    };
    let mut s = notifier.lock();
    let index = s.notices.iter().position(|n| n.id == id);
    let notice = index.map(|index| s.notices.remove(index));
    drop(s);
    notifier.hub.changed();
    let Some(notice) = notice else {
        return Reply::Interrupted { always: false };
    };
    // Whatever else was asked of the thread finds it gone.
    for addfd in &notice.addfd {
        addfd.finish(Err(ESRCH));
    }
    if interrupted {
        return Reply::Interrupted {
            always: filter.restart_before_recv && notice.state == State::Init,
        };
    }
    if notice.flags & USER_NOTIF_FLAG_CONTINUE != 0 {
        return Reply::Continue;
    }
    // `syscall_set_return_value`: the error if there is one, else the value.
    Reply::Return(if notice.error != 0 {
        i64::from(notice.error) as u64
    } else {
        notice.val as u64
    })
}

/// Whether a signal pending for `c` would end it, which ends a killable
/// wait (`fatal_signal_pending`, as `complete_signal` turns such a signal
/// into SIGKILL): SIGKILL, the group ending, or an unblocked signal whose
/// default action, with no handler, ends the process.
fn fatal_pending(c: &mut Context<'_>) -> bool {
    c.inbox.drain(c.process);
    c.group.drain_process(c.process);
    if c.group.status().is_some()
        || (!c.inbox.owns_wake(c.cancellation) && c.cancellation.load(Ordering::SeqCst))
    {
        return true;
    }
    c.process.pending.iter().any(|signal| {
        let number = signal.number;
        let action = c
            .process
            .signal_actions
            .get(&number)
            .copied()
            .unwrap_or_default();
        number == 9
            || (c.process.signal_mask & (1u64 << (number - 1)) == 0
                && action.handler == 0
                && !matches!(number, 17..=23 | 28))
    })
}

/// A wait that signals do not end: until the readiness ticket moves, or
/// for a short while, after which the caller looks for a fatal signal.
fn wait_through_signals(c: &Context<'_>, ticket: u32) {
    let never = AtomicBool::new(false);
    let clock = paludarium_host::ClockId::Monotonic;
    let Ok(now) = c.host.clock(clock) else {
        return;
    };
    let end = now.saturating_add(10_000_000);
    if c.host
        .wait_on(&c.files.readiness.token, ticket, Some((clock, end)), &never)
        .is_err_and(|e| e == Errno::ENOSYS)
    {
        let _ = c.host.wait_until(clock, end, &never);
    }
}

/// The waiting thread installs `addfd`'s file: at the lowest free
/// descriptor (`receive_fd`), or at the one asked for, closing what was
/// there (`receive_fd_replace`).
fn install(c: &mut Context<'_>, addfd: &AddFd) -> Result<u32, Errno> {
    let descriptor = addfd.descriptor.clone().received(addfd.cloexec);
    let limit = c.group.nofile();
    let Some(at) = addfd.at else {
        return c.files.allocate(descriptor, 0, limit);
    };
    if u64::from(at) >= limit {
        return Err(Errno::EBADF);
    }
    if let Some(closed) = c.files.replace(at, descriptor)? {
        crate::record_locks::closed(c, &closed);
        crate::mqueue::closed(c, &closed);
        crate::inet::linger(c, &closed.file);
    }
    Ok(at)
}

/// A listener's own `ioctl` requests (`seccomp_notify_ioctl`), EINVAL for
/// any other; `None` for any other file.
pub(crate) fn ioctl(
    c: &mut Context<'_>,
    file: &Arc<dyn FileHandle>,
    request: u64,
    argument: u64,
) -> Option<Result<u64, Errno>> {
    let listener = file.as_any()?.downcast_ref::<Listener>()?;
    let filter = Arc::clone(&listener.filter);
    let notifier = Arc::clone(filter.notifier.as_ref()?);
    let request = request as u32;
    Some(match request {
        NOTIF_RECV => receive(c, &filter, &notifier, argument),
        NOTIF_SEND => answer(c, &notifier, argument),
        NOTIF_ID_VALID | NOTIF_ID_VALID_WRONG_DIR => {
            let id = c
                .mem
                .read_u64(GuestAddr(argument))
                .map_err(|_| Errno::EFAULT);
            id.and_then(|id| {
                let mut s = notifier.lock();
                match s.find(id) {
                    Some(notice) if notice.state == State::Sent => Ok(0),
                    _ => Err(ENOENT),
                }
            })
        }
        NOTIF_SET_FLAGS => {
            if argument & !USER_NOTIF_FD_SYNC_WAKE_UP != 0 {
                Err(Errno::EINVAL)
            } else {
                notifier.lock().flags = argument;
                Ok(0)
            }
        }
        _ if request & 0xffff == NOTIF_ADDFD => {
            add_fd(c, &notifier, argument, (request >> 16 & 0x3fff) as usize)
        }
        _ => Err(Errno::EINVAL),
    })
}

/// A wait of the listener's own a signal ended: EINTR, which a stop or a
/// SA_RESTART handler runs again (ERESTARTSYS).
fn interrupted(c: &mut Context<'_>) -> Result<u64, Errno> {
    c.process.restart = Some(16);
    Err(EINTR)
}

/// `SECCOMP_IOCTL_NOTIF_RECV` (`seccomp_notify_recv`): into a zeroed
/// `struct seccomp_notif`, the oldest call not received yet, once one has
/// come or no thread runs the filter.
fn receive(
    c: &mut Context<'_>,
    filter: &Filter,
    notifier: &Notifier,
    at: u64,
) -> Result<u64, Errno> {
    let mut buffer = [0u8; 80];
    c.mem
        .read(GuestAddr(at), &mut buffer)
        .map_err(|_| Errno::EFAULT)?;
    if buffer.iter().any(|&b| b != 0) {
        return Err(Errno::EINVAL);
    }
    loop {
        let ticket = c.files.readiness.token.value();
        {
            let mut s = notifier.lock();
            if filter.users.load(Ordering::SeqCst) == 0 {
                break;
            }
            if s.requests > 0 {
                s.requests -= 1;
                break;
            }
        }
        if crate::events::wait(c, ticket, None).is_err() {
            return interrupted(c);
        }
    }
    let mut s = notifier.lock();
    let Some(notice) = s.notices.iter_mut().find(|n| n.state == State::Init) else {
        return Err(ENOENT);
    };
    notice.state = State::Sent;
    let (id, tid) = (notice.id, notice.tid);
    buffer[0..8].copy_from_slice(&id.to_le_bytes());
    buffer[16..80].copy_from_slice(&notice.data);
    s.output += 1;
    drop(s);
    notifier.hub.changed();
    // The thread as the listener's PID namespace numbers it, 0 if it does not.
    let pid = c.group.namespaces(c.tid).pid.number(tid);
    buffer[8..12].copy_from_slice(&pid.to_le_bytes());
    if c.mem.write(GuestAddr(at), &buffer).is_err() {
        // The call waits to be received again.
        let mut s = notifier.lock();
        if let Some(notice) = s.find(id) {
            notice.state = State::Init;
            s.requests += 1;
            s.input += 1;
        }
        drop(s);
        notifier.hub.changed();
        return Err(Errno::EFAULT);
    }
    Ok(0)
}

/// `SECCOMP_IOCTL_NOTIF_SEND` (`seccomp_notify_send`): the one answer to a
/// call received, an error, a value or `SECCOMP_USER_NOTIF_FLAG_CONTINUE`.
fn answer(c: &Context<'_>, notifier: &Notifier, at: u64) -> Result<u64, Errno> {
    let mut response = [0u8; 24];
    c.mem
        .read(GuestAddr(at), &mut response)
        .map_err(|_| Errno::EFAULT)?;
    let id = u64::from_le_bytes(response[0..8].try_into().unwrap_or_default());
    let val = i64::from_le_bytes(response[8..16].try_into().unwrap_or_default());
    let error = i32::from_le_bytes(response[16..20].try_into().unwrap_or_default());
    let flags = u32::from_le_bytes(response[20..24].try_into().unwrap_or_default());
    if flags & !USER_NOTIF_FLAG_CONTINUE != 0
        || flags & USER_NOTIF_FLAG_CONTINUE != 0 && (error != 0 || val != 0)
    {
        return Err(Errno::EINVAL);
    }
    let mut s = notifier.lock();
    let notice = s.find(id).ok_or(ENOENT)?;
    if notice.state != State::Sent {
        return Err(EINPROGRESS);
    }
    notice.state = State::Replied;
    notice.error = error;
    notice.val = val;
    notice.flags = flags;
    drop(s);
    notifier.hub.changed();
    Ok(0)
}

/// `SECCOMP_IOCTL_NOTIF_ADDFD` (`seccomp_notify_addfd`) with a `size`-byte
/// `struct seccomp_notif_addfd`: the thread of a call received installs a
/// file of the caller's, and the call returns the descriptor with
/// `SECCOMP_ADDFD_FLAG_SEND`. Gives the descriptor once the thread has.
fn add_fd(c: &mut Context<'_>, notifier: &Notifier, at: u64, size: usize) -> Result<u64, Errno> {
    if !(ADDFD_SIZE..4096).contains(&size) {
        return Err(Errno::EINVAL);
    }
    // `copy_struct_from_user`: what a newer, longer struct adds must be 0.
    if size > ADDFD_SIZE {
        let mut rest = vec![0u8; size - ADDFD_SIZE];
        c.mem
            .read(
                GuestAddr(at.checked_add(ADDFD_SIZE as u64).ok_or(Errno::EFAULT)?),
                &mut rest,
            )
            .map_err(|_| Errno::EFAULT)?;
        if rest.iter().any(|&b| b != 0) {
            return Err(E2BIG);
        }
    }
    let mut raw = [0u8; ADDFD_SIZE];
    c.mem
        .read(GuestAddr(at), &mut raw)
        .map_err(|_| Errno::EFAULT)?;
    let word = |i: usize| u32::from_le_bytes(raw[i..i + 4].try_into().unwrap_or_default());
    let id = u64::from_le_bytes(raw[0..8].try_into().unwrap_or_default());
    let (flags, source, target, target_flags) = (word(8), word(12), word(16), word(20));
    if target_flags & !O_CLOEXEC != 0 || flags & !(ADDFD_FLAG_SETFD | ADDFD_FLAG_SEND) != 0 {
        return Err(Errno::EINVAL);
    }
    if target != 0 && flags & ADDFD_FLAG_SETFD == 0 {
        return Err(Errno::EINVAL);
    }
    let descriptor = c.files.descriptor(u64::from(source))?;
    let send = flags & ADDFD_FLAG_SEND != 0;
    let request = Arc::new(AddFd {
        descriptor,
        cloexec: target_flags & O_CLOEXEC != 0,
        at: (flags & ADDFD_FLAG_SETFD != 0).then_some(target),
        send,
        result: Mutex::new(None),
    });
    {
        let mut s = notifier.lock();
        let notice = s.find(id).ok_or(ENOENT)?;
        if notice.state != State::Sent {
            return Err(EINPROGRESS);
        }
        if send {
            if !notice.addfd.is_empty() {
                return Err(EBUSY);
            }
            notice.state = State::Replied;
        }
        notice.addfd.push_front(Arc::clone(&request));
    }
    notifier.hub.changed();
    loop {
        let ticket = c.files.readiness.token.value();
        if let Some(result) = request.result() {
            return result.map(u64::from);
        }
        if crate::events::wait(c, ticket, None).is_err() {
            let mut s = notifier.lock();
            if let Some(result) = request.result() {
                return result.map(u64::from);
            }
            if let Some(notice) = s.find(id) {
                notice.addfd.retain(|other| !Arc::ptr_eq(other, &request));
                if send {
                    notice.state = State::Sent;
                }
            }
            drop(s);
            return interrupted(c);
        }
    }
}

/// Answers the oldest call waiting on listener `file` with `val`, as a
/// receive and a send would; false if none waits.
#[cfg(test)]
pub(crate) fn answer_oldest(file: &Arc<dyn FileHandle>, val: i64) -> bool {
    let Some(listener) = file.as_any().and_then(|any| any.downcast_ref::<Listener>()) else {
        return false;
    };
    let Some(notifier) = &listener.filter.notifier else {
        return false;
    };
    let mut s = notifier.lock();
    let Some(notice) = s.notices.iter_mut().find(|n| n.state == State::Init) else {
        return false;
    };
    notice.state = State::Replied;
    notice.val = val;
    s.requests -= 1;
    drop(s);
    notifier.hub.changed();
    true
}

/// Strict mode or filters, for `PR_GET_SECCOMP`; strict mode never gets
/// here, as prctl is not among the calls it allows.
pub(crate) fn mode(state: &ThreadState) -> u64 {
    u64::from(state.seccomp.mode)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn insn(code: u16, jt: u8, jf: u8, k: u32) -> Insn {
        Insn { code, jt, jf, k }
    }

    fn run(insns: &[Insn], number: u32, args: [u64; 6]) -> Result<u32, Errno> {
        let program = prepare(insns)?;
        let state = Seccomp {
            mode: MODE_FILTER,
            filter: Some(Arc::new(Filter::new(program, None, false))),
        };
        let mut data = [0u8; 64];
        data[0..4].copy_from_slice(&number.to_le_bytes());
        data[4..8].copy_from_slice(&ARCH.to_le_bytes());
        for (i, arg) in args.iter().enumerate() {
            data[16 + i * 8..24 + i * 8].copy_from_slice(&arg.to_le_bytes());
        }
        Ok(state.run(&data).0)
    }

    #[test]
    fn a_filter_reads_the_number_and_arguments_and_returns_its_action() {
        // if nr == 39 return ERRNO(1); if args[0] low > 5 return TRAP|7; allow
        let program = [
            insn(0x20, 0, 0, 0),
            insn(0x15, 0, 1, 39),
            insn(0x06, 0, 0, RET_ERRNO | 1),
            insn(0x20, 0, 0, 16),
            insn(0x25, 0, 1, 5),
            insn(0x06, 0, 0, RET_TRAP | 7),
            insn(0x06, 0, 0, RET_ALLOW),
        ];
        assert_eq!(run(&program, 39, [0; 6]), Ok(RET_ERRNO | 1));
        assert_eq!(run(&program, 1, [6, 0, 0, 0, 0, 0]), Ok(RET_TRAP | 7));
        assert_eq!(run(&program, 1, [5, 0, 0, 0, 0, 0]), Ok(RET_ALLOW));
    }

    #[test]
    fn arithmetic_is_32_bit_and_division_by_a_zero_x_returns_0() {
        // A = 7; X = 0; A /= X; ret A  -> 0 (KILL_THREAD)
        let program = [
            insn(0x00, 0, 0, 7),
            insn(0x01, 0, 0, 0),
            insn(0x3c, 0, 0, 0),
            insn(0x16, 0, 0, 0),
        ];
        assert_eq!(run(&program, 0, [0; 6]), Ok(0));
        // A = 1; X = 33; A <<= X (counts 1); A -= 3; neg; ret A
        let program = [
            insn(0x00, 0, 0, 1),
            insn(0x01, 0, 0, 33),
            insn(0x6c, 0, 0, 0),
            insn(0x14, 0, 0, 3),
            insn(0x84, 0, 0, 0),
            insn(0x16, 0, 0, 0),
        ];
        assert_eq!(run(&program, 0, [0; 6]), Ok(1));
        // LEN loads sizeof(seccomp_data); scratch words keep values.
        let program = [
            insn(0x80, 0, 0, 0),
            insn(0x02, 0, 0, 3),
            insn(0x00, 0, 0, 0),
            insn(0x60, 0, 0, 3),
            insn(0x16, 0, 0, 0),
        ];
        assert_eq!(run(&program, 0, [0; 6]), Ok(64));
    }

    #[test]
    fn programs_linux_refuses_are_einval() {
        let ret = insn(0x06, 0, 0, RET_ALLOW);
        let refused: [&[Insn]; 10] = [
            // No return at the end.
            &[insn(0x00, 0, 0, 0)],
            // A jump past the end.
            &[insn(0x05, 0, 0, 1), ret],
            &[insn(0x15, 1, 0, 0), ret],
            // Division by a K of 0, a shift by 32.
            &[insn(0x34, 0, 0, 0), ret],
            &[insn(0x64, 0, 0, 32), ret],
            // mod, which seccomp does not take; half-word loads; unaligned
            // and outside the data.
            &[insn(0x94, 0, 0, 2), ret],
            &[insn(0x28, 0, 0, 0), ret],
            &[insn(0x20, 0, 0, 2), ret],
            &[insn(0x20, 0, 0, 64), ret],
            // A scratch word read before any write.
            &[insn(0x60, 0, 0, 0), ret],
        ];
        for program in refused {
            assert_eq!(prepare(program), Err(Errno::EINVAL), "{program:?}");
        }
        // A word written on one path only.
        let program = [
            insn(0x15, 0, 1, 0),
            insn(0x02, 0, 0, 1),
            insn(0x60, 0, 0, 1),
            ret,
        ];
        assert_eq!(prepare(&program), Err(Errno::EINVAL));
        // An unknown code.
        assert_eq!(prepare(&[insn(0xff, 0, 0, 0), ret]), Err(Errno::EINVAL));
    }

    #[test]
    fn the_lowest_action_of_all_filters_decides() {
        let make = |ret: u32, prev: Option<Arc<Filter>>| {
            Some(Arc::new(Filter::new(
                prepare(&[insn(0x06, 0, 0, ret)]).unwrap(),
                prev,
                false,
            )))
        };
        let older = make(RET_ERRNO | 2, None);
        let state = Seccomp {
            mode: MODE_FILTER,
            filter: make(RET_TRAP | 1, older.clone()),
        };
        assert_eq!(state.filters(), 2);
        assert!(matches!(check(&state, 1, [0; 6], 0x1000), Verdict::Trap(_)));
        let state = Seccomp {
            mode: MODE_FILTER,
            filter: make(RET_KILL_PROCESS, older.clone()),
        };
        assert!(matches!(
            check(&state, 1, [0; 6], 0x1000),
            Verdict::Kill { process: true, .. }
        ));
        let errno = Seccomp {
            mode: MODE_FILTER,
            filter: make(RET_LOG, older.clone()),
        };
        assert_eq!(
            check(&errno, 1, [0; 6], 0),
            Verdict::Return(u64::from(2u32).wrapping_neg())
        );
        // Every filter but the first is ancestry.
        assert!(errno.descends_from(&Seccomp {
            mode: MODE_FILTER,
            filter: older,
        }));
        assert!(!Seccomp::default().descends_from(&errno));
        // uprobe passes, strict mode allows four calls.
        assert_eq!(check(&state, 336, [0; 6], 0), Verdict::Allow);
        let strict = Seccomp {
            mode: MODE_STRICT,
            filter: None,
        };
        assert_eq!(check(&strict, 15, [0; 6], 0), Verdict::Allow);
        assert_eq!(check(&strict, 231, [0; 6], 0), Verdict::Strict);
    }

    #[test]
    fn the_sigsys_siginfo_carries_the_call() {
        let info = siginfo(39, 7, 0x40_1000);
        assert_eq!(&info[0..4], &31i32.to_le_bytes());
        assert_eq!(&info[4..8], &7u32.to_le_bytes());
        assert_eq!(&info[8..12], &1i32.to_le_bytes());
        assert_eq!(&info[16..24], &0x40_1000u64.to_le_bytes());
        assert_eq!(&info[24..28], &39u32.to_le_bytes());
        assert_eq!(&info[28..32], &ARCH.to_le_bytes());
    }
}
