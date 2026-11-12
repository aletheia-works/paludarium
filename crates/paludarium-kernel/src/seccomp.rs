//! seccomp, as Linux's `kernel/seccomp.c`: strict mode, which allows only
//! `read`, `write`, `exit` and `rt_sigreturn`, and filter mode, where every
//! system call first runs the thread's classic BPF programs over its
//! `seccomp_data`. The lowest action of all of them decides: kill the
//! process or the thread with SIGSYS, a SIGSYS the thread may handle
//! (TRAP), an errno, ENOSYS for TRACE (no tracer) and USER_NOTIF (no
//! listener), or the call itself (LOG, ALLOW).
//!
//! A thread keeps its mode and filters in [`ThreadState`]; a new thread or
//! process takes its creator's, exec keeps them, and
//! `SECCOMP_FILTER_FLAG_TSYNC` gives the caller's to every other thread
//! through the group's [`Threads`], as Linux's `seccomp_sync_threads` does.

use std::collections::BTreeMap;
use std::sync::Arc;

use paludarium_mmu::AddressSpace;
use paludarium_types::{Errno, GuestAddr};

use crate::ThreadState;
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
    /// the newest of equal ones giving the data.
    fn run(&self, data: &[u8; 64]) -> u32 {
        let mut ret = RET_ALLOW;
        let mut walker = self.filter.as_deref();
        while let Some(filter) = walker {
            let current = execute(&filter.program, data);
            if action_only(current) < action_only(ret) {
                ret = current;
            }
            walker = filter.prev.as_deref();
        }
        ret
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

/// The seccomp state of every thread of a process that may have other
/// threads, which `SECCOMP_FILTER_FLAG_TSYNC` reads and changes; each thread
/// takes a change made to its own when it next enters the kernel
/// ([`crate::ThreadGroup::take_seccomp`]).
#[derive(Default)]
pub(crate) struct Threads {
    pub states: BTreeMap<u32, Seccomp>,
    /// How many `SECCOMP_FILTER_FLAG_TSYNC` have changed other threads.
    pub syncs: u64,
}

/// What a system call does after the filters have seen it.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Verdict {
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
            let ret = state.run(&data);
            let value = ret & RET_DATA;
            match ret & RET_ACTION_FULL {
                RET_ERRNO => {
                    // Capped at MAX_ERRNO.
                    let errno = value.min(4095);
                    Verdict::Return(u64::from(errno).wrapping_neg())
                }
                RET_TRAP => Verdict::Trap(siginfo(number, value, rip)),
                // No tracer, no listener.
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
            threads.states.insert(c.tid, c.state.seccomp.clone());
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

/// `seccomp_set_mode_filter`. A listener (`SECCOMP_FILTER_FLAG_NEW_LISTENER`)
/// is not made: once the filter is found good, that flag is EINVAL.
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
    if flags & FLAG_NEW_LISTENER != 0 {
        return Err(Errno::EINVAL);
    }
    let mut threads = c.group.seccomp_threads();
    crate::ThreadGroup::refresh_seccomp(&threads, c.tid, c.state);
    let own = &c.state.seccomp;
    if !matches!(own.mode, 0 | MODE_FILTER) {
        return Err(Errno::EINVAL);
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
        && let Some((&tid, _)) = threads.states.iter().find(|&(&tid, other)| {
            tid != c.tid
                && !(other.mode == 0 || other.mode == MODE_FILTER && own.descends_from(other))
        })
    {
        if flags & FLAG_TSYNC_ESRCH != 0 {
            return Err(Errno(3));
        }
        return Ok(u64::from(c.group.namespaces(c.tid).pid.number(tid)));
    }
    let new = Seccomp {
        mode: MODE_FILTER,
        filter: Some(Arc::new(Filter {
            program,
            prev: own.filter.clone(),
            log: flags & FLAG_LOG != 0,
        })),
    };
    c.state.seccomp = new.clone();
    if flags & FLAG_TSYNC != 0 {
        for state in threads.states.values_mut() {
            *state = new.clone();
        }
        threads.syncs += 1;
        c.group.seccomp_synced(threads.syncs);
        c.state.seccomp_sync = threads.syncs;
    }
    threads.states.insert(c.tid, new);
    Ok(0)
}

/// The SIGSYS siginfo `Verdict::Kill` and `Verdict::Trap` carry, as the
/// 128 bytes of a frame or a core dump.
pub(crate) fn full_siginfo(info: &[u8; 48]) -> [u8; 128] {
    let mut full = [0u8; 128];
    full[..48].copy_from_slice(info);
    full
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
            filter: Some(Arc::new(Filter {
                program,
                prev: None,
                log: false,
            })),
        };
        let mut data = [0u8; 64];
        data[0..4].copy_from_slice(&number.to_le_bytes());
        data[4..8].copy_from_slice(&ARCH.to_le_bytes());
        for (i, arg) in args.iter().enumerate() {
            data[16 + i * 8..24 + i * 8].copy_from_slice(&arg.to_le_bytes());
        }
        Ok(state.run(&data))
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
            Some(Arc::new(Filter {
                program: prepare(&[insn(0x06, 0, 0, ret)]).unwrap(),
                prev,
                log: false,
            }))
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
