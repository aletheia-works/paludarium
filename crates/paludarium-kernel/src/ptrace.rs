//! `ptrace`, as Linux's `kernel/ptrace.c`, the ptrace stops of
//! `kernel/signal.c` and the x86-64 register access of
//! `arch/x86/kernel/ptrace.c`.
//!
//! A tracee stops in its own thread: [`Kernel::ptrace_stop`] copies its
//! registers into the table of tracees ([`Traces`]), tells the tracer and
//! waits until the tracer resumes it, it is killed, or the tracer goes. The
//! tracer reads and changes the copy while the tracee waits, and the tracee
//! takes it back when it resumes, as Linux's tracer works on the
//! `pt_regs` of a task in `TASK_TRACED`.
use crate::processes::{ChildEvent, WaitFor, Wanted};
use crate::{Kernel, Next, Thread, signals};
use paludarium_cpu::breakpoints::{BreakOn, Breakpoint, Breakpoints};
use paludarium_cpu::{CpuState, flag, reg};
use paludarium_mmu::AddressSpace;
use paludarium_types::{Errno, ExitStatus, GuestAddr};
use std::collections::BTreeMap;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex, PoisonError};

pub(crate) const PTRACE_TRACEME: i64 = 0;
const PTRACE_PEEKTEXT: i64 = 1;
const PTRACE_PEEKDATA: i64 = 2;
const PTRACE_PEEKUSR: i64 = 3;
const PTRACE_POKETEXT: i64 = 4;
const PTRACE_POKEDATA: i64 = 5;
const PTRACE_POKEUSR: i64 = 6;
const PTRACE_CONT: i64 = 7;
const PTRACE_KILL: i64 = 8;
const PTRACE_GETREGS: i64 = 12;
const PTRACE_SETREGS: i64 = 13;
const PTRACE_GETFPREGS: i64 = 14;
const PTRACE_SETFPREGS: i64 = 15;
const PTRACE_ATTACH: i64 = 16;
const PTRACE_DETACH: i64 = 17;
const PTRACE_SINGLESTEP: i64 = 9;
/// x86's `PTRACE_SYSEMU_SINGLESTEP`.
const PTRACE_SYSEMU_SINGLESTEP: i64 = 32;
/// `si_code` of a single-step trap after a system call (`TRAP_BRKPT`).
const TRAP_BRKPT: i32 = 1;
const PTRACE_SYSCALL: i64 = 24;
/// x86's `PTRACE_ARCH_PRCTL`.
const PTRACE_ARCH_PRCTL: i64 = 30;
/// x86's `PTRACE_SYSEMU`.
const PTRACE_SYSEMU: i64 = 31;
const PTRACE_SETOPTIONS: i64 = 0x4200;
const PTRACE_GETEVENTMSG: i64 = 0x4201;
const PTRACE_GETSIGINFO: i64 = 0x4202;
const PTRACE_SETSIGINFO: i64 = 0x4203;
const PTRACE_GETREGSET: i64 = 0x4204;
const PTRACE_SETREGSET: i64 = 0x4205;
const PTRACE_SEIZE: i64 = 0x4206;
const PTRACE_INTERRUPT: i64 = 0x4207;
const PTRACE_LISTEN: i64 = 0x4208;
const PTRACE_PEEKSIGINFO: i64 = 0x4209;
const PTRACE_GETSIGMASK: i64 = 0x420a;
const PTRACE_SETSIGMASK: i64 = 0x420b;
const PTRACE_GET_RSEQ_CONFIGURATION: i64 = 0x420f;
/// `PTRACE_PEEKSIGINFO_SHARED`: the process's queue, not the thread's.
const PTRACE_PEEKSIGINFO_SHARED: u32 = 1;
/// `PTRACE_O_TRACESECCOMP`.
const PTRACE_O_TRACESECCOMP: u32 = 1 << PTRACE_EVENT_SECCOMP;
/// `arch_prctl`'s base requests.
const ARCH_SET_GS: u64 = 0x1001;
const ARCH_SET_FS: u64 = 0x1002;
const ARCH_GET_FS: u64 = 0x1003;
const ARCH_GET_GS: u64 = 0x1004;
const PTRACE_GET_SYSCALL_INFO: i64 = 0x420e;
const PTRACE_SET_SYSCALL_INFO: i64 = 0x4212;

/// `PTRACE_O_TRACESYSGOOD`: syscall stops report `SIGTRAP | 0x80`.
const PTRACE_O_TRACESYSGOOD: u32 = 1;
/// The events, each enabled by option bit `1 << event`.
const PTRACE_EVENT_FORK: i32 = 1;
const PTRACE_EVENT_VFORK: i32 = 2;
const PTRACE_EVENT_CLONE: i32 = 3;
const PTRACE_EVENT_EXEC: i32 = 4;
const PTRACE_EVENT_VFORK_DONE: i32 = 5;
const PTRACE_EVENT_EXIT: i32 = 6;
/// `PTRACE_EVENT_SECCOMP`, whose stops come with `SECCOMP_RET_TRACE`.
const PTRACE_EVENT_SECCOMP: i32 = 7;
/// The message of a syscall-entry and a syscall-exit stop.
const PTRACE_EVENTMSG_SYSCALL_ENTRY: u64 = 1;
const PTRACE_EVENTMSG_SYSCALL_EXIT: u64 = 2;
/// `PTRACE_SYSCALL_INFO_*`, the kinds of stop `ptrace_syscall_info`
/// describes.
const SYSCALL_INFO_NONE: u8 = 0;
const SYSCALL_INFO_ENTRY: u8 = 1;
const SYSCALL_INFO_EXIT: u8 = 2;
const SYSCALL_INFO_SECCOMP: u8 = 3;
/// `sizeof(struct ptrace_syscall_info)`.
const SYSCALL_INFO_SIZE: usize = 88;
/// `AUDIT_ARCH_X86_64`.
const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;
/// `CLONE_VFORK`, `CLONE_PTRACE` and `CLONE_UNTRACED`.
const CLONE_VFORK: u64 = 0x4000;
const CLONE_PTRACE: u64 = 0x2000;
const CLONE_UNTRACED: u64 = 0x80_0000;
const SIGCHLD: u64 = 17;

/// `PTRACE_EVENT_STOP`, the event of a group stop or an interrupt of a
/// seized tracee.
const PTRACE_EVENT_STOP: i32 = 128;
/// `PTRACE_O_EXITKILL`.
const PTRACE_O_EXITKILL: u32 = 1 << 20;
/// `PTRACE_O_SUSPEND_SECCOMP`.
const PTRACE_O_SUSPEND_SECCOMP: u32 = 1 << 21;
/// `PTRACE_O_MASK`: the event options and the two without events.
const PTRACE_O_MASK: u64 = 0xff | PTRACE_O_EXITKILL as u64 | PTRACE_O_SUSPEND_SECCOMP as u64;

/// `NT_PRSTATUS`, `NT_PRFPREG` and `NT_X86_XSTATE`.
const NT_PRSTATUS: u64 = 1;
const NT_PRFPREG: u64 = 2;
const NT_X86_XSTATE: u64 = 0x202;

/// `sizeof(struct user_regs_struct)`: 27 registers of 8 bytes.
const REGS_SIZE: u64 = 27 * 8;
/// `offsetof(struct user, u_debugreg)` and `sizeof(struct user)`.
const DEBUGREG: u64 = 848;
const USER_SIZE: u64 = 928;
/// `sizeof(struct user_i387_struct)`, the `fxsave` area.
const FPREGS_SIZE: usize = 512;
/// Linux's `DR6_RESERVED`, which a debug status register that nothing set
/// reads as.
const DR6_RESERVED: u64 = 0xffff_0ff0;
/// Where `user_regs_struct` keeps each register, by its offset over 8.
const ORIG_RAX: u64 = 15;
const RIP: u64 = 16;
const CS: u64 = 17;
const EFLAGS: u64 = 18;
const RSP: u64 = 19;
const SS: u64 = 20;
const FS_BASE: u64 = 21;
const GS_BASE: u64 = 22;
const DS: u64 = 23;
const ES: u64 = 24;
const FS: u64 = 25;
const GS: u64 = 26;
/// The general registers in `user_regs_struct` order, from r15 to rdi.
const GENERAL: [usize; 15] = [
    reg::R15,
    reg::R14,
    reg::R13,
    reg::R12,
    reg::RBP,
    reg::RBX,
    reg::R11,
    reg::R10,
    reg::R9,
    reg::R8,
    reg::RAX,
    reg::RCX,
    reg::RDX,
    reg::RSI,
    reg::RDI,
];
/// Linux's `FLAG_MASK` on x86-64: the flags a tracer may change.
const FLAG_MASK: u64 = flag::CF
    | flag::PF
    | flag::AF
    | flag::ZF
    | flag::SF
    | flag::TF
    | flag::DF
    | flag::OF
    | flag::RF
    | flag::AC
    | flag::NT;
/// `TASK_SIZE_MAX` with 4-level page tables, above which neither segment
/// base may be set.
const TASK_SIZE_MAX: u64 = (1 << 47) - 4096;

/// The codes a call that is to run again returns, which a tracer sees in
/// `rax` while the task is stopped: `ERESTARTSYS`, `ERESTARTNOINTR`,
/// `ERESTARTNOHAND` and `ERESTART_RESTARTBLOCK`.
const ERESTARTSYS: u64 = -512i64 as u64;
const ERESTARTNOINTR: u64 = -513i64 as u64;
const ERESTARTNOHAND: u64 = -514i64 as u64;
const ERESTART_RESTARTBLOCK: u64 = -516i64 as u64;

const SIGKILL: i32 = 9;
const SIGTRAP: i32 = 5;
const SIGSTOP: i32 = 19;
/// `CLD_TRAPPED`.
pub(crate) const CLD_TRAPPED: i32 = 4;

/// What a thread keeps of ptrace: not copied to a new thread or process,
/// which starts untraced, but for `orig_rax`, the call that made it, as
/// the registers a new task starts with are a copy of its maker's.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Local {
    /// The thread's own ID, as of its last stop at the kernel.
    tid: u32,
    /// The thread that made this one, whose task a `PTRACE_TRACEME`
    /// makes the tracer (Linux's `real_parent`).
    pub(crate) forked_by: u32,
    /// `orig_rax`: the call the thread is in, as it entered it, or -1 when
    /// it stopped at the kernel otherwise.
    pub(crate) orig_rax: u64,
    /// Whether the thread has stopped for the group stop now in effect
    /// while traced, and was let run on by its tracer.
    pub(crate) group_stopped: bool,
    /// The thread is returning from a system call, whose syscall-exit stop
    /// the next checkpoint takes if its tracer asked for it.
    pub(crate) in_syscall: bool,
    /// A traced thread's `clone`, `fork` or `vfork`: its checkpoints wait
    /// until the new task has started ([`Kernel::child_started`]), where
    /// the thread reports the event, as Linux's `kernel_clone` does after
    /// `wake_up_new_task`.
    pub(crate) hold: bool,
    clone: Option<Cloned>,
    /// A traced thread's `execve` that has replaced the program, by the
    /// thread's ID before it: the event the next checkpoint reports.
    exec: Option<u32>,
    /// `TIF_FORCED_TF`: the trap flag is set because the tracer
    /// single-steps the thread, not because the thread set it.
    pub(crate) forced_tf: bool,
    /// The segment selectors a tracer wrote, `ds`, `es`, `fs`, `gs`, `cs`
    /// and `ss` (`thread.ds` and the others); none for the ones every task
    /// starts with, which an exec gives back.
    pub(crate) selectors: Option<[u16; 6]>,
    /// The debug registers a tracer set (`ptrace_bps`, `ptrace_dr7`,
    /// `virtual_dr6`), which a new task does not take and exec clears.
    pub(crate) debug: Debug,
}

/// DR6's single-step bit (`DR_STEP`).
pub(crate) const DR_STEP: u64 = 0x4000;
/// DR7's bits no breakpoint reads (`DR_CONTROL_RESERVED`).
const DR_CONTROL_RESERVED: u64 = 0xffff_ffff_0000_fc00;

/// One debug register a breakpoint was made for: its address, its length
/// and type as DR7 last gave them (1 byte and a write, until then), and
/// whether DR7 enables it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Slot {
    address: u64,
    length: u8,
    on: BreakOn,
    enabled: bool,
}

/// A task's debug registers, as Linux's `ptrace_get_debugreg` and
/// `ptrace_set_debugreg` keep them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Debug {
    slots: [Option<Slot>; 4],
    /// DR7 as written.
    dr7: u64,
    /// DR6 as Linux's `virtual_dr6` has it: the bits of the last #DB.
    pub(crate) dr6: u64,
    /// The breakpoints DR7 enables, which the CPU matches.
    active: Option<Breakpoints>,
}

impl Debug {
    /// The breakpoints the CPU is to match, if any is enabled.
    pub(crate) fn active(&self) -> Option<&Breakpoints> {
        self.active.as_ref()
    }
    fn update(&mut self) {
        let mut set = Breakpoints::default();
        for (n, slot) in self.slots.iter().enumerate() {
            set.0[n] = slot.filter(|s| s.enabled).map(|s| Breakpoint {
                address: s.address,
                length: s.length,
                on: s.on,
            });
        }
        self.active = set.0.iter().any(Option::is_some).then_some(set);
    }
    /// `PTRACE_PEEKUSER` of debug register `n`.
    fn get(&self, n: u64) -> u64 {
        match n {
            0..=3 => self.slots[n as usize].map_or(0, |s| s.address),
            6 => self.dr6 ^ DR6_RESERVED,
            7 => self.dr7,
            _ => 0,
        }
    }
    /// `PTRACE_POKEUSER` of debug register `n` (`ptrace_set_debugreg`):
    /// an address goes to its breakpoint, which must be of user space and
    /// aligned to its length (`EINVAL`); DR7 enables and shapes the four,
    /// all or none (`ptrace_write_dr7`); there is no DR4 or DR5 (`EIO`).
    fn set(&mut self, n: u64, value: u64) -> Result<(), Errno> {
        match n {
            0..=3 => {
                let slot = &mut self.slots[n as usize];
                let mut new = slot.unwrap_or(Slot {
                    address: 0,
                    length: 1,
                    on: BreakOn::Write,
                    enabled: false,
                });
                new.address = value;
                check_breakpoint(new.address, new.length)?;
                *slot = Some(new);
            }
            6 => self.dr6 = value ^ DR6_RESERVED,
            7 => {
                let data = value & !DR_CONTROL_RESERVED;
                let mut slots = self.slots;
                for (n, slot) in slots.iter_mut().enumerate() {
                    let enabled = (data >> (n * 2)) & 3 != 0;
                    if slot.is_none() && !enabled {
                        continue;
                    }
                    let control = (data >> (16 + n * 4)) & 0xf;
                    let length = match control >> 2 {
                        0 => 1,
                        1 => 2,
                        2 => 8,
                        _ => 4,
                    };
                    // `arch_bp_generic_fields`: an execute breakpoint is
                    // 1 byte; I/O breakpoints are not taken.
                    let on = match control & 3 {
                        0 if length == 1 => BreakOn::Execute,
                        1 => BreakOn::Write,
                        3 => BreakOn::Access,
                        _ => return Err(Errno::EINVAL),
                    };
                    let address = slot.map_or(0, |s| s.address);
                    check_breakpoint(address, length)?;
                    *slot = Some(Slot {
                        address,
                        length,
                        on,
                        enabled,
                    });
                }
                self.slots = slots;
                self.dr7 = value;
            }
            _ => return Err(Errno::EIO),
        }
        self.update();
        Ok(())
    }
}

/// `hw_breakpoint_arch_parse`: a breakpoint's address is aligned to its
/// length and its range in user space (`EINVAL`).
fn check_breakpoint(address: u64, length: u8) -> Result<(), Errno> {
    let last = address.wrapping_add(u64::from(length) - 1);
    if address & (u64::from(length) - 1) != 0 || address >= TASK_SIZE_MAX || last >= TASK_SIZE_MAX {
        return Err(Errno::EINVAL);
    }
    Ok(())
}

/// The selectors of a 64-bit task: null data and `fs`/`gs` selectors,
/// `__USER_CS` and `__USER_DS`.
const SELECTORS: [u16; 6] = [0, 0, 0, 0, 0x33, 0x2b];

/// Where each selector is in `user_regs_struct`, in [`SELECTORS`]' order.
const SELECTOR_SLOTS: [u64; 6] = [DS, ES, FS, GS, CS, SS];

/// The `clone` of a traced thread: its flags, the new task once it is
/// made, and the event the tracer asked for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Cloned {
    flags: u64,
    child: Option<u32>,
    event: Option<i32>,
}

/// How the tracer last resumed a tracee: whether it stops at each system
/// call (`PTRACE_SYSCALL`), or at each entry, which it then skips
/// (`PTRACE_SYSEMU`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Mode {
    #[default]
    Cont,
    Syscall,
    Sysemu,
    /// `PTRACE_SINGLESTEP` (`TIF_SINGLESTEP`), and `PTRACE_SYSEMU_SINGLESTEP`
    /// with the syscall-entry stops of `PTRACE_SYSEMU`.
    Step,
    SysemuStep,
}
impl Clone for Local {
    fn clone(&self) -> Self {
        Self {
            forked_by: self.tid,
            orig_rax: self.orig_rax,
            // `copy_thread` copies the selectors.
            selectors: self.selectors,
            ..Self::default()
        }
    }
}
impl Local {
    pub(crate) fn enter(&mut self, tid: u32, orig_rax: u64) {
        self.tid = tid;
        self.orig_rax = orig_rax;
    }
}

/// A task in a ptrace stop (`TASK_TRACED`).
#[derive(Clone, Debug)]
struct Stop {
    cpu: CpuState,
    orig_rax: u64,
    /// `last_siginfo`, the first 48 bytes; none for a group stop of a task
    /// attached without `PTRACE_SEIZE`.
    siginfo: Option<[u8; 48]>,
    /// `ptrace_message`.
    message: u64,
    /// `exit_code`, which a wait reports and clears.
    code: i32,
    /// The signal the tracer resumed it with.
    resumed: Option<i32>,
    /// The signals it blocks, as `PTRACE_GETSIGMASK` shows them (the mask
    /// a `sigsuspend` or `ppoll` puts back, while it waits), and the mask a
    /// `PTRACE_SETSIGMASK` gave it for when it goes on.
    mask: u64,
    new_mask: Option<u64>,
    /// The siginfo of each signal pending for the task and for its process,
    /// in the order they came (`PTRACE_PEEKSIGINFO`).
    queued: Vec<[u8; 128]>,
    shared: Vec<[u8; 128]>,
    /// Its `rseq` registration (`PTRACE_GET_RSEQ_CONFIGURATION`).
    rseq: Option<crate::rseq::Registration>,
    /// `JOBCTL_LISTENING`: after `PTRACE_LISTEN`, it stays stopped but is
    /// not in a stop a wait or a request sees, until the group stop it was
    /// in (`group_stopped`) changes or an interrupt comes, when it traps
    /// again.
    listening: bool,
    group_stopped: bool,
    /// The thread's `TIF_FORCED_TF`, which a tracer's requests change.
    forced_tf: bool,
    /// Its segment selectors, which a tracer may write.
    selectors: [u16; 6],
    /// Its debug registers, which a tracer may write.
    debug: Debug,
}

/// One traced task, which its process's thread group counts while it is
/// traced ([`crate::ThreadGroup::traced`]).
struct Tracee {
    group: Arc<crate::ThreadGroup>,
    /// The tracer, a task, and its process.
    tracer: u32,
    tracer_pid: u32,
    /// The tracee's process.
    pid: u32,
    seized: bool,
    options: u32,
    mode: Mode,
    /// `JOBCTL_TRAP_STOP`: an interrupt, or an attach to a stopped task.
    trap_stop: bool,
    stop: Option<Stop>,
    /// The tracee has exited, and its tracer has not waited for it.
    exited: Option<(ExitStatus, bool, u32)>,
}

impl Drop for Tracee {
    fn drop(&mut self) {
        self.group.set_traced(false);
    }
}

/// The machine's tracees, by task.
#[derive(Default)]
pub(crate) struct Traces {
    tracees: Mutex<BTreeMap<u32, Tracee>>,
    /// The signal each tracee its tracer let go of while it was stopped is
    /// to resume with, and its stop with what the tracer changed there
    /// (registers, mask, siginfo), which Linux's requests write straight
    /// into the task and a detach keeps.
    released: Mutex<BTreeMap<u32, (i32, Stop)>>,
}

/// The tracer as a wait sees a tracee: whether `tid` of `pid` may report
/// to it, and whether only that thread may.
#[derive(Clone, Copy)]
pub(crate) struct Waiter {
    pub pid: u32,
    pub tid: u32,
    pub only_thread: bool,
}

impl Traces {
    fn lock(&self) -> std::sync::MutexGuard<'_, BTreeMap<u32, Tracee>> {
        self.tracees.lock().unwrap_or_else(PoisonError::into_inner)
    }
    /// Whether any task is traced: the fast path of every stop.
    pub(crate) fn any(&self) -> bool {
        !self.lock().is_empty()
    }
    /// The process that traces task `tid`, if it is traced.
    pub(crate) fn tracer_of(&self, tid: u32) -> Option<u32> {
        self.lock().get(&tid).map(|t| t.tracer_pid)
    }
    /// Whether task `tid` is in a ptrace stop.
    pub(crate) fn in_stop(&self, tid: u32) -> bool {
        self.lock().get(&tid).is_some_and(|t| t.stop.is_some())
    }
    /// Whether the exit of process `pid`, traced by another process, waits
    /// for its tracer (Linux's `EXIT_TRACE` zombie).
    pub(crate) fn holds_exit(&self, pid: u32, parent: u32) -> bool {
        self.lock()
            .get(&pid)
            .is_some_and(|t| t.tracer_pid != parent && t.exited.is_some())
    }
    /// Runs `f` on the stop of tracee `tid` (`ESRCH` when it is not in one).
    fn stopped<T>(
        &self,
        tid: u32,
        f: impl FnOnce(&mut Stop) -> Result<T, Errno>,
    ) -> Result<T, Errno> {
        let mut tracees = self.lock();
        let stop = tracees
            .get_mut(&tid)
            .and_then(|t| t.stop.as_mut())
            .ok_or(Errno(3))?;
        f(stop)
    }
    /// Records that tracee `tid` has exited with `status`, with a core if
    /// `dumped`: its tracer's process and its real user ID, if it is traced.
    pub(crate) fn exited(&self, tid: u32, status: ExitStatus, dumped: bool) -> Option<(u32, u32)> {
        let mut tracees = self.lock();
        let tracee = tracees.get_mut(&tid)?;
        tracee.stop = None;
        tracee.trap_stop = false;
        let uid = tracee.group.task_ids(tracee.pid, tid).uid;
        tracee.exited = Some((status, dumped, uid));
        Some((tracee.tracer_pid, uid))
    }
    /// How tracee `tid` was last resumed, its options and whether it was
    /// seized.
    fn settings(&self, tid: u32) -> Option<(Mode, u32, bool)> {
        self.lock().get(&tid).map(|t| (t.mode, t.options, t.seized))
    }
    /// Forgets the tasks of process `pid`, which has been reaped.
    pub(crate) fn forget_process(&self, pid: u32) {
        self.lock().retain(|_, tracee| tracee.pid != pid);
    }
}

impl crate::Processes {
    /// Makes task `tid` of process `pid` (of `group`) traced by `tracer`, a
    /// task, and its process, as Linux's `ptrace_link`; false if it is
    /// traced already.
    pub(crate) fn trace(
        &self,
        tid: u32,
        pid: u32,
        group: &Arc<crate::ThreadGroup>,
        (tracer, tracer_pid): (u32, u32),
        seized: bool,
        options: u32,
    ) -> bool {
        let mut tracees = self.traces.lock();
        if tracees.contains_key(&tid) {
            return false;
        }
        group.set_traced(true);
        tracees.insert(
            tid,
            Tracee {
                group: group.clone(),
                tracer,
                tracer_pid,
                pid,
                seized,
                options,
                mode: Mode::Cont,
                trap_stop: false,
                stop: None,
                exited: None,
            },
        );
        true
    }
    /// Lets go of tracee `tid`, as Linux's `__ptrace_detach`: one in a
    /// ptrace stop goes on with `signal`, or for a tracer that exits, with
    /// the signal it stopped for if its tracer did not wait for the stop. A
    /// traced thread that has exited goes; a process whose exit its tracer
    /// held is its parent's to wait for now.
    pub(crate) fn untrace(&self, tid: u32, signal: Option<i32>) {
        let Some(mut tracee) = self.traces.lock().remove(&tid) else {
            return;
        };
        if let Some(stop) = tracee.stop.take() {
            let code = if (1..=64).contains(&stop.code) {
                stop.code
            } else {
                0
            };
            self.traces
                .released
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .insert(tid, (signal.unwrap_or(code), stop));
        }
        let (pid, exited) = (tracee.pid, tracee.exited.is_some());
        drop(tracee);
        if exited && tid == pid {
            self.exit_untraced(pid);
        }
        self.changed().notify();
    }
    /// Thread `tid`, traced, other than its process's leader, has exited
    /// with `status`: its tracer is told, as by Linux's `do_notify_parent`
    /// with SIGCHLD, and waits for it.
    pub(crate) fn traced_thread_exit(&self, tid: u32, status: ExitStatus) {
        let Some(tracer) = self.traces.exited(tid, status, false) else {
            return;
        };
        if let Some(view) = self.view(tracer.0) {
            let (code, status) = match status {
                ExitStatus::Signaled(signal) => (signals::CLD_KILLED, signal),
                ExitStatus::Exited(code) => (signals::CLD_EXITED, code & 255),
                _ => (signals::CLD_EXITED, 0),
            };
            view.group.notify_child(
                code,
                signals::ChildSignal {
                    pid: view.space.number(tid),
                    uid: tracer.1,
                    status,
                    cpu: 0,
                },
            );
        }
        self.changed().notify();
    }
    /// The ptrace stop or exit of a task traced by `waiter` that a wait
    /// for `wanted` reports, as Linux's `ptrace_do_wait` finds it, and
    /// whether any task it traces is wanted at all. A stop is reported
    /// whatever the wait asks for, as Linux's `wait_task_stopped` does for
    /// a tracer; the exit of a process traced by its parent is its
    /// parent's wait's ([`crate::Processes::reap`]).
    pub(crate) fn reap_traced(
        &self,
        waiter: Waiter,
        space: &crate::namespaces::Namespace,
        wanted: Wanted,
        wait: WaitFor,
    ) -> (Option<(u32, ChildEvent, u64, u32)>, bool) {
        let groups = self.traced_groups();
        let mut released = None;
        let found = {
            let mut tracees = self.traces.lock();
            let mut any = false;
            let mut found = None;
            for (&tid, tracee) in tracees.iter_mut() {
                if tracee.tracer_pid != waiter.pid
                    || (waiter.only_thread && tracee.tracer != waiter.tid)
                {
                    continue;
                }
                let Some((group, pgid, parent)) = groups.get(&tracee.pid) else {
                    continue;
                };
                let matching = match wanted {
                    Wanted::Any => true,
                    Wanted::Pid(wanted) => wanted == tid,
                    Wanted::Pgid(wanted) => *pgid == wanted,
                };
                if !matching {
                    continue;
                }
                // A leader traced by its parent exits to its parent's wait.
                let own = tid == tracee.pid && *parent == waiter.pid;
                if let Some((status, dumped, uid)) = tracee.exited {
                    if own {
                        continue;
                    }
                    any |= wait.exits || wait.continues;
                    if !wait.exits {
                        continue;
                    }
                    // Once the group has exited, Linux's wait_task_zombie
                    // reports the group's exit code for each of its threads.
                    let event = match group.status().unwrap_or(status) {
                        ExitStatus::Signaled(signal) if dumped => ChildEvent::Dumped(signal),
                        status => ChildEvent::Exited(status),
                    };
                    found = Some((tid, event, group.process_cpu(), uid, !wait.keep));
                    break;
                }
                any = true;
                if let Some(stop) = tracee.stop.as_mut()
                    && stop.code != 0
                    && !stop.listening
                {
                    let code = stop.code;
                    if !wait.keep {
                        stop.code = 0;
                    }
                    let uid = group.task_ids(tracee.pid, tid).uid;
                    found = Some((
                        tid,
                        ChildEvent::Trapped(code),
                        group.process_cpu(),
                        uid,
                        false,
                    ));
                    break;
                }
            }
            if let Some((tid, _, _, _, true)) = found {
                released = tracees.remove(&tid).map(|t| (tid, t.pid));
            }
            (found, any)
        };
        // The tracer has waited for a process another one is the parent
        // of: its parent learns of the exit now.
        if let Some((tid, pid)) = released
            && tid == pid
        {
            self.exit_untraced(pid);
        }
        let (found, any) = found;
        (
            found.map(|(tid, event, cpu, uid, _)| (space.number(tid), event, cpu, uid)),
            any,
        )
    }
}

/// The 27 registers of `user_regs_struct` of a stopped task.
fn regs(stop: &Stop) -> [u64; 27] {
    let cpu = &stop.cpu;
    let mut out = [0u64; 27];
    for (slot, &r) in GENERAL.iter().enumerate() {
        out[slot] = cpu.gpr[r];
    }
    out[ORIG_RAX as usize] = stop.orig_rax;
    out[RIP as usize] = cpu.rip.0;
    for (&slot, &selector) in SELECTOR_SLOTS.iter().zip(&stop.selectors) {
        out[slot as usize] = u64::from(selector);
    }
    // A trap flag the tracer set is not shown (`get_flags`).
    out[EFLAGS as usize] = if stop.forced_tf {
        cpu.rflags & !flag::TF
    } else {
        cpu.rflags
    };
    out[RSP as usize] = cpu.gpr[reg::RSP];
    out[FS_BASE as usize] = cpu.fs_base;
    out[GS_BASE as usize] = cpu.gs_base;
    out
}

/// Linux's `putreg`: register `index` of `user_regs_struct` takes `value`.
/// A segment selector must be null or of user privilege, and `cs` and `ss`
/// not null (`EIO`); the selectors cannot be changed here, so a valid one
/// is taken and left as it is. The flags change only where a tracer may
/// change them, and a segment base must be below `TASK_SIZE_MAX` (`EIO`).
fn putreg(stop: &mut Stop, index: u64, value: u64) -> Result<(), Errno> {
    let cpu = &mut stop.cpu;
    match index {
        0..=14 => cpu.gpr[GENERAL[index as usize]] = value,
        ORIG_RAX => stop.orig_rax = value,
        RIP => cpu.rip = GuestAddr(value),
        RSP => cpu.gpr[reg::RSP] = value,
        EFLAGS => {
            // `set_flags`: a trap flag written is the thread's own; one the
            // tracer set stays while it steps.
            let mut value = value;
            if value & flag::TF != 0 {
                stop.forced_tf = false;
            } else if stop.forced_tf {
                value |= flag::TF;
            }
            let cpu = &mut stop.cpu;
            cpu.rflags = (cpu.rflags & !FLAG_MASK) | (value & FLAG_MASK);
        }
        // `set_segment_reg`: a null or user selector, `cs` and `ss` not
        // null; it is kept as written. A new `fs` or `gs` selector leaves the
        // base as it is, as with FSGSBASE.
        CS | SS | DS | ES | FS | GS => {
            let selector = value as u16;
            if selector != 0 && selector & 3 != 3 || matches!(index, CS | SS) && selector == 0 {
                return Err(Errno::EIO);
            }
            if let Some(slot) = SELECTOR_SLOTS.iter().position(|&s| s == index) {
                stop.selectors[slot] = selector;
            }
        }
        FS_BASE | GS_BASE => {
            if value >= TASK_SIZE_MAX {
                return Err(Errno::EIO);
            }
            if index == FS_BASE {
                cpu.fs_base = value;
            } else {
                cpu.gs_base = value;
            }
        }
        _ => return Err(Errno::EIO),
    }
    Ok(())
}

/// What `rax` shows a tracer of a task stopped as a call it was in is to
/// run again, as Linux returns the restart codes: `ERESTART_RESTARTBLOCK`
/// for a wait `restart_syscall` resumes, `ERESTARTNOINTR` for a call a
/// signal took back from a seccomp listener whatever the handler,
/// `ERESTARTSYS` for one a `SA_RESTART` handler runs again, and
/// `ERESTARTNOHAND` for the rest.
pub(crate) fn restart_code(restart: Option<u64>, seccomp: Option<bool>) -> Option<u64> {
    let number = restart?;
    Some(match (number, seccomp) {
        (_, Some(true)) => ERESTARTNOINTR,
        (_, Some(false)) => ERESTARTSYS,
        (219, _) => ERESTART_RESTARTBLOCK,
        (number, _) if signals::restarts_with_handler(number) => ERESTARTSYS,
        _ => ERESTARTNOHAND,
    })
}

/// The restart of the call a checkpoint follows, as the checkpoint took
/// it ([`crate::ThreadState::restart`] and `seccomp_restart`).
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Restart {
    pub number: Option<u64>,
    pub seccomp: Option<bool>,
    /// `-ERESTARTNOHAND` or `-ERESTART_RESTARTBLOCK` a tracer left: no
    /// restart once a handler runs.
    pub no_handler: bool,
    /// The thread has stopped for its tracer since.
    pub traced: bool,
}

/// How a ptrace stop of the tracee ended.
pub(crate) enum Resumed {
    /// The tracer resumed it, or let it go, with this signal (0 for none)
    /// and the siginfo it left.
    With(i32, Option<[u8; 48]>),
    /// It was not traced, or a fatal signal came first.
    Not,
}

/// The siginfo of a trap the tracee reports itself (`ptrace_do_notify`):
/// `signal`, with `code` as its `si_code`, from the tracee.
fn notify_siginfo(signal: i32, code: i32, pid: u32, uid: u32) -> [u8; 48] {
    let mut info = [0u8; 48];
    info[0..4].copy_from_slice(&signal.to_le_bytes());
    info[8..12].copy_from_slice(&code.to_le_bytes());
    info[16..20].copy_from_slice(&pid.to_le_bytes());
    info[20..24].copy_from_slice(&uid.to_le_bytes());
    info
}

impl Kernel {
    /// Whether this thread is traced.
    pub(crate) fn traced(&self, tid: u32) -> bool {
        self.processes.traces.any() && self.processes.traces.tracer_of(tid).is_some()
    }

    /// Linux's `ptrace_stop`: the thread stops for its tracer with `code`
    /// (the signal a wait reports, with the event above it), the siginfo
    /// `siginfo` and the message `message`, the tracer learns of it
    /// (`SIGCHLD` with `CLD_TRAPPED`, or `CLD_STOPPED` for a `group` stop,
    /// unless it ignores the signal or set `SA_NOCLDSTOP`), and it waits.
    /// `rax` shows `restart`'s code while it waits, if a call is to run
    /// again. The registers the tracer left are the thread's when it goes
    /// on.
    pub(crate) fn ptrace_stop(
        &mut self,
        thread: &mut Thread,
        code: i32,
        group: bool,
        message: u64,
        siginfo: Option<[u8; 48]>,
        restart: &mut Restart,
    ) -> Resumed {
        let traces = &self.processes.traces;
        let shown = if restart.no_handler {
            restart.number.map(|number| {
                if number == 219 {
                    ERESTART_RESTARTBLOCK
                } else {
                    ERESTARTNOHAND
                }
            })
        } else {
            restart_code(restart.number, restart.seccomp)
        }
        .filter(|_| thread.cpu.gpr[reg::RAX] == Errno(4).to_syscall_return());
        if self.fatal_pending(thread) {
            return Resumed::Not;
        }
        let tracer = {
            let mut tracees = traces.lock();
            let Some(tracee) = tracees.get_mut(&thread.tid) else {
                return Resumed::Not;
            };
            let mut cpu = thread.cpu.clone();
            if let Some(shown) = shown {
                cpu.gpr[reg::RAX] = shown;
            }
            tracee.trap_stop = false;
            restart.traced = true;
            let (queued, shared) = self.pending_siginfos(thread);
            tracee.stop = Some(Stop {
                cpu,
                orig_rax: thread.state.ptrace.orig_rax,
                siginfo,
                message,
                code,
                resumed: None,
                mask: thread
                    .state
                    .wait_restore_mask
                    .unwrap_or(thread.state.signal_mask),
                new_mask: None,
                queued,
                shared,
                rseq: thread.state.rseq,
                listening: false,
                group_stopped: self.group.is_stopped(),
                forced_tf: thread.state.ptrace.forced_tf,
                selectors: thread.state.ptrace.selectors.unwrap_or(SELECTORS),
                debug: thread.state.ptrace.debug,
            });
            tracee.tracer_pid
        };
        // `do_notify_parent_cldstop` for the tracer.
        if let Some(view) = self.processes.view(tracer)
            && view.group.wants_stop_notices()
        {
            view.group.notify_child(
                if group {
                    signals::CLD_STOPPED
                } else {
                    CLD_TRAPPED
                },
                signals::ChildSignal {
                    pid: view.space.number(thread.tid),
                    uid: thread.state.credentials.task_ids().uid,
                    status: code & 0x7f,
                    cpu: self.group.process_cpu(),
                },
            );
        }
        self.processes.changed().notify();
        let resumed = loop {
            let ticket = self.processes.changed().value();
            {
                let mut tracees = traces.lock();
                match tracees.get_mut(&thread.tid) {
                    Some(tracee) => {
                        if let Some(signal) = tracee.stop.as_ref().and_then(|stop| stop.resumed) {
                            break Some((signal, tracee.stop.take()));
                        }
                        // A listening tracee traps again once its group
                        // stop changes or an interrupt comes
                        // (`ptrace_trap_notify`). Each wakes it at once: a
                        // stop and a SIGCONT notify the wait, and an
                        // interrupt its inbox; the wait's 10 ms deadline
                        // is only for a wake-up missed.
                        if let Some(stop) = &tracee.stop
                            && stop.listening
                            && (stop.group_stopped != self.group.is_stopped() || tracee.trap_stop)
                        {
                            tracee.trap_stop = true;
                            break Some((0, tracee.stop.take()));
                        }
                    }
                    // Let go of: it resumes with what its tracer left.
                    None => {
                        let released = traces
                            .released
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner)
                            .remove(&thread.tid);
                        break released.map(|(signal, stop)| (signal, Some(stop)));
                    }
                }
            }
            if self.fatal_pending(thread) {
                if let Some(tracee) = traces.lock().get_mut(&thread.tid) {
                    tracee.stop = None;
                }
                break None;
            }
            // Signals that came meanwhile, for PTRACE_PEEKSIGINFO.
            let (queued, shared) = self.pending_siginfos(thread);
            if let Some(stop) = traces
                .lock()
                .get_mut(&thread.tid)
                .and_then(|t| t.stop.as_mut())
            {
                stop.queued = queued;
                stop.shared = shared;
            }
            let _ = self.wait_for_children(ticket);
        };
        self.processes.changed().notify();
        match resumed {
            None => Resumed::Not,
            Some((signal, Some(stop))) => {
                Self::take_registers(thread, &stop, shown, restart);
                Resumed::With(signal, stop.siginfo)
            }
            Some((signal, None)) => Resumed::With(signal, siginfo),
        }
    }

    /// The tracee takes back the registers of `stop`. A restart code still
    /// in `rax` runs the call again as before; anything else the tracer
    /// put there, or an `orig_rax` of -1, ends the restart, and another
    /// `orig_rax` is the call that runs again.
    fn take_registers(thread: &mut Thread, stop: &Stop, shown: Option<u64>, restart: &mut Restart) {
        let before = thread.state.ptrace.orig_rax;
        thread.cpu = stop.cpu.clone();
        thread.state.ptrace.forced_tf = stop.forced_tf;
        // PTRACE_SETSIGMASK: the mask, and no other to put back.
        if let Some(mask) = stop.new_mask {
            thread.state.signal_mask = mask;
            thread.state.wait_restore_mask = None;
        }
        thread.state.ptrace.selectors = (stop.selectors != SELECTORS).then_some(stop.selectors);
        thread.state.ptrace.debug = stop.debug;
        let orig = stop.orig_rax;
        if orig != before {
            thread.state.ptrace.orig_rax = orig;
        }
        // The restart of a call a signal interrupted goes by the restart
        // code in rax, as Linux's `arch_do_signal_or_restart` and
        // `handle_signal` take it, whichever the call left or the tracer
        // wrote: the call in `orig_rax` runs again, as `restart_syscall` for
        // `-ERESTART_RESTARTBLOCK`. Anything else in rax, or `orig_rax`
        // below 0, ends the restart, and the thread sees what rax has.
        let code = thread.cpu.gpr[reg::RAX];
        match code {
            ERESTARTSYS | ERESTARTNOINTR | ERESTARTNOHAND | ERESTART_RESTARTBLOCK
                if shown.is_some() && (orig as i64) >= 0 =>
            {
                thread.cpu.gpr[reg::RAX] = Errno(4).to_syscall_return();
                restart.number = Some(if code == ERESTART_RESTARTBLOCK {
                    219
                } else {
                    u64::from(orig as u32)
                });
                restart.seccomp = match code {
                    ERESTARTNOINTR => Some(true),
                    ERESTARTSYS => Some(false),
                    _ => None,
                };
                restart.no_handler = matches!(code, ERESTARTNOHAND | ERESTART_RESTARTBLOCK);
                if code != ERESTART_RESTARTBLOCK {
                    thread.state.syscall_rax = orig;
                }
            }
            _ if shown.is_some() || (orig as i64) < 0 => {
                restart.number = None;
                restart.seccomp = None;
                restart.no_handler = false;
            }
            _ => {}
        }
    }

    /// Whether a fatal signal waits for the thread, which ends any ptrace
    /// stop: SIGKILL, or the end of its process that another thread began
    /// (Linux sends those threads SIGKILL; the thread that ends it still
    /// stops for `PTRACE_EVENT_EXIT`).
    fn fatal_pending(&self, thread: &mut Thread) -> bool {
        self.group.drain_process(&mut thread.state);
        self.inbox.drain(&mut thread.state);
        (self.group.status().is_some() && thread.state.exit_status.is_none())
            || self.group.killed()
            || thread.state.pending.iter().any(|s| s.number == SIGKILL)
    }

    /// The siginfo of each signal pending for the thread, then for its
    /// process, in the order they came.
    fn pending_siginfos(&self, thread: &Thread) -> (Vec<[u8; 128]>, Vec<[u8; 128]>) {
        let info = |signal: &signals::PendingSignal| signals::siginfo(&thread.state, signal);
        let queued = thread.state.pending.iter().map(info).collect();
        let shared = self
            .group
            .process_pending_signals()
            .iter()
            .map(info)
            .collect();
        (queued, shared)
    }

    /// `SECCOMP_RET_TRACE` with the filter's `data` (`__seccomp_filter`):
    /// without a tracer that asked for `PTRACE_EVENT_SECCOMP`, the call
    /// returns `ENOSYS`; otherwise the thread stops for the event with
    /// `data` as its message and `rax` at `-ENOSYS`. The call to run then,
    /// which the filters see again, unless the thread was killed or the
    /// tracer set `orig_rax` below 0, when it does not run and `rax` stays.
    pub(crate) fn ptrace_seccomp(&mut self, thread: &mut Thread, data: u16) -> Option<u64> {
        thread.cpu.gpr[reg::RAX] = Errno::ENOSYS.to_syscall_return();
        let enabled = self.group.traced()
            && self
                .processes
                .traces
                .settings(thread.tid)
                .is_some_and(|(_, options, _)| options & PTRACE_O_TRACESECCOMP != 0);
        if !enabled {
            return None;
        }
        self.ptrace_report(
            thread,
            SIGTRAP | PTRACE_EVENT_SECCOMP << 8,
            u64::from(data),
            &mut Restart::default(),
        );
        let number = thread.state.ptrace.orig_rax;
        if self.fatal_pending(thread) || (number as i32) < 0 {
            return None;
        }
        thread.cpu.gpr[reg::RAX] = number;
        Some(u64::from(number as u32))
    }

    /// Linux's `ptrace_notify`: the thread stops with `code`, `SIGTRAP`
    /// with an event or `0x80` above it, and `message`, its siginfo the
    /// trap's own. The signal its tracer resumed it with, or none if it was
    /// killed or is no longer traced.
    fn ptrace_report(
        &mut self,
        thread: &mut Thread,
        code: i32,
        message: u64,
        restart: &mut Restart,
    ) -> Option<i32> {
        let info = notify_siginfo(
            SIGTRAP,
            code,
            self.pid_space(thread.tid).number(thread.tid),
            thread.state.credentials.task_ids().uid,
        );
        match self.ptrace_stop(thread, code, false, message, Some(info), restart) {
            Resumed::With(signal, _) => Some(signal),
            Resumed::Not => None,
        }
    }

    /// Linux's `ptrace_event`: the thread stops for `event` with `message`
    /// if its tracer asked for it. A signal its tracer resumes it with is
    /// not delivered. `rax` shows `-ENOSYS` while it waits, which a call
    /// has until it returns, and keeps its value.
    fn ptrace_event(&mut self, thread: &mut Thread, event: i32, message: u64) {
        let Some((_, options, _)) = self.processes.traces.settings(thread.tid) else {
            return;
        };
        if options & (1 << event) == 0 {
            return;
        }
        let value = thread.cpu.gpr[reg::RAX];
        thread.cpu.gpr[reg::RAX] = Errno::ENOSYS.to_syscall_return();
        self.ptrace_report(
            thread,
            SIGTRAP | event << 8,
            message,
            &mut Restart::default(),
        );
        thread.cpu.gpr[reg::RAX] = value;
    }

    /// The syscall stop `code` of a thread traced with
    /// `PTRACE_O_TRACESYSGOOD` or not.
    fn syscall_code(options: u32) -> i32 {
        SIGTRAP
            | if options & PTRACE_O_TRACESYSGOOD != 0 {
                0x80
            } else {
                0
            }
    }

    /// Linux's `ptrace_report_syscall` for a signal the tracer resumed a
    /// syscall stop with: `send_sig` with `SEND_SIG_PRIV`, to the process
    /// (`PIDTYPE_TGID`) from the kernel.
    fn syscall_signal(&self, signal: Option<i32>) {
        if let Some(signal) = signal.filter(|&s| s != 0) {
            self.processes.signal_from_kernel(self.process.pid, signal);
        }
    }

    /// The syscall-entry stop of a thread its tracer resumed with
    /// `PTRACE_SYSCALL` or `PTRACE_SYSEMU` (`syscall_trace_enter`), with
    /// `rax` at `-ENOSYS` and the call in `orig_rax`. Whether the call runs:
    /// not when the thread was killed meanwhile, under `PTRACE_SYSEMU`, or
    /// when the tracer made its number -1, where `rax` stays as the tracer
    /// left it. Otherwise the call is the one `orig_rax` names now, with the
    /// arguments the registers have.
    pub(crate) fn ptrace_syscall_entry(&mut self, thread: &mut Thread) -> bool {
        let Some((mode, options, _)) = self.processes.traces.settings(thread.tid) else {
            return true;
        };
        if matches!(mode, Mode::Cont | Mode::Step) {
            return true;
        }
        thread.cpu.gpr[reg::RAX] = Errno::ENOSYS.to_syscall_return();
        let signal = self.ptrace_report(
            thread,
            Self::syscall_code(options),
            PTRACE_EVENTMSG_SYSCALL_ENTRY,
            &mut Restart::default(),
        );
        self.syscall_signal(signal);
        if self.fatal_pending(thread) || matches!(mode, Mode::Sysemu | Mode::SysemuStep) {
            return false;
        }
        let number = thread.state.ptrace.orig_rax;
        if number as i32 == -1 {
            return false;
        }
        thread.cpu.gpr[reg::RAX] = number;
        true
    }

    /// The syscall-exit stop of a thread whose tracer resumed it with
    /// `PTRACE_SYSCALL` (`syscall_exit_work`); `rax` has what the call
    /// returned, or the code of its restart.
    fn ptrace_syscall_exit(&mut self, thread: &mut Thread, restart: &mut Restart) {
        let options = match self.processes.traces.settings(thread.tid) {
            Some((Mode::Syscall, options, _)) => options,
            // Single-stepped over the call: the trap its instruction would
            // have given comes now (`user_single_step_report`, SIGTRAP with
            // TRAP_BRKPT at the address after it).
            Some((Mode::Step, _, _)) => {
                signals::queue(
                    &mut thread.state,
                    signals::PendingSignal {
                        target: signals::PendingTarget::Thread,
                        addr: thread.cpu.rip.0,
                        trap: 1,
                        synchronous: true,
                        ..signals::PendingSignal::thread(SIGTRAP, TRAP_BRKPT)
                    },
                );
                return;
            }
            _ => return,
        };
        let signal = self.ptrace_report(
            thread,
            Self::syscall_code(options),
            PTRACE_EVENTMSG_SYSCALL_EXIT,
            restart,
        );
        self.syscall_signal(signal);
    }

    /// A thread is about to enter a signal handler: if it is
    /// single-stepped, stepping ends before its frame is written, so that
    /// the frame does not keep a trap flag its tracer set, as Linux's
    /// `handle_signal` calls `user_disable_single_step` first. Whether it
    /// was stepped, for [`Self::ptrace_handler_entered`].
    pub(crate) fn ptrace_handler_entering(&mut self, thread: &mut Thread) -> bool {
        if !self.group.traced() {
            return false;
        }
        let mut tracees = self.processes.traces.lock();
        let Some(tracee) = tracees.get_mut(&thread.tid) else {
            return false;
        };
        if !matches!(tracee.mode, Mode::Step | Mode::SysemuStep) {
            return false;
        }
        tracee.mode = if tracee.mode == Mode::SysemuStep {
            Mode::Sysemu
        } else {
            Mode::Cont
        };
        if std::mem::take(&mut thread.state.ptrace.forced_tf) {
            thread.cpu.rflags &= !flag::TF;
        }
        true
    }

    /// A single-stepped thread has entered a signal handler: it stops with
    /// SIGTRAP before the handler's first instruction, as Linux's
    /// `signal_delivered` reports it (`ptrace_notify`).
    pub(crate) fn ptrace_handler_entered(&mut self, thread: &mut Thread, restart: &mut Restart) {
        self.ptrace_report(thread, SIGTRAP, 0, restart);
    }

    /// A traced thread enters `clone` (56), `fork` (57) or `vfork` (58),
    /// `clone` with flags `flags`.
    pub(crate) fn ptrace_clone(&self, thread: &mut Thread, number: u64, flags: u64) {
        let flags = match number {
            57 => SIGCHLD,
            58 => CLONE_VFORK | 0x100 | SIGCHLD,
            _ => flags,
        };
        thread.state.ptrace.clone = Some(Cloned {
            flags,
            child: None,
            event: None,
        });
    }

    /// After a traced thread's `clone` made a task, which has not started:
    /// the event its tracer asked for (`PTRACE_EVENT_FORK`, `VFORK` or
    /// `CLONE`, none for `CLONE_UNTRACED`), and the new task traced by the
    /// same tracer with the same options if it asked for the event or the
    /// call for `CLONE_PTRACE` (`ptrace_init_task`): seized, it starts with
    /// `PTRACE_EVENT_STOP`, otherwise with `SIGSTOP` pending. No task was
    /// made: the checkpoint the call held back runs now.
    pub(crate) fn ptrace_cloned(
        &mut self,
        thread: &mut Thread,
        mem: &AddressSpace,
        next: Next,
    ) -> Next {
        let Some(mut cloned) = thread.state.ptrace.clone else {
            thread.state.ptrace.hold = false;
            return next;
        };
        let Some((child, child_thread)) = self.pending_child.as_mut() else {
            thread.state.ptrace.hold = false;
            thread.state.ptrace.clone = None;
            return self.checkpoint(thread, mem);
        };
        let flags = cloned.flags;
        let event = if flags & CLONE_UNTRACED != 0 {
            None
        } else if flags & CLONE_VFORK != 0 {
            Some(PTRACE_EVENT_VFORK)
        } else if flags & 0xff != SIGCHLD {
            Some(PTRACE_EVENT_CLONE)
        } else {
            Some(PTRACE_EVENT_FORK)
        };
        let traces = &self.processes.traces;
        let parent = traces
            .lock()
            .get(&thread.tid)
            .map(|t| (t.tracer, t.tracer_pid, t.seized, t.options));
        // `copy_process`'s `user_disable_single_step`: the new task does
        // not keep a trap flag its maker's tracer set.
        if thread.state.ptrace.forced_tf {
            child_thread.cpu.rflags &= !flag::TF;
        }
        if let Some((tracer, tracer_pid, seized, options)) = parent {
            let event = event.filter(|&e| options & (1 << e) != 0);
            if event.is_some() || flags & CLONE_PTRACE != 0 {
                let tid = child_thread.tid;
                let pid = child.process.pid;
                if self.processes.trace(
                    tid,
                    pid,
                    &child.group,
                    (tracer, tracer_pid),
                    seized,
                    options,
                ) {
                    if seized {
                        if let Some(tracee) = traces.lock().get_mut(&tid) {
                            tracee.trap_stop = true;
                        }
                    } else {
                        // `sigaddset` alone: no siginfo was queued, so it
                        // is `SI_USER` from no one.
                        signals::queue(
                            &mut child_thread.state,
                            signals::PendingSignal {
                                queued: Some([0; 48]),
                                ..signals::PendingSignal::thread(SIGSTOP, 0)
                            },
                        );
                    }
                }
            }
            cloned.event = event;
            cloned.child = Some(child_thread.tid);
        }
        thread.state.ptrace.clone = Some(cloned);
        next
    }

    /// The task a `clone` made has started, or failed to (`started`), when
    /// the call fails and no event is reported, as in Linux's
    /// `kernel_clone`. Once it started, the thread reports the event
    /// its tracer asked for with the task as its tracer's PID namespace
    /// numbers it, waits for a `vfork` child to exec or exit, then reports
    /// `PTRACE_EVENT_VFORK_DONE`, as Linux's `kernel_clone` does; its
    /// checkpoints go on after. The error of a wait the thread was killed
    /// in.
    ///
    /// # Errors
    ///
    /// As [`Kernel::wait_vfork`].
    pub fn child_started(
        &mut self,
        thread: &mut Thread,
        started: bool,
        kill: &AtomicBool,
    ) -> Result<(), Errno> {
        thread.state.ptrace.hold = false;
        let cloned = thread.state.ptrace.clone.take();
        // A task that never ran is not traced either.
        if !started {
            if let Some(Cloned {
                child: Some(child), ..
            }) = cloned
            {
                self.processes.traces.lock().remove(&child);
            }
            return self.wait_vfork(kill);
        }
        let tid = thread.tid;
        let number = |kernel: &Self, child: u32| {
            kernel
                .processes
                .traces
                .tracer_of(tid)
                .and_then(|tracer| kernel.processes.view(tracer))
                .map_or(0, |view| u64::from(view.space.number(child)))
        };
        if let Some(Cloned {
            child: Some(child),
            event: Some(event),
            ..
        }) = cloned
        {
            let message = number(self, child);
            self.ptrace_event(thread, event, message);
        }
        self.wait_vfork(kill)?;
        if let Some(Cloned {
            flags,
            child: Some(child),
            ..
        }) = cloned
            && flags & CLONE_VFORK != 0
        {
            let message = number(self, child);
            self.ptrace_event(thread, PTRACE_EVENT_VFORK_DONE, message);
        }
        Ok(())
    }

    /// Linux's `ptrace_signal`: the thread reports signal `signal`, which
    /// it took, to its tracer. `None` when the tracer cancelled it, or
    /// gave a signal the thread blocks, which is queued again; otherwise
    /// the signal to deliver, the tracer's if it gave another (sent by the
    /// tracer, `SI_USER`) or changed the siginfo.
    pub(crate) fn ptrace_signal(
        &mut self,
        thread: &mut Thread,
        signal: signals::PendingSignal,
        restart: &mut Restart,
    ) -> Option<signals::PendingSignal> {
        let mut info = [0u8; 48];
        info.copy_from_slice(&signals::siginfo(&thread.state, &signal)[..48]);
        let (given, edited) =
            match self.ptrace_stop(thread, signal.number, false, 0, Some(info), restart) {
                Resumed::With(given, edited) => (given, edited.unwrap_or(info)),
                // Killed: the signal waits, as Linux queues it again.
                Resumed::Not => {
                    signals::queue(&mut thread.state, signal);
                    return None;
                }
            };
        if given == 0 {
            return None;
        }
        let signo = i32::from_le_bytes([edited[0], edited[1], edited[2], edited[3]]);
        let signal = if given != signo {
            // Another signal: sent by the tracer, as the thread's PID
            // namespace numbers it.
            let (sender, uid) = self.tracer_identity(thread);
            let mut fresh = [0u8; 48];
            fresh[0..4].copy_from_slice(&given.to_le_bytes());
            fresh[16..20].copy_from_slice(&sender.to_le_bytes());
            fresh[20..24].copy_from_slice(&uid.to_le_bytes());
            signals::PendingSignal {
                queued: Some(fresh),
                ..signals::PendingSignal::thread(given, 0)
            }
        } else if edited != info {
            signals::PendingSignal {
                queued: Some(edited),
                ..signal
            }
        } else {
            signal
        };
        // A fault's signal was unblocked as it was forced; any other the
        // thread blocks waits.
        let blocked = thread.state.signal_mask & (1u64 << (given - 1)) != 0 && !signal.synchronous;
        if blocked || self.fatal_pending(thread) {
            signals::queue(&mut thread.state, signal);
            return None;
        }
        Some(signal)
    }
}

impl Kernel {
    /// The tracer of `thread` as the thread's PID namespace numbers its
    /// task, and its real user ID: who a signal the tracer gave in place of
    /// another is from (`ptrace_signal`).
    fn tracer_identity(&self, thread: &Thread) -> (u32, u32) {
        let Some((tracer, tracer_pid)) = self
            .processes
            .traces
            .lock()
            .get(&thread.tid)
            .map(|t| (t.tracer, t.tracer_pid))
        else {
            return (0, 0);
        };
        let uid = self
            .processes
            .view(tracer_pid)
            .map_or(0, |view| view.group.task_ids(tracer_pid, tracer).uid);
        (self.pid_space(thread.tid).number(tracer), uid)
    }

    /// The ptrace traps a checkpoint takes before any signal, as Linux's
    /// `get_signal` does: the group stop now in effect, which a traced
    /// thread reports to its tracer once and then runs on while its tracer
    /// lets it (`do_signal_stop`, then `do_jobctl_trap`), and an interrupt
    /// (`PTRACE_INTERRUPT`, or an attach to a stopped task).
    pub(crate) fn ptrace_traps(&mut self, thread: &mut Thread, restart: &mut Restart) {
        let in_syscall = std::mem::take(&mut thread.state.ptrace.in_syscall);
        if !self.group.traced() || !self.traced(thread.tid) {
            thread.state.ptrace.group_stopped = false;
            thread.state.ptrace.exec = None;
            return;
        }
        // `execve` reports its event, then returns (`exec_binprm`).
        if let Some(old) = thread.state.ptrace.exec.take() {
            self.ptrace_exec_event(thread, old);
        }
        if in_syscall {
            self.ptrace_syscall_exit(thread, restart);
        }
        loop {
            if thread.state.stopped {
                if !thread.state.ptrace.group_stopped {
                    thread.state.ptrace.group_stopped = true;
                    self.ptrace_job_trap(thread, restart);
                }
                // The tracer lets it run while the group is stopped.
                if self.traced(thread.tid) {
                    thread.state.stopped = false;
                }
            } else {
                thread.state.ptrace.group_stopped = false;
            }
            let trap = self
                .processes
                .traces
                .lock()
                .get(&thread.tid)
                .is_some_and(|t| t.trap_stop);
            if !trap || self.fatal_pending(thread) {
                return;
            }
            self.ptrace_job_trap(thread, restart);
        }
    }

    /// Linux's `do_jobctl_trap`: a seized thread reports
    /// `PTRACE_EVENT_STOP` with the stop signal of the group stop in effect,
    /// or `SIGTRAP` without one, and its siginfo; one attached otherwise
    /// reports the stop signal alone, with no siginfo.
    fn ptrace_job_trap(&mut self, thread: &mut Thread, restart: &mut Restart) {
        let Some(seized) = self
            .processes
            .traces
            .lock()
            .get(&thread.tid)
            .map(|t| t.seized)
        else {
            return;
        };
        if seized {
            // A listening tracee woken by a change traps again at once.
            loop {
                let stopped = self.group.is_stopped();
                let signal = if stopped {
                    self.group.stop_signal()
                } else {
                    SIGTRAP
                };
                let code = signal | PTRACE_EVENT_STOP << 8;
                let info = notify_siginfo(
                    signal,
                    code,
                    self.pid_space(thread.tid).number(thread.tid),
                    thread.state.credentials.task_ids().uid,
                );
                self.ptrace_stop(thread, code, true, 0, Some(info), restart);
                let again = self
                    .processes
                    .traces
                    .lock()
                    .get_mut(&thread.tid)
                    .is_some_and(|t| std::mem::take(&mut t.trap_stop));
                if !again || self.fatal_pending(thread) {
                    break;
                }
            }
        } else {
            let stopped = self.group.is_stopped();
            let stop_signal = if stopped { self.group.stop_signal() } else { 0 };
            let signal = if stopped { stop_signal } else { SIGSTOP };
            self.ptrace_stop(thread, signal, true, 0, None, restart);
        }
    }

    /// A traced thread starts or joins the group stop of `signal`: it
    /// stops for its tracer, then goes on as its tracer lets it.
    pub(crate) fn ptrace_group_stop(&mut self, thread: &mut Thread, restart: &mut Restart) {
        thread.state.ptrace.group_stopped = true;
        self.ptrace_job_trap(thread, restart);
        if self.traced(thread.tid) {
            thread.state.stopped = false;
        }
    }

    /// After an `execve` of a traced thread, which reports it at its next
    /// checkpoint: a thread other than the leader has taken the leader's
    /// number, and is traced by that number now (`de_thread`).
    pub(crate) fn ptrace_exec(&mut self, thread: &mut Thread) {
        if !self.group.traced() {
            return;
        }
        let old = thread.state.ptrace.tid;
        {
            let mut tracees = self.processes.traces.lock();
            if old != thread.tid
                && let Some(tracee) = tracees.remove(&old)
            {
                tracees.insert(thread.tid, tracee);
            }
            if !tracees.contains_key(&thread.tid) {
                return;
            }
        }
        thread.state.ptrace.exec = Some(old);
    }

    /// `PTRACE_EVENT_EXEC` with the thread's ID before the `execve` as its
    /// tracer's PID namespace numbers it, if its tracer asked for it; a
    /// thread traced without `PTRACE_SEIZE` gets `SIGTRAP` from itself
    /// otherwise.
    fn ptrace_exec_event(&mut self, thread: &mut Thread, old: u32) {
        let Some((_, options, seized)) = self.processes.traces.settings(thread.tid) else {
            return;
        };
        if options & (1 << PTRACE_EVENT_EXEC) != 0 {
            let message = self
                .processes
                .traces
                .tracer_of(thread.tid)
                .and_then(|tracer| self.processes.view(tracer))
                .map_or(0, |view| u64::from(view.space.number(old)));
            self.ptrace_event(thread, PTRACE_EVENT_EXEC, message);
        } else if !seized {
            signals::queue(&mut thread.state, signals::PendingSignal::user(SIGTRAP, 0));
        }
    }

    /// The thread exits with `status`: as a tracer, it lets go of its
    /// tracees (`exit_ptrace`), killing those that asked for it
    /// (`PTRACE_O_EXITKILL`); as a traced thread other than its process's
    /// leader, its tracer learns of the exit and waits for it, as for a
    /// child. A leader's exit is its process's ([`crate::Processes::finish`]).
    pub(crate) fn ptrace_exit(&mut self, thread: &Thread, status: ExitStatus) {
        if !self.processes.traces.any() {
            return;
        }
        // `do_exit` reports `PTRACE_EVENT_EXIT` with its code first: not a
        // thread killed, or one the end of its process began elsewhere. A
        // fatal signal's code has 0x80 when it dumps a core, which Linux has
        // written by then (`coredump_finish`).
        if self.group.traced() && self.traced(thread.tid) {
            let code = match status {
                ExitStatus::Exited(code) => ((code & 0xff) << 8) as u64,
                ExitStatus::Signaled(signal) if self.group.dumping_core() => signal as u64 | 0x80,
                ExitStatus::Signaled(signal) => signal as u64,
                _ => 0,
            };
            let mut exiting = thread.clone();
            self.ptrace_event(&mut exiting, PTRACE_EVENT_EXIT, code);
        }
        let tracees: Vec<(u32, u32, bool)> = self
            .processes
            .traces
            .lock()
            .iter()
            .filter(|(_, t)| t.tracer == thread.tid)
            .map(|(&tid, t)| (tid, t.pid, t.options & PTRACE_O_EXITKILL != 0))
            .collect();
        for (tid, pid, kill) in tracees {
            if kill {
                self.processes.kill_traced(pid, None);
            }
            self.processes.untrace(tid, None);
        }
        if thread.tid != self.process.pid {
            self.processes.traced_thread_exit(thread.tid, status);
        }
    }

    /// Whether the thread may set `options`: `PTRACE_O_SUSPEND_SECCOMP`
    /// needs `CAP_SYS_ADMIN` and a tracer under no seccomp mode nor itself
    /// a tracee whose seccomp is suspended (`EPERM`), as Linux's
    /// `check_ptrace_options` asks of a kernel with checkpoint and restore.
    fn may_suspend_seccomp(&self, thread: &Thread, options: u32) -> Result<(), Errno> {
        if options & PTRACE_O_SUSPEND_SECCOMP == 0 {
            return Ok(());
        }
        const CAP_SYS_ADMIN: u64 = 1 << 21;
        let suspended = self.seccomp_suspended(thread.tid);
        if !thread.state.credentials.capable(CAP_SYS_ADMIN)
            || thread.state.seccomp.mode != 0
            || suspended
        {
            return Err(Errno::EPERM);
        }
        Ok(())
    }

    /// Whether task `tid` is traced with `PTRACE_O_SUSPEND_SECCOMP`, which
    /// its filters and strict mode then let every call through
    /// (`PT_SUSPEND_SECCOMP`).
    pub(crate) fn seccomp_suspended(&self, tid: u32) -> bool {
        self.group.traced()
            && self
                .processes
                .traces
                .settings(tid)
                .is_some_and(|(_, options, _)| options & PTRACE_O_SUSPEND_SECCOMP != 0)
    }

    /// `ptrace(request, pid, addr, data)`.
    pub(crate) fn ptrace(
        &mut self,
        thread: &mut Thread,
        mem: &AddressSpace,
        a: [u64; 6],
    ) -> Result<u64, Errno> {
        let request = a[0] as i64;
        let (addr, data) = (a[2], a[3]);
        if request == PTRACE_TRACEME {
            return self.ptrace_traceme(thread);
        }
        let esrch = Errno(3);
        let number = u32::try_from(a[1] as i32)
            .ok()
            .filter(|&n| n > 0)
            .ok_or(esrch)?;
        let tid = self.pid_space(thread.tid).task(number).ok_or(esrch)?;
        if request == PTRACE_ATTACH || request == PTRACE_SEIZE {
            return self.ptrace_attach(thread, tid, request == PTRACE_SEIZE, addr, data);
        }
        let ignore_state = matches!(request, PTRACE_KILL | PTRACE_INTERRUPT);
        let pid = self.ptrace_check_attach(thread, tid, ignore_state)?;
        let traces = &self.processes.traces;
        let memory = || {
            self.processes
                .view(pid)
                .and_then(|view| view.group.public(tid))
                .and_then(|public| public.memory)
                .ok_or(Errno::EIO)
        };
        let put =
            |at: u64, bytes: &[u8]| mem.write(GuestAddr(at), bytes).map_err(|_| Errno::EFAULT);
        let get =
            |at: u64, bytes: &mut [u8]| mem.read(GuestAddr(at), bytes).map_err(|_| Errno::EFAULT);
        match request {
            PTRACE_PEEKTEXT | PTRACE_PEEKDATA => {
                let mut word = [0u8; 8];
                if memory()?.read_forced(addr, &mut word) != Some(8) {
                    return Err(Errno::EIO);
                }
                put(data, &word)?;
                Ok(0)
            }
            PTRACE_POKETEXT | PTRACE_POKEDATA => {
                if memory()?.write_forced(addr, &data.to_le_bytes()) != Some(8) {
                    return Err(Errno::EIO);
                }
                Ok(0)
            }
            PTRACE_PEEKUSR => {
                if addr & 7 != 0 || addr >= USER_SIZE {
                    return Err(Errno::EIO);
                }
                let value = traces.stopped(tid, |stop| {
                    Ok(if addr < REGS_SIZE {
                        regs(stop)[(addr / 8) as usize]
                    } else if (DEBUGREG..DEBUGREG + 64).contains(&addr) {
                        stop.debug.get((addr - DEBUGREG) / 8)
                    } else {
                        0
                    })
                })?;
                put(data, &value.to_le_bytes())?;
                Ok(0)
            }
            PTRACE_POKEUSR => {
                if addr & 7 != 0 || addr >= USER_SIZE {
                    return Err(Errno::EIO);
                }
                traces.stopped(tid, |stop| {
                    if addr < REGS_SIZE {
                        putreg(stop, addr / 8, data)?;
                        Ok(0)
                    } else if (DEBUGREG..DEBUGREG + 64).contains(&addr) {
                        stop.debug.set((addr - DEBUGREG) / 8, data)?;
                        Ok(0)
                    } else {
                        Err(Errno::EIO)
                    }
                })
            }
            PTRACE_GETREGS => {
                let bytes = traces.stopped(tid, |stop| Ok(general_bytes(stop)))?;
                put(data, &bytes)?;
                Ok(0)
            }
            PTRACE_SETREGS => {
                let mut bytes = [0u8; REGS_SIZE as usize];
                get(data, &mut bytes)?;
                traces.stopped(tid, |stop| set_general(stop, &bytes))
            }
            PTRACE_GETFPREGS => {
                let area = traces.stopped(tid, |stop| Ok(fp_area(stop)))?;
                put(data, &area)?;
                Ok(0)
            }
            PTRACE_SETFPREGS => {
                let mut bytes = [0u8; FPREGS_SIZE];
                get(data, &mut bytes)?;
                traces.stopped(tid, |stop| set_fp(stop, &bytes))
            }
            PTRACE_GETREGSET | PTRACE_SETREGSET => {
                let mut iov = [0u8; 16];
                get(data, &mut iov)?;
                let base = u64::from_le_bytes(iov[..8].try_into().map_err(|_| Errno::EFAULT)?);
                let length = u64::from_le_bytes(iov[8..].try_into().map_err(|_| Errno::EFAULT)?);
                let whole = match addr {
                    NT_PRSTATUS => REGS_SIZE,
                    NT_PRFPREG => FPREGS_SIZE as u64,
                    NT_X86_XSTATE => 0,
                    _ => return Err(Errno::EINVAL),
                };
                if length % 8 != 0 {
                    return Err(Errno::EINVAL);
                }
                let length = length.min(whole);
                // No XSAVE on this CPU: Linux's `xstateregs_get` and
                // `xstateregs_set` refuse.
                if addr == NT_X86_XSTATE {
                    return Err(Errno::ENODEV);
                }
                let size = length as usize;
                if request == PTRACE_GETREGSET {
                    let bytes = traces.stopped(tid, |stop| {
                        Ok(if addr == NT_PRSTATUS {
                            general_bytes(stop).to_vec()
                        } else {
                            fp_area(stop).to_vec()
                        })
                    })?;
                    put(base, &bytes[..size])?;
                } else {
                    let mut bytes = vec![0u8; size];
                    get(base, &mut bytes)?;
                    traces.stopped(tid, |stop| {
                        if addr == NT_PRSTATUS {
                            set_general(stop, &bytes)
                        } else if size != FPREGS_SIZE {
                            Err(Errno::EINVAL)
                        } else {
                            set_fp(stop, &bytes)
                        }
                    })?;
                }
                put(data + 8, &length.to_le_bytes())?;
                Ok(0)
            }
            PTRACE_SETOPTIONS => {
                let options = check_options(data)?;
                self.may_suspend_seccomp(thread, options)?;
                if let Some(tracee) = traces.lock().get_mut(&tid) {
                    tracee.options = options;
                }
                Ok(0)
            }
            PTRACE_GETEVENTMSG => {
                let message = traces.stopped(tid, |stop| Ok(stop.message))?;
                put(data, &message.to_le_bytes())?;
                Ok(0)
            }
            PTRACE_GETSIGINFO => {
                let kernel = traces.stopped(tid, |stop| stop.siginfo.ok_or(Errno::EINVAL))?;
                let mut info = [0u8; 128];
                info[..48].copy_from_slice(&kernel);
                put(data, &info)?;
                Ok(0)
            }
            PTRACE_SETSIGINFO => {
                let mut info = [0u8; 48];
                get(data, &mut info)?;
                let signo = i32::from_le_bytes([info[0], info[1], info[2], info[3]]);
                let code = i32::from_le_bytes([info[8], info[9], info[10], info[11]]);
                if !crate::processes::known_layout(signo, code) {
                    let mut rest = [0u8; 80];
                    get(data.wrapping_add(48), &mut rest)?;
                    if rest.iter().any(|&b| b != 0) {
                        return Err(Errno(7));
                    }
                }
                traces.stopped(tid, |stop| {
                    if stop.siginfo.is_none() {
                        return Err(Errno::EINVAL);
                    }
                    stop.siginfo = Some(info);
                    Ok(0)
                })
            }
            PTRACE_CONT
            | PTRACE_SYSCALL
            | PTRACE_SYSEMU
            | PTRACE_SINGLESTEP
            | PTRACE_SYSEMU_SINGLESTEP => {
                let signal = valid_signal(data)?;
                let mode = match request {
                    PTRACE_SYSCALL => Mode::Syscall,
                    PTRACE_SYSEMU => Mode::Sysemu,
                    PTRACE_SINGLESTEP => Mode::Step,
                    PTRACE_SYSEMU_SINGLESTEP => Mode::SysemuStep,
                    _ => Mode::Cont,
                };
                {
                    let mut tracees = traces.lock();
                    let tracee = tracees.get_mut(&tid).ok_or(esrch)?;
                    let stop = tracee.stop.as_mut().ok_or(esrch)?;
                    stop.resumed = Some(signal);
                    tracee.mode = mode;
                    // `user_enable_single_step` sets the trap flag unless the
                    // thread has it; `user_disable_single_step` takes back
                    // only one it set.
                    if matches!(mode, Mode::Step | Mode::SysemuStep) {
                        if stop.cpu.rflags & flag::TF == 0 {
                            stop.cpu.rflags |= flag::TF;
                            stop.forced_tf = true;
                        }
                    } else if std::mem::take(&mut stop.forced_tf) {
                        stop.cpu.rflags &= !flag::TF;
                    }
                }
                self.processes.changed().notify();
                Ok(0)
            }
            PTRACE_LISTEN => {
                let seized = traces.lock().get(&tid).is_some_and(|t| t.seized);
                traces.stopped(tid, |stop| {
                    let event = stop.siginfo.map(|info| {
                        i32::from_le_bytes([info[8], info[9], info[10], info[11]]) >> 8
                    });
                    if !seized || event != Some(PTRACE_EVENT_STOP) {
                        return Err(Errno::EIO);
                    }
                    stop.listening = true;
                    Ok(0)
                })?;
                self.processes.changed().notify();
                Ok(0)
            }
            PTRACE_PEEKSIGINFO => {
                let mut args = [0u8; 16];
                get(addr, &mut args)?;
                let offset = u64::from_le_bytes(args[..8].try_into().unwrap_or_default());
                let flags = u32::from_le_bytes(args[8..12].try_into().unwrap_or_default());
                let count = i32::from_le_bytes(args[12..].try_into().unwrap_or_default());
                if flags & !PTRACE_PEEKSIGINFO_SHARED != 0 || count < 0 {
                    return Err(Errno::EINVAL);
                }
                let list = traces.stopped(tid, |stop| {
                    Ok(if flags & PTRACE_PEEKSIGINFO_SHARED != 0 {
                        stop.shared.clone()
                    } else {
                        stop.queued.clone()
                    })
                })?;
                let mut copied = 0u64;
                for (slot, info) in list
                    .iter()
                    .skip(usize::try_from(offset).unwrap_or(usize::MAX))
                    .take(count as usize)
                    .enumerate()
                {
                    if put(data.wrapping_add(slot as u64 * 128), info).is_err() {
                        return if copied > 0 {
                            Ok(copied)
                        } else {
                            Err(Errno::EFAULT)
                        };
                    }
                    copied += 1;
                }
                Ok(copied)
            }
            PTRACE_GETSIGMASK => {
                if addr != 8 {
                    return Err(Errno::EINVAL);
                }
                let mask = traces.stopped(tid, |stop| Ok(stop.mask))?;
                put(data, &mask.to_le_bytes())?;
                Ok(0)
            }
            PTRACE_SETSIGMASK => {
                if addr != 8 {
                    return Err(Errno::EINVAL);
                }
                let mut mask = [0u8; 8];
                get(data, &mut mask)?;
                // Never SIGKILL or SIGSTOP.
                let mask = u64::from_le_bytes(mask) & !(1 << (SIGKILL - 1) | 1 << (SIGSTOP - 1));
                traces.stopped(tid, |stop| {
                    stop.mask = mask;
                    stop.new_mask = Some(mask);
                    Ok(0)
                })
            }
            PTRACE_GET_RSEQ_CONFIGURATION => {
                let rseq = traces.stopped(tid, |stop| Ok(stop.rseq))?;
                let mut conf = [0u8; 24];
                if let Some(rseq) = rseq {
                    conf[..8].copy_from_slice(&rseq.address.to_le_bytes());
                    conf[8..12].copy_from_slice(&rseq.length.to_le_bytes());
                    conf[12..16].copy_from_slice(&rseq.signature.to_le_bytes());
                }
                let length = usize::try_from(addr).unwrap_or(usize::MAX).min(conf.len());
                if length != 0 {
                    put(data, &conf[..length])?;
                }
                Ok(conf.len() as u64)
            }
            PTRACE_ARCH_PRCTL => match data {
                ARCH_SET_FS | ARCH_SET_GS => {
                    if addr >= TASK_SIZE_MAX {
                        return Err(Errno::EPERM);
                    }
                    traces.stopped(tid, |stop| {
                        if data == ARCH_SET_FS {
                            stop.cpu.fs_base = addr;
                        } else {
                            stop.cpu.gs_base = addr;
                        }
                        Ok(0)
                    })
                }
                ARCH_GET_FS | ARCH_GET_GS => {
                    let base = traces.stopped(tid, |stop| {
                        Ok(if data == ARCH_GET_FS {
                            stop.cpu.fs_base
                        } else {
                            stop.cpu.gs_base
                        })
                    })?;
                    put(addr, &base.to_le_bytes())?;
                    Ok(0)
                }
                _ => Err(Errno::EINVAL),
            },
            PTRACE_GET_SYSCALL_INFO => {
                let (info, size) = traces.stopped(tid, |stop| Ok(syscall_info(stop)))?;
                let length = size.min(usize::try_from(addr).unwrap_or(usize::MAX));
                if length != 0 {
                    put(data, &info[..length])?;
                }
                Ok(size as u64)
            }
            PTRACE_SET_SYSCALL_INFO => {
                if addr < SYSCALL_INFO_SIZE as u64 {
                    return Err(Errno::EINVAL);
                }
                let mut info = [0u8; SYSCALL_INFO_SIZE];
                get(data, &mut info)?;
                traces.stopped(tid, |stop| set_syscall_info(stop, &info))
            }
            PTRACE_KILL => {
                self.processes
                    .kill_traced(pid, Some((self.process.pid, thread.state.credentials.uid)));
                Ok(0)
            }
            PTRACE_DETACH => {
                let signal = valid_signal(data)?;
                // `ptrace_detach`'s `user_disable_single_step`.
                let _ = traces.stopped(tid, |stop| {
                    if std::mem::take(&mut stop.forced_tf) {
                        stop.cpu.rflags &= !flag::TF;
                    }
                    Ok(())
                });
                self.processes.untrace(tid, Some(signal));
                Ok(0)
            }
            PTRACE_INTERRUPT => {
                let seized = traces.lock().get(&tid).is_some_and(|t| t.seized);
                if !seized {
                    return Err(Errno::EIO);
                }
                if let Some(tracee) = traces.lock().get_mut(&tid)
                    && tracee.stop.as_ref().is_none_or(|stop| stop.listening)
                {
                    tracee.trap_stop = true;
                }
                if let Some(view) = self.processes.view(pid) {
                    view.group.interrupt_thread(tid);
                }
                Ok(0)
            }
            _ => Err(Errno::EIO),
        }
    }

    /// `PTRACE_TRACEME`, as Linux's `ptrace_traceme`: a traced thread gets
    /// `EPERM`; the thread that made this one becomes its tracer (another
    /// live thread of that process if it has gone), unless it may not, as
    /// the capability module's `cap_ptrace_traceme` and Landlock's
    /// `hook_ptrace_traceme` decide (`EPERM`). A parent that is exiting
    /// traces nothing, without an error.
    fn ptrace_traceme(&mut self, thread: &Thread) -> Result<u64, Errno> {
        if self.processes.traces.tracer_of(thread.tid).is_some() {
            return Err(Errno::EPERM);
        }
        let parent = self.processes.parent_of(self.process.pid);
        let Some(view) = self.processes.view(parent).filter(|view| !view.zombie) else {
            return Ok(0);
        };
        if view.group.status().is_some() {
            return Ok(0);
        }
        let forked_by = thread.state.ptrace.forked_by;
        let threads = view.group.threads();
        let tracer = threads
            .iter()
            .map(|&(tid, _)| tid)
            .find(|&tid| tid == forked_by)
            .or_else(|| threads.first().map(|&(tid, _)| tid))
            .unwrap_or(parent);
        let tracing = view
            .group
            .public(tracer)
            .or_else(|| view.group.public(parent))
            .map(|public| public.credentials)
            .unwrap_or_default();
        let own = &thread.state.credentials;
        let allowed = (tracing.user == own.user && own.permitted & !tracing.permitted == 0
            || tracing.capable_in(crate::credentials::CAP_SYS_PTRACE, &own.user))
            && crate::landlock::may_trace(&tracing.landlock, &own.landlock);
        if !allowed {
            return Err(Errno::EPERM);
        }
        self.processes.trace(
            thread.tid,
            self.process.pid,
            &self.group,
            (tracer, parent),
            false,
            0,
        );
        Ok(0)
    }

    /// `PTRACE_ATTACH` and `PTRACE_SEIZE` of task `tid`, as Linux's
    /// `ptrace_attach`: a seize takes no address (`EIO`) and only known
    /// options (`EIO`, then [`check_options`]); a task of the caller's own
    /// process is refused (`EPERM`), and so is one the caller may not
    /// attach to (`__ptrace_may_access` with `PTRACE_MODE_ATTACH_REALCREDS`
    /// and Yama, `EPERM`), one that has exited, and one already traced
    /// (`EPERM`). An attach sends the task `SIGSTOP` from the kernel; a
    /// task already in a group stop is made to report it, and the attach
    /// waits until it has.
    fn ptrace_attach(
        &mut self,
        thread: &mut Thread,
        tid: u32,
        seize: bool,
        addr: u64,
        data: u64,
    ) -> Result<u64, Errno> {
        let options = if seize {
            if addr != 0 || data & !PTRACE_O_MASK != 0 {
                return Err(Errno::EIO);
            }
            let options = check_options(data)?;
            self.may_suspend_seccomp(thread, options)?;
            options
        } else {
            0
        };
        if self.group.has_member(tid) {
            return Err(Errno::EPERM);
        }
        let esrch = Errno(3);
        let pid = match self.processes.view(tid) {
            Some(_) => tid,
            None => self.processes.thread_leader(tid).ok_or(esrch)?,
        };
        let view = self.processes.view(pid).ok_or(esrch)?;
        let public = view.group.public(tid).ok_or(Errno::EPERM)?;
        if !self.may_attach(thread, pid, &view, &public) {
            return Err(Errno::EPERM);
        }
        if view.zombie || !view.group.has_member(tid) || view.group.status().is_some() {
            return Err(Errno::EPERM);
        }
        if !self.processes.trace(
            tid,
            pid,
            &view.group,
            (thread.tid, self.process.pid),
            seize,
            options,
        ) {
            return Err(Errno::EPERM);
        }
        if !seize {
            let _ = view.group.send_thread_signal(
                tid,
                signals::PendingSignal::thread(SIGSTOP, signals::SI_KERNEL),
            );
        }
        if view.group.is_stopped() {
            if let Some(tracee) = self.processes.traces.lock().get_mut(&tid) {
                tracee.trap_stop = true;
            }
            view.group.interrupt_thread(tid);
            // `wait_on_bit(JOBCTL_TRAPPING)`, killable: until it has
            // stopped for the tracer or gone, or a SIGKILL or the end of
            // its process waits for the caller; no other signal ends the
            // wait, which would leave the attach half done. Draining the
            // caller's signals each pass keeps the wait from returning at
            // once while one is pending.
            loop {
                let ticket = self.processes.changed().value();
                let trapping = self
                    .processes
                    .traces
                    .lock()
                    .get(&tid)
                    .is_some_and(|t| t.trap_stop && t.exited.is_none());
                if !trapping
                    || !view.group.has_member(tid)
                    || view.group.status().is_some()
                    || self.fatal_pending(thread)
                {
                    break;
                }
                let _ = self.wait_for_children(ticket);
            }
        }
        Ok(0)
    }

    /// Linux's `ptrace_check_attach`: the caller must be the tracer of task
    /// `tid`, which must be in a ptrace stop unless `ignore_state`
    /// (`ESRCH`). The tracee's process.
    fn ptrace_check_attach(
        &self,
        thread: &Thread,
        tid: u32,
        ignore_state: bool,
    ) -> Result<u32, Errno> {
        let tracees = self.processes.traces.lock();
        let tracee = tracees
            .get(&tid)
            .filter(|t| t.tracer == thread.tid && t.exited.is_none())
            .ok_or(Errno(3))?;
        if !ignore_state
            && tracee
                .stop
                .as_ref()
                .is_none_or(|stop| stop.resumed.is_some() || stop.listening)
        {
            return Err(Errno(3));
        }
        Ok(tracee.pid)
    }
}

/// Linux's `check_ptrace_options`: only the known options (`EINVAL`).
fn check_options(data: u64) -> Result<u32, Errno> {
    if data & !PTRACE_O_MASK != 0 {
        return Err(Errno::EINVAL);
    }
    Ok(data as u32)
}

/// Linux's `valid_signal` for the signal a resume or detach gives (`EIO`).
fn valid_signal(data: u64) -> Result<i32, Errno> {
    if data > 64 {
        return Err(Errno::EIO);
    }
    Ok(data as i32)
}

/// Linux's `ptrace_get_syscall_info_op`: the kind of stop a task is in,
/// from the `si_code` of its siginfo and its message. Syscall stops are
/// known only with `PTRACE_O_TRACESYSGOOD`.
fn syscall_info_op(stop: &Stop) -> u8 {
    let code = stop.siginfo.map_or(0, |info| {
        i32::from_le_bytes([info[8], info[9], info[10], info[11]])
    });
    if code == SIGTRAP | 0x80 {
        match stop.message {
            PTRACE_EVENTMSG_SYSCALL_ENTRY => SYSCALL_INFO_ENTRY,
            PTRACE_EVENTMSG_SYSCALL_EXIT => SYSCALL_INFO_EXIT,
            _ => SYSCALL_INFO_NONE,
        }
    } else if code == SIGTRAP | PTRACE_EVENT_SECCOMP << 8 {
        SYSCALL_INFO_SECCOMP
    } else {
        SYSCALL_INFO_NONE
    }
}

/// The six argument registers of a call, in order.
const ARGUMENTS: [usize; 6] = [reg::RDI, reg::RSI, reg::RDX, reg::R10, reg::R8, reg::R9];

/// `struct ptrace_syscall_info` of a stopped task and the size of what
/// describes its stop, as Linux's `ptrace_get_syscall_info` fills them:
/// the call and its arguments at an entry (and the seccomp filter's data
/// at a seccomp stop), the return value at an exit, an error being one of
/// the last 4095 values.
fn syscall_info(stop: &Stop) -> ([u8; SYSCALL_INFO_SIZE], usize) {
    let mut info = [0u8; SYSCALL_INFO_SIZE];
    let op = syscall_info_op(stop);
    info[0] = op;
    info[4..8].copy_from_slice(&AUDIT_ARCH_X86_64.to_le_bytes());
    info[8..16].copy_from_slice(&stop.cpu.rip.0.to_le_bytes());
    info[16..24].copy_from_slice(&stop.cpu.gpr[reg::RSP].to_le_bytes());
    let size = match op {
        SYSCALL_INFO_ENTRY | SYSCALL_INFO_SECCOMP => {
            info[24..32].copy_from_slice(&stop.orig_rax.to_le_bytes());
            for (slot, &r) in ARGUMENTS.iter().enumerate() {
                let at = 32 + slot * 8;
                info[at..at + 8].copy_from_slice(&stop.cpu.gpr[r].to_le_bytes());
            }
            if op == SYSCALL_INFO_SECCOMP {
                info[80..84].copy_from_slice(&(stop.message as u32).to_le_bytes());
                84
            } else {
                80
            }
        }
        SYSCALL_INFO_EXIT => {
            let value = stop.cpu.gpr[reg::RAX];
            info[24..32].copy_from_slice(&value.to_le_bytes());
            info[32] = u8::from(value >= (-4095i64) as u64);
            33
        }
        _ => 24,
    };
    (info, size)
}

/// Linux's `ptrace_set_syscall_info`: the stop must be the kind `info`
/// names, with no flags (`EINVAL`). At an entry or a seccomp stop, the call
/// becomes `info`'s, an `int` (`ERANGE`), with its arguments unless it is
/// -1; at an exit, `rax` becomes the return value, an error as an `int`.
fn set_syscall_info(stop: &mut Stop, info: &[u8; SYSCALL_INFO_SIZE]) -> Result<u64, Errno> {
    let word = |at: usize| u64::from_le_bytes(info[at..at + 8].try_into().unwrap_or_default());
    let (op, reserved, flags) = (info[0], info[1], u16::from_le_bytes([info[2], info[3]]));
    if flags != 0 || reserved != 0 || syscall_info_op(stop) != op {
        return Err(Errno::EINVAL);
    }
    match op {
        SYSCALL_INFO_ENTRY | SYSCALL_INFO_SECCOMP => {
            let number = word(24);
            if i64::from(number as i32) as u64 != number {
                return Err(Errno::ERANGE);
            }
            stop.orig_rax = number;
            if number as i32 != -1 {
                for (slot, &r) in ARGUMENTS.iter().enumerate() {
                    stop.cpu.gpr[r] = word(32 + slot * 8);
                }
            }
        }
        SYSCALL_INFO_EXIT => {
            let value = word(24);
            // `syscall_set_return_value`: an error is the `int` it is.
            stop.cpu.gpr[reg::RAX] = if info[32] != 0 {
                i64::from(value as i32) as u64
            } else {
                value
            };
        }
        _ => return Err(Errno::EINVAL),
    }
    Ok(0)
}

/// `user_regs_struct` of a stopped task, as `genregs_get` writes it.
fn general_bytes(stop: &Stop) -> [u8; REGS_SIZE as usize] {
    let mut bytes = [0u8; REGS_SIZE as usize];
    for (slot, value) in regs(stop).iter().enumerate() {
        bytes[slot * 8..slot * 8 + 8].copy_from_slice(&value.to_le_bytes());
    }
    bytes
}

/// `genregs_set`: the words of `bytes` from the first register on, each
/// through [`putreg`], which stops at the first one refused.
fn set_general(stop: &mut Stop, bytes: &[u8]) -> Result<u64, Errno> {
    for (index, word) in bytes.as_chunks::<8>().0.iter().enumerate() {
        putreg(stop, index as u64, u64::from_le_bytes(*word))?;
    }
    Ok(0)
}

/// The `fxsave` area `PTRACE_GETFPREGS` and `NT_PRFPREG` give, zero past
/// what `fxsave` writes, as Linux's `xfpregs_get` copies it.
fn fp_area(stop: &Stop) -> [u8; FPREGS_SIZE] {
    let mut area = [0u8; FPREGS_SIZE];
    area[..paludarium_cpu::FX_WRITTEN].copy_from_slice(&stop.cpu.fx_image());
    area
}

/// `xfpregs_set`: the whole area, whose MXCSR must have no reserved bit
/// (`EINVAL`).
fn set_fp(stop: &mut Stop, bytes: &[u8]) -> Result<u64, Errno> {
    let written: &[u8; paludarium_cpu::FX_WRITTEN] = bytes[..paludarium_cpu::FX_WRITTEN]
        .try_into()
        .map_err(|_| Errno::EINVAL)?;
    if !stop.cpu.restore_fx_image(written) {
        return Err(Errno::EINVAL);
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stopped() -> Stop {
        Stop {
            cpu: CpuState::default(),
            orig_rax: u64::MAX,
            siginfo: None,
            message: 0,
            code: SIGSTOP,
            resumed: None,
            mask: 0,
            new_mask: None,
            queued: Vec::new(),
            shared: Vec::new(),
            rseq: None,
            listening: false,
            group_stopped: false,
            forced_tf: false,
            selectors: SELECTORS,
            debug: Debug::default(),
        }
    }

    #[test]
    fn registers_take_what_linux_putreg_takes() {
        let mut stop = stopped();
        putreg(&mut stop, 3, 7).unwrap();
        assert_eq!(stop.cpu.gpr[reg::R12], 7);
        putreg(&mut stop, ORIG_RAX, 60).unwrap();
        assert_eq!(regs(&stop)[ORIG_RAX as usize], 60);
        // The selectors: null or of user privilege, cs and ss never null.
        assert_eq!(putreg(&mut stop, CS, 0), Err(Errno::EIO));
        assert_eq!(putreg(&mut stop, SS, 0), Err(Errno::EIO));
        assert_eq!(putreg(&mut stop, DS, 0x10), Err(Errno::EIO));
        assert_eq!(putreg(&mut stop, DS, 0), Ok(()));
        assert_eq!(putreg(&mut stop, FS, 0x63), Ok(()));
        assert_eq!(regs(&stop)[CS as usize], 0x33);
        // The bases stay below TASK_SIZE_MAX.
        assert_eq!(putreg(&mut stop, FS_BASE, TASK_SIZE_MAX), Err(Errno::EIO));
        putreg(&mut stop, GS_BASE, 0x1000).unwrap();
        assert_eq!(stop.cpu.gs_base, 0x1000);
        // IF cannot be cleared, nor VM set; CF and TF can change.
        let before = stop.cpu.rflags;
        putreg(&mut stop, EFLAGS, flag::CF | flag::TF | flag::VM).unwrap();
        assert_eq!(stop.cpu.rflags, before | flag::CF | flag::TF);
        assert_eq!(putreg(&mut stop, 27, 0), Err(Errno::EIO));
    }

    #[test]
    fn general_registers_are_set_in_order_up_to_a_refusal() {
        let mut stop = stopped();
        let mut bytes = general_bytes(&stop);
        bytes[..8].copy_from_slice(&5u64.to_le_bytes());
        bytes[CS as usize * 8..CS as usize * 8 + 8].copy_from_slice(&0u64.to_le_bytes());
        bytes[RSP as usize * 8..RSP as usize * 8 + 8].copy_from_slice(&9u64.to_le_bytes());
        assert_eq!(set_general(&mut stop, &bytes), Err(Errno::EIO));
        assert_eq!(stop.cpu.gpr[reg::R15], 5);
        // Past cs nothing changed.
        assert_eq!(stop.cpu.gpr[reg::RSP], 0);
    }

    #[test]
    fn the_floating_point_area_is_fxsave_with_zeros_after() {
        let mut stop = stopped();
        stop.cpu.xmm[0] = 0x1234;
        let area = fp_area(&stop);
        assert_eq!(&area[160..162], &[0x34, 0x12]);
        assert!(area[paludarium_cpu::FX_WRITTEN..].iter().all(|&b| b == 0));
        let mut bad = area;
        bad[24..28].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(set_fp(&mut stop, &bad), Err(Errno::EINVAL));
        let mut good = area;
        good[160] = 0x99;
        assert_eq!(set_fp(&mut stop, &good), Ok(0));
        assert_eq!(stop.cpu.xmm[0] & 0xff, 0x99);
    }

    #[test]
    fn restart_codes_are_linux_ones() {
        assert_eq!(restart_code(None, None), None);
        assert_eq!(restart_code(Some(0), None), Some(ERESTARTSYS));
        assert_eq!(restart_code(Some(34), None), Some(ERESTARTNOHAND));
        assert_eq!(restart_code(Some(219), None), Some(ERESTART_RESTARTBLOCK));
        assert_eq!(restart_code(Some(7), Some(true)), Some(ERESTARTNOINTR));
        assert_eq!(restart_code(Some(7), Some(false)), Some(ERESTARTSYS));
    }

    #[test]
    fn selectors_a_tracer_writes_are_kept_and_shown() {
        let mut stop = stopped();
        assert_eq!(putreg(&mut stop, DS, 0x2b), Ok(()));
        assert_eq!(putreg(&mut stop, ES, 0x1_0033), Ok(()));
        assert_eq!(putreg(&mut stop, FS, 0x28), Err(Errno::EIO));
        assert_eq!(putreg(&mut stop, SS, 0), Err(Errno::EIO));
        let shown = regs(&stop);
        assert_eq!((shown[DS as usize], shown[ES as usize]), (0x2b, 0x33));
        assert_eq!((shown[CS as usize], shown[SS as usize]), (0x33, 0x2b));
    }

    #[test]
    fn a_restart_code_the_tracer_writes_decides_the_restart() {
        let mut thread = Thread::new(1, CpuState::default());
        let mut stop = stopped();
        stop.orig_rax = 0;
        let mut restart = Restart {
            number: Some(0),
            seccomp: None,
            ..Restart::default()
        };
        // -ERESTARTSYS shown, -ERESTARTNOINTR left: it restarts whatever
        // the handler.
        stop.cpu.gpr[reg::RAX] = ERESTARTNOINTR;
        Kernel::take_registers(&mut thread, &stop, Some(ERESTARTSYS), &mut restart);
        assert_eq!(thread.cpu.gpr[reg::RAX], Errno(4).to_syscall_return());
        assert_eq!((restart.number, restart.seccomp), (Some(0), Some(true)));
        // -ERESTART_RESTARTBLOCK: restart_syscall, never after a handler.
        stop.cpu.gpr[reg::RAX] = ERESTART_RESTARTBLOCK;
        Kernel::take_registers(&mut thread, &stop, Some(ERESTARTSYS), &mut restart);
        assert_eq!((restart.number, restart.no_handler), (Some(219), true));
        // orig_rax below 0: no restart, and the code stays.
        stop.orig_rax = u64::MAX;
        stop.cpu.gpr[reg::RAX] = ERESTARTNOHAND;
        Kernel::take_registers(&mut thread, &stop, Some(ERESTARTSYS), &mut restart);
        assert_eq!(
            (restart.number, thread.cpu.gpr[reg::RAX]),
            (None, ERESTARTNOHAND)
        );
    }

    #[test]
    fn suspending_seccomp_needs_cap_sys_admin_and_a_tracer_free_of_it() {
        let kernel = Kernel::new(Arc::new(paludarium_host::testing::RecordingHost::new()));
        let mut thread = Thread::new(1, CpuState::default());
        let suspend = PTRACE_O_SUSPEND_SECCOMP;
        assert_eq!(
            kernel.may_suspend_seccomp(&thread, PTRACE_O_EXITKILL),
            Ok(())
        );
        assert_eq!(kernel.may_suspend_seccomp(&thread, suspend), Ok(()));
        // Without CAP_SYS_ADMIN.
        let mut unprivileged = Thread::new(1, CpuState::default());
        unprivileged.state.credentials.euid = 1000;
        unprivileged.state.credentials.effective = 0;
        assert_eq!(
            kernel.may_suspend_seccomp(&unprivileged, suspend),
            Err(Errno::EPERM)
        );
        // A tracer under a seccomp mode.
        thread.state.seccomp.mode = 2;
        assert_eq!(
            kernel.may_suspend_seccomp(&thread, suspend),
            Err(Errno::EPERM)
        );
        thread.state.seccomp.mode = 0;
        // A tracer whose own seccomp is suspended by its tracer.
        let group = kernel.group.clone();
        assert!(kernel.processes.trace(1, 1, &group, (9, 9), false, suspend));
        assert_eq!(
            kernel.may_suspend_seccomp(&thread, suspend),
            Err(Errno::EPERM)
        );
        assert!(kernel.seccomp_suspended(1));
    }

    #[test]
    fn debug_registers_take_what_linux_takes() {
        let mut debug = Debug::default();
        // An address alone makes a disabled 1-byte write breakpoint.
        assert_eq!(debug.set(0, 0x1000), Ok(()));
        assert_eq!((debug.get(0), debug.active()), (0x1000, None));
        assert_eq!(debug.set(1, TASK_SIZE_MAX), Err(Errno::EINVAL));
        assert_eq!(debug.set(4, 0), Err(Errno::EIO));
        // DR0 enabled as a 4-byte write: the address is aligned to it.
        assert_eq!(debug.set(7, 1 | 0b1101 << 16), Ok(()));
        assert_eq!(debug.get(7), 1 | 0b1101 << 16);
        let active = *debug.active().unwrap();
        assert_eq!(
            active.0[0],
            Some(Breakpoint {
                address: 0x1000,
                length: 4,
                on: BreakOn::Write
            })
        );
        assert_eq!(debug.set(0, 0x1002), Err(Errno::EINVAL));
        // An execute breakpoint is 1 byte; I/O breakpoints are refused, and
        // a refused DR7 leaves the old one.
        assert_eq!(debug.set(7, 1 | 0b0100 << 16), Err(Errno::EINVAL));
        assert_eq!(debug.set(7, 1 | 0b0010 << 16), Err(Errno::EINVAL));
        assert_eq!(debug.get(7), 1 | 0b1101 << 16);
        assert_eq!(debug.set(7, 1), Ok(()));
        assert_eq!(debug.active().unwrap().0[0].unwrap().on, BreakOn::Execute);
        // DR6 is kept with its reserved bits flipped, as virtual_dr6.
        assert_eq!(debug.get(6), DR6_RESERVED);
        assert_eq!(debug.set(6, DR6_RESERVED | DR_STEP), Ok(()));
        assert_eq!(debug.dr6, DR_STEP);
        assert_eq!(debug.set(7, 0), Ok(()));
        assert_eq!(debug.active(), None);
    }

    #[test]
    fn options_and_signals_are_checked() {
        assert_eq!(
            check_options(PTRACE_O_EXITKILL.into()),
            Ok(PTRACE_O_EXITKILL)
        );
        assert_eq!(check_options(1 << 30), Err(Errno::EINVAL));
        // Known: whether the caller may set it is asked apart.
        assert_eq!(
            check_options(PTRACE_O_SUSPEND_SECCOMP.into()),
            Ok(PTRACE_O_SUSPEND_SECCOMP)
        );
        assert_eq!(valid_signal(64), Ok(64));
        assert_eq!(valid_signal(65), Err(Errno::EIO));
    }

    /// A syscall stop of a tracee traced with `PTRACE_O_TRACESYSGOOD`.
    fn syscall_stop(message: u64) -> Stop {
        let mut stop = stopped();
        stop.siginfo = Some(notify_siginfo(SIGTRAP, SIGTRAP | 0x80, 1, 0));
        stop.message = message;
        stop.orig_rax = 39;
        stop.cpu.rip = GuestAddr(0x40_1000);
        stop.cpu.gpr[reg::RSP] = 0x7000;
        stop.cpu.gpr[reg::RDI] = 11;
        stop.cpu.gpr[reg::R9] = 66;
        stop
    }

    #[test]
    fn syscall_info_describes_the_stop() {
        let word =
            |info: &[u8], at: usize| u64::from_le_bytes(info[at..at + 8].try_into().unwrap());
        let (info, size) = syscall_info(&syscall_stop(PTRACE_EVENTMSG_SYSCALL_ENTRY));
        assert_eq!((info[0], size), (SYSCALL_INFO_ENTRY, 80));
        assert_eq!(
            u32::from_le_bytes(info[4..8].try_into().unwrap()),
            AUDIT_ARCH_X86_64
        );
        assert_eq!((word(&info, 8), word(&info, 16)), (0x40_1000, 0x7000));
        assert_eq!(
            (word(&info, 24), word(&info, 32), word(&info, 72)),
            (39, 11, 66)
        );
        let mut exit = syscall_stop(PTRACE_EVENTMSG_SYSCALL_EXIT);
        exit.cpu.gpr[reg::RAX] = (-9i64) as u64;
        let (info, size) = syscall_info(&exit);
        assert_eq!(
            (info[0], size, word(&info, 24), info[32]),
            (SYSCALL_INFO_EXIT, 33, (-9i64) as u64, 1)
        );
        exit.cpu.gpr[reg::RAX] = (-4096i64) as u64;
        assert_eq!(syscall_info(&exit).0[32], 0);
        // A plain SIGTRAP, without PTRACE_O_TRACESYSGOOD, is no syscall stop.
        let mut plain = syscall_stop(PTRACE_EVENTMSG_SYSCALL_ENTRY);
        plain.siginfo = Some(notify_siginfo(SIGTRAP, SIGTRAP, 1, 0));
        assert_eq!(syscall_info(&plain).1, 24);
        let mut seccomp = syscall_stop(0x1234);
        seccomp.siginfo = Some(notify_siginfo(
            SIGTRAP,
            SIGTRAP | PTRACE_EVENT_SECCOMP << 8,
            1,
            0,
        ));
        let (info, size) = syscall_info(&seccomp);
        assert_eq!((info[0], size, info[80]), (SYSCALL_INFO_SECCOMP, 84, 0x34));
    }

    #[test]
    fn syscall_info_changes_only_the_stop_it_describes() {
        let mut stop = syscall_stop(PTRACE_EVENTMSG_SYSCALL_ENTRY);
        let mut info = syscall_info(&stop).0;
        info[2] = 1;
        assert_eq!(set_syscall_info(&mut stop, &info), Err(Errno::EINVAL));
        info[2] = 0;
        info[0] = SYSCALL_INFO_EXIT;
        assert_eq!(set_syscall_info(&mut stop, &info), Err(Errno::EINVAL));
        info[0] = SYSCALL_INFO_ENTRY;
        info[24..32].copy_from_slice(&(1u64 << 40).to_le_bytes());
        assert_eq!(set_syscall_info(&mut stop, &info), Err(Errno::ERANGE));
        info[24..32].copy_from_slice(&102u64.to_le_bytes());
        info[32..40].copy_from_slice(&5u64.to_le_bytes());
        assert_eq!(set_syscall_info(&mut stop, &info), Ok(0));
        assert_eq!((stop.orig_rax, stop.cpu.gpr[reg::RDI]), (102, 5));
        // -1 skips the call and leaves the arguments, which share rax's
        // registers on other machines.
        info[24..32].copy_from_slice(&u64::MAX.to_le_bytes());
        info[32..40].copy_from_slice(&6u64.to_le_bytes());
        assert_eq!(set_syscall_info(&mut stop, &info), Ok(0));
        assert_eq!((stop.orig_rax, stop.cpu.gpr[reg::RDI]), (u64::MAX, 5));
        let mut exit = syscall_stop(PTRACE_EVENTMSG_SYSCALL_EXIT);
        let mut info = syscall_info(&exit).0;
        info[24..32].copy_from_slice(&(-1i64 << 33 | 1).to_le_bytes());
        info[32] = 1;
        assert_eq!(set_syscall_info(&mut exit, &info), Ok(0));
        assert_eq!(exit.cpu.gpr[reg::RAX], 1, "an error is an int");
        info[32] = 0;
        assert_eq!(set_syscall_info(&mut exit, &info), Ok(0));
        assert_eq!(exit.cpu.gpr[reg::RAX], (-1i64 << 33 | 1) as u64);
        let mut other = stopped();
        assert_eq!(
            set_syscall_info(&mut other, &[0; SYSCALL_INFO_SIZE]),
            Err(Errno::EINVAL)
        );
    }

    #[test]
    fn a_new_thread_starts_untraced_and_knows_its_maker() {
        let mut local = Local::default();
        local.enter(7, 57);
        local.group_stopped = true;
        local.in_syscall = true;
        local.hold = true;
        let copy = local.clone();
        assert_eq!(copy.forked_by, 7);
        assert_eq!(copy.orig_rax, 57);
        assert!(!copy.group_stopped && !copy.in_syscall && !copy.hold);
    }
}
