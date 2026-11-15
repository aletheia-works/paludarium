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
use crate::{Kernel, Thread, signals};
use paludarium_cpu::{CpuState, flag, reg};
use paludarium_mmu::AddressSpace;
use paludarium_types::{Errno, ExitStatus, GuestAddr};
use std::collections::BTreeMap;
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
const PTRACE_SETOPTIONS: i64 = 0x4200;
const PTRACE_GETEVENTMSG: i64 = 0x4201;
const PTRACE_GETSIGINFO: i64 = 0x4202;
const PTRACE_SETSIGINFO: i64 = 0x4203;
const PTRACE_GETREGSET: i64 = 0x4204;
const PTRACE_SETREGSET: i64 = 0x4205;
const PTRACE_SEIZE: i64 = 0x4206;
const PTRACE_INTERRUPT: i64 = 0x4207;

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
/// which starts untraced.
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
}
impl Clone for Local {
    fn clone(&self) -> Self {
        Self {
            forked_by: self.tid,
            orig_rax: u64::MAX,
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
    /// to resume with.
    released: Mutex<BTreeMap<u32, i32>>,
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
        let Some(tracee) = self.traces.lock().remove(&tid) else {
            return;
        };
        if let Some(stop) = &tracee.stop {
            let code = if (1..=64).contains(&stop.code) {
                stop.code
            } else {
                0
            };
            self.traces
                .released
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .insert(tid, signal.unwrap_or(code));
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
    out[CS as usize] = 0x33;
    out[EFLAGS as usize] = cpu.rflags;
    out[RSP as usize] = cpu.gpr[reg::RSP];
    out[SS as usize] = 0x2b;
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
        EFLAGS => cpu.rflags = (cpu.rflags & !FLAG_MASK) | (value & FLAG_MASK),
        CS | SS | DS | ES | FS | GS => {
            let selector = value as u16;
            if selector != 0 && selector & 3 != 3 || matches!(index, CS | SS) && selector == 0 {
                return Err(Errno::EIO);
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
        let shown = restart_code(restart.number, restart.seccomp)
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
            tracee.stop = Some(Stop {
                cpu,
                orig_rax: thread.state.ptrace.orig_rax,
                siginfo,
                message,
                code,
                resumed: None,
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
                    }
                    // Let go of: it resumes with what it had.
                    None => {
                        let released = traces
                            .released
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner)
                            .remove(&thread.tid);
                        break released.map(|signal| (signal, None));
                    }
                }
            }
            if self.fatal_pending(thread) {
                if let Some(tracee) = traces.lock().get_mut(&thread.tid) {
                    tracee.stop = None;
                }
                break None;
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
        if let Some(shown) = shown {
            if thread.cpu.gpr[reg::RAX] == shown {
                thread.cpu.gpr[reg::RAX] = Errno(4).to_syscall_return();
            } else {
                restart.number = None;
                restart.seccomp = None;
            }
        }
        if stop.orig_rax != before {
            thread.state.ptrace.orig_rax = stop.orig_rax;
            if (stop.orig_rax as i64) < 0 {
                restart.number = None;
                restart.seccomp = None;
            } else if restart.number.is_some() {
                restart.number = Some(u64::from(stop.orig_rax as u32));
                thread.state.syscall_rax = stop.orig_rax;
            }
        }
    }

    /// Whether a fatal signal waits for the thread, which ends any ptrace
    /// stop: SIGKILL, or the end of its process.
    fn fatal_pending(&self, thread: &mut Thread) -> bool {
        self.group.drain_process(&mut thread.state);
        self.inbox.drain(&mut thread.state);
        self.group.status().is_some() || thread.state.pending.iter().any(|s| s.number == SIGKILL)
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
        if !self.traced(thread.tid) {
            thread.state.ptrace.group_stopped = false;
            return;
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
        let stopped = self.group.is_stopped();
        let stop_signal = if stopped { self.group.stop_signal() } else { 0 };
        if seized {
            let signal = if stopped { stop_signal } else { SIGTRAP };
            let code = signal | PTRACE_EVENT_STOP << 8;
            let info = notify_siginfo(
                signal,
                code,
                self.pid_space(thread.tid).number(thread.tid),
                thread.state.credentials.task_ids().uid,
            );
            self.ptrace_stop(thread, code, true, 0, Some(info), restart);
        } else {
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

    /// After an `execve`, a thread traced without `PTRACE_SEIZE` gets
    /// `SIGTRAP` from itself, as Linux's `ptrace_event` sends it for
    /// `PTRACE_EVENT_EXEC` when the tracer did not ask for the event.
    pub(crate) fn ptrace_exec(&mut self, thread: &mut Thread) {
        let legacy = self
            .processes
            .traces
            .lock()
            .get(&thread.tid)
            .is_some_and(|t| !t.seized);
        if legacy {
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
                        match (addr - DEBUGREG) / 8 {
                            6 => DR6_RESERVED,
                            _ => 0,
                        }
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
                    } else if (DEBUGREG..DEBUGREG + 64).contains(&addr)
                        && (addr - DEBUGREG) / 8 == 7
                        && data == 0
                    {
                        // Disabling every hardware breakpoint; there are none.
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
            PTRACE_CONT => {
                let signal = valid_signal(data)?;
                traces.stopped(tid, |stop| {
                    stop.resumed = Some(signal);
                    Ok(0)
                })?;
                self.processes.changed().notify();
                Ok(0)
            }
            PTRACE_KILL => {
                self.processes
                    .kill_traced(pid, Some((self.process.pid, thread.state.credentials.uid)));
                Ok(0)
            }
            PTRACE_DETACH => {
                let signal = valid_signal(data)?;
                self.processes.untrace(tid, Some(signal));
                Ok(0)
            }
            PTRACE_INTERRUPT => {
                let seized = traces.lock().get(&tid).is_some_and(|t| t.seized);
                if !seized {
                    return Err(Errno::EIO);
                }
                if let Some(tracee) = traces.lock().get_mut(&tid)
                    && tracee.stop.is_none()
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
            check_options(data)?
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
                .is_none_or(|stop| stop.resumed.is_some())
        {
            return Err(Errno(3));
        }
        Ok(tracee.pid)
    }
}

/// Linux's `check_ptrace_options`: only the known options (`EINVAL`).
/// `PTRACE_O_SUSPEND_SECCOMP` gives `EINVAL` too, as on a Linux built
/// without checkpoint and restore.
fn check_options(data: u64) -> Result<u32, Errno> {
    if data & !PTRACE_O_MASK != 0 || data & u64::from(PTRACE_O_SUSPEND_SECCOMP) != 0 {
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
    fn options_and_signals_are_checked() {
        assert_eq!(
            check_options(PTRACE_O_EXITKILL.into()),
            Ok(PTRACE_O_EXITKILL)
        );
        assert_eq!(check_options(1 << 30), Err(Errno::EINVAL));
        assert_eq!(
            check_options(PTRACE_O_SUSPEND_SECCOMP.into()),
            Err(Errno::EINVAL)
        );
        assert_eq!(valid_signal(64), Ok(64));
        assert_eq!(valid_signal(65), Err(Errno::EIO));
    }

    #[test]
    fn a_new_thread_starts_untraced_and_knows_its_maker() {
        let mut local = Local::default();
        local.enter(7, 60);
        local.group_stopped = true;
        let copy = local.clone();
        assert_eq!(copy.forked_by, 7);
        assert_eq!(copy.orig_rax, u64::MAX);
        assert!(!copy.group_stopped);
    }
}
