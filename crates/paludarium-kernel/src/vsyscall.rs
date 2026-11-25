//! The `vsyscall` page, as Linux has it by default on x86-64
//! (`CONFIG_LEGACY_VSYSCALL_XONLY`): a gate area at a fixed address above
//! user space, with no page behind it, which every program may run and none
//! may read. It is no mapping of the process: `maps`, `smaps` and a core
//! dump show it after the last one. Running one of its three entries is a
//! page fault that Linux's `emulate_vsyscall` takes as the call of the
//! entry and a `ret`; anything else there is SIGSEGV.
use crate::{Kernel, Next, Thread, seccomp, signals, syscalls};
use paludarium_cpu::reg;
use paludarium_mmu::{AddressSpace, Prot, Vma, vm};
use paludarium_types::{Errno, ExitReason, GuestAddr, signal};

/// Linux's `VSYSCALL_ADDR` and the gate area's end.
pub(crate) const START: u64 = 0xffff_ffff_ff60_0000;
pub(crate) const END: u64 = START + 0x1000;
/// Linux's `TASK_SIZE_MAX` with 4-level page tables, where `access_ok` stops.
pub(crate) const TASK_SIZE_MAX: u64 = (1 << 47) - 4096;
/// Linux's `ERESTARTSYS`, which a program sees only where no system call
/// restarts.
const ERESTARTSYS: Errno = Errno(512);

/// The gate area as `maps` and `smaps` show it (Linux's `gate_vma`).
pub(crate) fn vma() -> Vma {
    Vma {
        start: START,
        end: END,
        prot: Prot::EXEC,
        shared: false,
        offset: 0,
        file: None,
        identity: (0, 0),
        heap: false,
        anon_name: None,
        flags: vm::EXEC,
    }
}

/// Where the page is entered, if `reason` is a thread running an address of
/// it (`emulate_vsyscall`'s `address == regs->ip`).
pub(crate) fn entered(reason: &ExitReason) -> Option<u64> {
    match *reason {
        ExitReason::PageFault {
            rip,
            addr,
            write: false,
            fetch: true,
            ..
        } if addr == rip && (START..END).contains(&addr.0) => Some(addr.0),
        _ => None,
    }
}

/// The system call of the entry at `address` (`addr_to_vsyscall_nr`).
fn call(address: u64) -> Option<u64> {
    if address & !0xc00 != START {
        return None;
    }
    match (address & 0xc00) >> 10 {
        0 => Some(syscalls::nr::GETTIMEOFDAY),
        1 => Some(syscalls::nr::TIME),
        2 => Some(syscalls::nr::GETCPU),
        _ => None,
    }
}

impl Kernel {
    /// `thread` runs `address` of the page, as Linux's `emulate_vsyscall`:
    /// the entry's call goes through seccomp, whose filters see `address` as
    /// the instruction's, but makes no system call's stops; then the thread
    /// goes on at its caller, with `rax` the result. No entry, a stack that
    /// cannot be read, or a pointer the call finds bad is SIGSEGV.
    pub(crate) fn vsyscall(
        &mut self,
        thread: &mut Thread,
        mem: &AddressSpace,
        address: u64,
    ) -> Next {
        thread.cpu.rip = GuestAddr(address);
        let Some(number) = call(address) else {
            return self.vsyscall_fault(thread, mem, None);
        };
        let mut caller = [0; 8];
        if mem
            .read(GuestAddr(thread.cpu.gpr[reg::RSP]), &mut caller)
            .is_err()
        {
            return self.vsyscall_fault(thread, mem, None);
        }
        let caller = u64::from_le_bytes(caller);
        // `write_ok_or_segv`: the pointers of the call that lie past user
        // space (a null one does not).
        let (rdi, rsi) = (thread.cpu.gpr[reg::RDI], thread.cpu.gpr[reg::RSI]);
        let pointers = match number {
            syscalls::nr::GETTIMEOFDAY => [(rdi, 16), (rsi, 8)],
            syscalls::nr::TIME => [(rdi, 8), (0, 0)],
            _ => [(rdi, 4), (rsi, 4)],
        };
        if let Some(&(bad, _)) = pointers.iter().find(|&&(at, size)| {
            at.checked_add(size)
                .is_none_or(|end: u64| end > TASK_SIZE_MAX)
        }) {
            return self.vsyscall_fault(thread, mem, Some(bad));
        }
        thread.state.ptrace.orig_rax = number;
        thread.cpu.gpr[reg::RAX] = Errno::ENOSYS.to_syscall_return();
        let skipped = match self.vsyscall_seccomp(thread, mem, number, address) {
            Ok(skipped) => skipped,
            // "seccomp tried to change syscall nr or ip" (`force_exit_sig`).
            Err(()) => return self.terminate(thread, signal::SIGSYS),
        };
        thread.state.ptrace.orig_rax = u64::MAX;
        match skipped {
            Seccomp::Skip(verdict) => {
                Self::vsyscall_return(thread, caller);
                match verdict {
                    Some(verdict) => self.refuse(thread, mem, verdict),
                    None => self.vsyscall_done(thread, mem),
                }
            }
            Seccomp::Run => {
                let result = self.vsyscall_call(thread, mem, number);
                // "With a real vsyscall, page faults cause SIGSEGV."
                if result == Errno::EFAULT.to_syscall_return() {
                    return self.vsyscall_fault(thread, mem, None);
                }
                thread.cpu.gpr[reg::RAX] = result;
                Self::vsyscall_return(thread, caller);
                self.vsyscall_done(thread, mem)
            }
        }
    }

    /// `secure_computing` of the entry's call: whether it runs; `Err` if a
    /// tracer moved the thread, or made the call that would run another.
    fn vsyscall_seccomp(
        &mut self,
        thread: &mut Thread,
        mem: &AddressSpace,
        number: u64,
        address: u64,
    ) -> Result<Seccomp, ()> {
        self.group.take_seccomp(thread.tid, &mut thread.state);
        if thread.state.seccomp.mode == 0 || self.seccomp_suspended(thread.tid) {
            return Ok(Seccomp::Run);
        }
        let mut verdict = Self::vsyscall_verdict(thread, number);
        if let seccomp::Verdict::Trace(data) = verdict {
            let traced = self.ptrace_seccomp(thread, data);
            // Also when the call is skipped.
            if thread.cpu.rip.0 != address {
                return Err(());
            }
            match traced {
                None => return Ok(Seccomp::Skip(None)),
                // The filters see what the tracer left, then the number is
                // compared.
                Some(traced) => {
                    thread.cpu.gpr[reg::RAX] = Errno::ENOSYS.to_syscall_return();
                    verdict = match Self::vsyscall_verdict(thread, traced) {
                        seccomp::Verdict::Trace(_) => seccomp::Verdict::Allow,
                        verdict => verdict,
                    };
                    if traced != number && matches!(verdict, seccomp::Verdict::Allow) {
                        return Err(());
                    }
                }
            }
        }
        Ok(match verdict {
            seccomp::Verdict::Allow => Seccomp::Run,
            seccomp::Verdict::Notify(notify) => {
                match self.listener_reply(thread, mem, number, &notify) {
                    seccomp::Reply::Continue => Seccomp::Run,
                    seccomp::Reply::Return(value) => {
                        thread.cpu.gpr[reg::RAX] = value;
                        Seccomp::Skip(None)
                    }
                    // No system call to run again (`orig_ax` is -1).
                    seccomp::Reply::Interrupted { .. } => {
                        thread.cpu.gpr[reg::RAX] = ERESTARTSYS.to_syscall_return();
                        Seccomp::Skip(None)
                    }
                }
            }
            // `syscall_rollback`: `rax` is the number, as at a system call.
            verdict @ (seccomp::Verdict::Trap(_) | seccomp::Verdict::Kill { .. }) => {
                thread.cpu.gpr[reg::RAX] = number;
                Seccomp::Skip(Some(verdict))
            }
            verdict => Seccomp::Skip(Some(verdict)),
        })
    }

    /// What the thread's filters say of the call `number` with its registers.
    fn vsyscall_verdict(thread: &Thread, number: u64) -> seccomp::Verdict {
        let gpr = &thread.cpu.gpr;
        let args = [
            gpr[reg::RDI],
            gpr[reg::RSI],
            gpr[reg::RDX],
            gpr[reg::R10],
            gpr[reg::R8],
            gpr[reg::R9],
        ];
        seccomp::check(&thread.state.seccomp, number as u32, args, thread.cpu.rip.0)
    }

    /// The result of the entry's call, which takes no third argument.
    fn vsyscall_call(&mut self, thread: &mut Thread, mem: &AddressSpace, number: u64) -> u64 {
        let args = [
            thread.cpu.gpr[reg::RDI],
            thread.cpu.gpr[reg::RSI],
            0,
            0,
            0,
            0,
        ];
        let Some(handler) = self.table.get(number) else {
            return Errno::ENOSYS.to_syscall_return();
        };
        let mut ctx = syscalls::Context {
            number,
            tid: thread.tid,
            host: &*self.host,
            shared_host: &self.host,
            files: &mut self.files,
            process: &mut thread.state,
            cpu: &mut thread.cpu,
            mem,
            cancellation: &self.cancellation,
            inbox: &self.inbox,
            group: &self.group,
            processes: &self.processes,
        };
        let outcome = handler(&mut ctx, args);
        self.inbox.drain(&mut thread.state);
        match outcome {
            syscalls::Outcome::Return(value) => value,
            // None of the three calls does anything else.
            _ => Errno::ENOSYS.to_syscall_return(),
        }
    }

    /// The `ret` to the entry's `caller`.
    fn vsyscall_return(thread: &mut Thread, caller: u64) {
        thread.cpu.rip = GuestAddr(caller);
        thread.cpu.gpr[reg::RSP] = thread.cpu.gpr[reg::RSP].wrapping_add(8);
    }

    /// Back to the thread, with no system call to restart.
    fn vsyscall_done(&mut self, thread: &mut Thread, mem: &AddressSpace) -> Next {
        thread.state.restart = None;
        thread.state.syscall_rax = thread.cpu.gpr[reg::RAX];
        self.checkpoint(thread, mem)
    }

    /// SIGSEGV at the entry: from the kernel, or for a pointer `bad` past
    /// user space, as a write to it faults.
    fn vsyscall_fault(
        &mut self,
        thread: &mut Thread,
        mem: &AddressSpace,
        bad: Option<u64>,
    ) -> Next {
        // SEGV_MAPERR, with the error code of a user write.
        let (code, addr, trap, error) = match bad {
            Some(addr) => (1, addr, 14, 6),
            None => (signals::SI_KERNEL, 0, 0, 0),
        };
        signals::queue(
            &mut thread.state,
            signals::PendingSignal {
                target: signals::PendingTarget::Thread,
                addr,
                trap,
                error,
                synchronous: true,
                ..signals::PendingSignal::thread(signal::SIGSEGV, code)
            },
        );
        self.vsyscall_done(thread, mem)
    }
}

/// Whether seccomp lets an entry's call run, or what it says instead.
enum Seccomp {
    Run,
    /// It does not run: `rax` is set, or the verdict decides.
    Skip(Option<seccomp::Verdict>),
}
