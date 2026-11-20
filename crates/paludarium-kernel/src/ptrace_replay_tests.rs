//! Cases of `tests/guests/processes/ptrace.c`, `ptrace-syscalls.c`,
//! `ptrace-requests.c` and `single-step.c`, replayed through the kernel's
//! system calls: the tracer on the test's thread, the tracee on a thread of
//! its own, as a guest's tasks run, each system call followed by the
//! checkpoint the runtime takes before guest code runs again. The expected
//! lines are what the guest prints for its mode on native Linux: for the
//! `ptrace.c` cases but `ptrace-thread`, `ptrace-attach-stopped` and
//! `ptrace-tracer-exit` as printed on Linux 7.0 (x86-64, Ubuntu 26.04
//! runner); for those three, the `ptrace-syscalls.c`, `ptrace-requests.c` and `single-step.c` cases as the
//! guest prints them under the emulator, which `diff_processes` finds equal
//! to Linux's. It still compares the whole guests with Linux on every CI
//! run. What only the CPU does (a signal handler's body, the check a tracee
//! makes after it resumes, the trap after each instruction a stepped
//! tracee runs) is done here in Rust from the state the kernel left, or its
//! line is left out. An exec runs a program that does nothing; the tracee
//! then ends as the one the guest execs does.

use super::*;

const READ: u64 = 0;
const WRITE: u64 = 1;
const OPEN: u64 = 2;
const CLOSE: u64 = 3;
const MMAP: u64 = 9;
const MPROTECT: u64 = 10;
const RT_SIGACTION: u64 = 13;
const RT_SIGPROCMASK: u64 = 14;
const RT_SIGRETURN: u64 = 15;
const PIPE: u64 = 22;
const PAUSE: u64 = 34;
const SCHED_YIELD: u64 = 24;
const GETPID: u64 = 39;
const CLONE: u64 = 56;
const FORK: u64 = 57;
const VFORK: u64 = 58;
const EXECVE: u64 = 59;
const EXIT: u64 = 60;
const WAIT4: u64 = 61;
const KILL: u64 = 62;
const PTRACE: u64 = 101;
const GETUID: u64 = 102;
const GETPPID: u64 = 110;
const ARCH_PRCTL: u64 = 158;
const GETTID: u64 = 186;
const TKILL: u64 = 200;
const FUTEX: u64 = 202;
const EXIT_GROUP: u64 = 231;
const TGKILL: u64 = 234;
const RT_SIGQUEUEINFO: u64 = 129;
const PRCTL: u64 = 157;
const SECCOMP: u64 = 317;
const RSEQ: u64 = 334;
const PRLIMIT64: u64 = 302;

const TRACEME: u64 = 0;
const PEEKDATA: u64 = 2;
const PEEKUSER: u64 = 3;
const POKEDATA: u64 = 5;
const POKEUSER: u64 = 6;
const CONT: u64 = 7;
const KILL_REQUEST: u64 = 8;
const GETREGS: u64 = 12;
const SETREGS: u64 = 13;
const GETFPREGS: u64 = 14;
const SETFPREGS: u64 = 15;
const ATTACH: u64 = 16;
const SINGLESTEP: u64 = 9;
const SYSCALL: u64 = 24;
const SYSEMU_SINGLESTEP: u64 = 32;
const SYSEMU: u64 = 31;
const DETACH: u64 = 17;
const SETOPTIONS: u64 = 0x4200;
const GETEVENTMSG: u64 = 0x4201;
const GETSIGINFO: u64 = 0x4202;
const SETSIGINFO: u64 = 0x4203;
const GETREGSET: u64 = 0x4204;
const SETREGSET: u64 = 0x4205;
const SEIZE: u64 = 0x4206;
const INTERRUPT: u64 = 0x4207;
const LISTEN: u64 = 0x4208;
const PEEKSIGINFO: u64 = 0x4209;
const GETSIGMASK: u64 = 0x420a;
const SETSIGMASK: u64 = 0x420b;
const GET_SYSCALL_INFO: u64 = 0x420e;
const GET_RSEQ_CONFIGURATION: u64 = 0x420f;
const ARCH_PRCTL_REQUEST: u64 = 30;
const SET_SYSCALL_INFO: u64 = 0x4212;
const O_TRACESYSGOOD: u64 = 1;
const O_TRACEFORK: u64 = 2;
const O_TRACEEXIT: u64 = 0x40;
const O_TRACESECCOMP: u64 = 0x80;
const O_EXITKILL: u64 = 1 << 20;
const NT_PRSTATUS: u64 = 1;
const NT_PRFPREG: u64 = 2;

const SIGQUIT: u64 = 3;
const SIGTRAP: i64 = 5;
const SIGUSR1: u64 = 10;
const SIGUSR2: u64 = 12;
const SIGTERM: u64 = 15;
const SIGCHLD: u64 = 17;
const SIGSTOP: u64 = 19;
const SIGCONT: u64 = 18;
const SIGKILL: u64 = 9;
/// musl's `SIGRTMIN`, above the three it keeps for itself.
const SIGRTMIN: u64 = 35;
const WNOHANG: u64 = 1;
const WUNTRACED: u64 = 2;
const WALL: u64 = 0x4000_0000;
const SA_SIGINFO: u64 = 4;
const SA_RESTORER: u64 = 0x0400_0000;
const SA_RESTART: u64 = 0x1000_0000;
/// The trap flag.
const TF: u64 = 0x100;

/// `struct user_regs_struct`'s fields, by their offsets.
const R14: u64 = 8;
const R13: u64 = 16;
const R12: u64 = 24;
const R10: u64 = 56;
const RAX: u64 = 80;
const RDI: u64 = 112;
const ORIG_RAX: u64 = 120;
const RIP: u64 = 128;
const CS: u64 = 136;
const EFLAGS: u64 = 144;
const RSP: u64 = 152;
const SS: u64 = 160;
const FS_BASE: u64 = 168;
const GS_BASE: u64 = 176;
const DS: u64 = 184;
const REGS: u64 = 216;
/// `struct user`'s `u_tsize` and `u_debugreg`, and glibc's size of it.
const TSIZE: u64 = 736;
const DEBUGREG: u64 = 848;
const USER: u64 = 912;

/// Where the tracer and the tracee keep what they pass by address: mapped
/// before the fork, so the tracee has its own copy.
const HEAP: u64 = 0x700000;
const HEAP_PAGES: u64 = 16;
/// The tracee's code: where its system calls return to, its signal
/// handler and the restorer the handler returns through.
const CODE: u64 = 0x40_1002;
const HANDLER: u64 = 0x40_2000;
const RESTORER: u64 = 0x40_3000;
/// The tracee's word that the tracer peeks and pokes.
const WORD: u64 = HEAP + 0x800;

/// How long a test waits for a task to reach a state before it fails, so
/// that a tracee that went wrong fails the test instead of hanging it.
const PATIENCE: std::time::Duration = std::time::Duration::from_secs(30);
/// How long a whole test may take. A wait that never ends, such as a
/// tracer's blocking `wait4` for a stop that never comes, ends the test
/// binary after it, so that the run fails instead of hanging.
const WATCHDOG: std::time::Duration = std::time::Duration::from_secs(120);

fn neg(r: u64) -> i64 {
    r as i64
}
fn read32(m: &AddressSpace, at: u64) -> u32 {
    let mut bytes = [0; 4];
    m.read(GuestAddr(at), &mut bytes).unwrap();
    u32::from_le_bytes(bytes)
}
fn write32(m: &AddressSpace, at: u64, value: u32) {
    m.write(GuestAddr(at), &value.to_le_bytes()).unwrap();
}

/// The tracer: the test's thread, and the lines it printed.
struct Tracer {
    k: Kernel,
    t: Thread,
    m: AddressSpace,
    lines: Vec<String>,
    /// Dropped with the tracer, which tells its watchdog the test ended.
    _watchdog: std::sync::mpsc::Sender<()>,
}

/// The calls a tracee has gone into that its tracer waits for it to sleep
/// in, which the tracee counts just before it makes each.
type Entered = std::sync::atomic::AtomicU64;

/// A tracee on a thread of its own, as the runtime runs a guest task.
struct Tracee {
    k: Box<Kernel>,
    t: Thread,
    m: Arc<AddressSpace>,
    /// The threads of the tasks it forked, joined as it ends.
    children: Vec<std::thread::JoinHandle<()>>,
    /// What the child of its next `fork` runs.
    forked: Option<Box<Body>>,
}

/// What a forked task runs, to the end it gives.
type Body = dyn FnOnce(&mut Tracee) -> ExitStatus + Send;

/// What the tracee's signal handler does with a signal and its siginfo:
/// return, or end the process with a code.
type Handler<'a> = dyn FnMut(&mut Tracee, u64, u64) -> Option<i32> + Send + 'a;

impl Tracee {
    /// A system call from `CODE`, then the checkpoints until guest code
    /// runs again: a restart goes back into the call, a handler runs and
    /// returns through `rt_sigreturn`. `Err` is the process's end.
    fn call(&mut self, n: u64, a: [u64; 6], handler: &mut Handler<'_>) -> Result<u64, ExitStatus> {
        self.t.cpu.gpr[reg::RAX] = n;
        for (register, value) in [reg::RDI, reg::RSI, reg::RDX, reg::R10, reg::R8, reg::R9]
            .into_iter()
            .zip(a)
        {
            self.t.cpu.gpr[register] = value;
        }
        self.t.cpu.rip = GuestAddr(CODE);
        loop {
            let rip = self.t.cpu.rip;
            if let Next::Exit(status) =
                self.k
                    .handle(&mut self.t, &self.m, ExitReason::Syscall { rip })
            {
                return Err(status);
            }
            // As the runtime after an `execve`: the new image from now on.
            if let Some(memory) = self.k.take_exec_memory() {
                self.m = memory;
                self.k.exec_finished();
            }
            self.spawn();
            self.settle()?;
            match self.t.cpu.rip.0 {
                HANDLER => {
                    let (signal, info) = (self.t.cpu.gpr[reg::RDI], self.t.cpu.gpr[reg::RSI]);
                    if let Some(code) = handler(self, signal, info) {
                        return Err(self.exit(code));
                    }
                    // `ret` to the restorer, which calls rt_sigreturn.
                    self.t.cpu.gpr[reg::RSP] += 8;
                    self.t.cpu.gpr[reg::RAX] = RT_SIGRETURN;
                    self.t.cpu.rip = GuestAddr(RESTORER + 2);
                }
                // A restarted call runs again from the registers it had.
                rip if rip == CODE - 2 => self.t.cpu.rip = GuestAddr(CODE),
                _ => return Ok(self.t.cpu.gpr[reg::RAX]),
            }
        }
    }
    /// The checkpoints until guest code runs again, as the runtime takes
    /// them, waiting while the task is stopped.
    fn settle(&mut self) -> Result<(), ExitStatus> {
        let deadline = std::time::Instant::now() + PATIENCE;
        loop {
            match self.k.checkpoint(&mut self.t, &self.m) {
                Next::Exit(status) => return Err(status),
                Next::Stopped => {
                    assert!(
                        std::time::Instant::now() < deadline,
                        "tracee stayed stopped"
                    );
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
                Next::Resume => return Ok(()),
            }
        }
    }
    /// As the runtime after a call that made a task: the task on a thread
    /// of its own, which runs `forked` once its first checkpoints let it,
    /// then the event its maker's tracer asked for.
    fn spawn(&mut self) {
        let Some((mut k, t)) = self.k.take_child() else {
            return;
        };
        // A thread runs on its maker's memory.
        let m = k.take_spawn_memory().unwrap_or_else(|| self.m.clone());
        let body = self.forked.take().expect("a task no case runs");
        self.children.push(std::thread::spawn(move || {
            let mut child = Tracee {
                k,
                t,
                m,
                children: Vec::new(),
                forked: None,
            };
            // As a tracee of the tracer's: a failure ends the process, then
            // fails the test from join.
            let run =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| match child.settle() {
                    Ok(()) => body(&mut child),
                    Err(status) => status,
                }));
            match run {
                Ok(status) => child.end(status),
                Err(panic) => {
                    child.end(ExitStatus::Signaled(9));
                    std::panic::resume_unwind(panic);
                }
            }
        }));
        let kill = std::sync::atomic::AtomicBool::new(false);
        self.k.child_started(&mut self.t, true, &kill).unwrap();
    }
    /// `fork`, its child running `body`: the child's PID.
    fn fork(&mut self, body: impl FnOnce(&mut Tracee) -> ExitStatus + Send + 'static) -> u64 {
        self.forked = Some(Box::new(body));
        self.sys(FORK, [0; 6]).unwrap()
    }
    /// A thread, as musl's `pthread_create` makes it, running `body`; the
    /// word at `ctid` holds its TID until it ends: its TID.
    fn thread(
        &mut self,
        ctid: u64,
        body: impl FnOnce(&mut Tracee) -> ExitStatus + Send + 'static,
    ) -> u64 {
        // CLONE_VM | FS | FILES | SIGHAND | THREAD | PARENT_SETTID |
        // CHILD_CLEARTID.
        let flags = 0x10f00 | 0x10_0000 | 0x20_0000;
        self.forked = Some(Box::new(body));
        self.sys(CLONE, [flags, 0, ctid, ctid, 0, 0]).unwrap()
    }
    /// musl's `pthread_join`: a futex wait until the word at `ctid` clears.
    fn join(&mut self, ctid: u64) {
        loop {
            let tid = read32(&self.m, ctid);
            if tid == 0 {
                return;
            }
            self.sys(FUTEX, [ctid, 0, u64::from(tid), 0, 0, 0]).ok();
        }
    }
    /// A call with no handler to run.
    fn sys(&mut self, n: u64, a: [u64; 6]) -> Result<u64, ExitStatus> {
        self.call(n, a, &mut |_, _, _| None)
    }
    /// `exit_group(code)`, and the end the kernel gives it.
    fn exit(&mut self, code: i32) -> ExitStatus {
        match self.sys(EXIT_GROUP, [code as u64, 0, 0, 0, 0, 0]) {
            Err(status) => status,
            Ok(r) => panic!("exit_group returned {r}"),
        }
    }
    /// musl's `raise`: every signal blocked around a `tkill` to its own
    /// thread (whose TID musl keeps), so that it arrives as the mask comes
    /// back, at the end of `rt_sigprocmask`.
    fn raise(&mut self, signal: u64, handler: &mut Handler<'_>) -> Result<u64, ExitStatus> {
        let (all, old) = (HEAP + 0x900, HEAP + 0x908);
        self.m.write_u64(GuestAddr(all), u64::MAX).unwrap();
        self.call(RT_SIGPROCMASK, [0, all, old, 8, 0, 0], handler)?;
        let tid = u64::from(self.t.tid);
        self.call(TKILL, [tid, signal, 0, 0, 0, 0], handler)?;
        self.call(RT_SIGPROCMASK, [2, old, 0, 8, 0, 0], handler)
    }
    /// `vfork`, its child running `body`: the child's PID, once the child
    /// has exited.
    fn vfork(&mut self, body: impl FnOnce(&mut Tracee) -> ExitStatus + Send + 'static) -> u64 {
        self.forked = Some(Box::new(body));
        self.sys(VFORK, [0; 6]).unwrap()
    }
    /// `execve("/child")`, from which the tracee goes on as the program
    /// it runs: `Err` is the process's end.
    fn exec(&mut self) -> Result<u64, ExitStatus> {
        let path = HEAP + 0xb00;
        self.m.write(GuestAddr(path), b"/child\0").unwrap();
        self.sys(EXECVE, [path, 0, 0, 0, 0, 0])
    }
    /// `sigaction(signal)` with the handler at `HANDLER`.
    fn catch(&mut self, signal: u64, flags: u64) {
        let action = HEAP + 0xa00;
        for (at, value) in [HANDLER, flags | SA_RESTORER, RESTORER, 0]
            .into_iter()
            .enumerate()
        {
            self.m
                .write_u64(GuestAddr(action + at as u64 * 8), value)
                .unwrap();
        }
        assert_eq!(self.sys(RT_SIGACTION, [signal, action, 0, 8, 0, 0]), Ok(0));
    }
    /// Ends the task as the runtime does once the kernel has said so.
    fn end(mut self, status: ExitStatus) {
        self.k.finish_thread(&self.t, &self.m);
        self.k.complete_process(status);
        for child in std::mem::take(&mut self.children) {
            child.join().unwrap();
        }
    }
}

impl Tracer {
    fn new() -> Self {
        let (k, t, m) = setup();
        // The program a tracee execs, which ends as `exec-child` does.
        let mut fs = paludarium_vfs::MemFs::new();
        fs.add_file(paludarium_vfs::GuestFile::new(
            "/child",
            paludarium_loader::testing::tiny_exec(&[0x90], b""),
        ))
        .unwrap();
        let k = k.with_file_system(Arc::new(fs));
        m.map_shared(
            Some(GuestAddr(HEAP)),
            HEAP_PAGES * PAGE_SIZE,
            Prot::READ_WRITE,
            MappingKind::Anonymous,
        )
        .unwrap();
        m.write_u64(GuestAddr(WORD), 0x1122_3344_5566_7788).unwrap();
        let (watchdog, ended) = std::sync::mpsc::channel::<()>();
        let test = std::thread::current().name().unwrap_or("?").to_owned();
        std::thread::spawn(move || {
            if let Err(std::sync::mpsc::RecvTimeoutError::Timeout) = ended.recv_timeout(WATCHDOG) {
                eprintln!("{test} did not end in {WATCHDOG:?}");
                std::process::abort();
            }
        });
        Self {
            k,
            t,
            m,
            lines: Vec::new(),
            _watchdog: watchdog,
        }
    }
    fn call(&mut self, n: u64, a: [u64; 6]) -> u64 {
        syscall(&mut self.k, &mut self.t, &self.m, n, a)
    }
    /// The raw call, as the guest's `pt` makes it.
    fn pt(&mut self, request: u64, pid: u64, addr: u64, data: u64) -> i64 {
        neg(self.call(PTRACE, [request, pid, addr, data, 0, 0]))
    }
    /// A child on a thread of its own running `body`, whose end the
    /// kernel is told as the runtime tells it.
    fn fork(
        &mut self,
        body: impl FnOnce(&mut Tracee) -> ExitStatus + Send + 'static,
    ) -> (u64, std::thread::JoinHandle<()>) {
        let (k, t, m) = fork(&mut self.k, &mut self.t, &self.m);
        let pid = u64::from(t.tid);
        let thread = std::thread::spawn(move || {
            let mut tracee = Tracee {
                k,
                t,
                m,
                children: Vec::new(),
                forked: None,
            };
            // A tracee that fails ends its process, so that the tracer's
            // wait returns and the test reports the failure from join.
            let run = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| body(&mut tracee)));
            match run {
                Ok(status) => tracee.end(status),
                Err(panic) => {
                    tracee.end(ExitStatus::Signaled(9));
                    std::panic::resume_unwind(panic);
                }
            }
        });
        (pid, thread)
    }
    fn say(&mut self, name: &str, value: impl std::fmt::Display) {
        self.lines.push(format!("{name}={value}"));
    }
    /// `waitpid`, retried on EINTR: the status, 0 for none, or `-errno`.
    fn wait(&mut self, pid: u64, flags: u64) -> i64 {
        let status = HEAP + 0x100;
        loop {
            let r = neg(self.call(WAIT4, [pid, status, flags, 0, 0, 0]));
            if r == -4 {
                continue;
            }
            return match r {
                r if r == pid as i64 => i64::from(read32(&self.m, status)),
                0 => 0,
                r => r,
            };
        }
    }
    /// A stop, as the case prints it: the signal, and the event above it.
    fn stop(&mut self, name: &str, status: i64) {
        let stopped = status & 0xff == 0x7f;
        self.say(&format!("{name}-stopped"), i64::from(stopped));
        self.say(
            &format!("{name}-signal"),
            if stopped { (status >> 8) & 0xff } else { -1 },
        );
        self.say(&format!("{name}-event"), status >> 16);
    }
    /// PTRACE_GETSIGINFO's error, signal, code and sender.
    fn siginfo(&mut self, pid: u64) -> (i64, i32, i32, u32) {
        let info = HEAP + 0x200;
        self.m.write(GuestAddr(info), &[0; 128]).unwrap();
        let error = self.pt(GETSIGINFO, pid, 0, info);
        let int = |at| read32(&self.m, info + at);
        (error, int(0) as i32, int(8) as i32, int(16))
    }
    fn regs(&mut self, pid: u64) -> (i64, u64) {
        let at = HEAP + 0x300;
        (self.pt(GETREGS, pid, 0, at), at)
    }
    fn reg(&self, regs: u64, field: u64) -> u64 {
        self.m.read_u64(GuestAddr(regs + field)).unwrap()
    }
    /// `TracerPid` and the state letter of `/proc/<pid>/status`.
    fn status_of(&mut self, pid: u64) -> (i64, u8) {
        let path = HEAP + 0x400;
        self.m
            .write(GuestAddr(path), format!("/proc/{pid}/status\0").as_bytes())
            .unwrap();
        let fd = self.call(OPEN, [path, 0, 0, 0, 0, 0]);
        let buf = HEAP + 0x1000;
        let n = self.call(READ, [fd, buf, 4096, 0, 0, 0]);
        self.call(CLOSE, [fd, 0, 0, 0, 0, 0]);
        let mut text = vec![0; n as usize];
        self.m.read(GuestAddr(buf), &mut text).unwrap();
        let text = String::from_utf8(text).unwrap();
        let field = |name: &str| {
            text.lines()
                .find_map(|line| line.strip_prefix(name))
                .unwrap()
                .trim()
                .to_owned()
        };
        (
            field("TracerPid:").parse().unwrap(),
            field("State:").as_bytes()[0],
        )
    }
    /// A pipe: its read and write ends.
    fn pipe(&mut self) -> (u64, u64) {
        let fds = HEAP + 0x780;
        assert_eq!(self.call(PIPE, [fds, 0, 0, 0, 0, 0]), 0);
        (
            u64::from(read32(&self.m, fds)),
            u64::from(read32(&self.m, fds + 4)),
        )
    }
    /// The guest's wait for its child's byte on the ready pipe, and then for
    /// it to sleep in the call after, which `entered` counts.
    fn ready(&mut self, pid: u64, fd: u64, entered: &Entered) {
        assert_eq!(self.call(READ, [fd, HEAP + 0x790, 1, 0, 0, 0]), 1);
        self.sleeping_in(pid, entered, 1);
    }
    /// Waits until `pid` sleeps in the `nth` call `entered` counts. In
    /// /proc a task sleeps in every call it is in, also one that does not
    /// block, such as the write of the ready byte, an rt_sigreturn or a
    /// call restarted after a handler; a signal sent there would stop it
    /// before the call the test means.
    fn sleeping_in(&mut self, pid: u64, entered: &Entered, nth: u64) {
        let deadline = std::time::Instant::now() + PATIENCE;
        while entered.load(std::sync::atomic::Ordering::SeqCst) < nth {
            assert!(
                std::time::Instant::now() < deadline,
                "{pid} made no call {nth}"
            );
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        self.until_sleeping(pid);
    }
    /// Waits until `pid` sleeps, as the guest does before it attaches.
    fn until_sleeping(&mut self, pid: u64) {
        let deadline = std::time::Instant::now() + PATIENCE;
        while self.status_of(pid).1 != b'S' {
            assert!(std::time::Instant::now() < deadline, "{pid} did not sleep");
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }
    /// A stop as `ptrace-requests.c` prints it.
    fn show(&mut self, name: &str, status: i64) {
        let stopped = status & 0xff == 0x7f;
        let signal = if stopped { (status >> 8) & 0xff } else { -1 };
        self.lines.push(format!(
            "{name}: stopped={} signal={signal} event={}",
            i64::from(stopped),
            status >> 16
        ));
    }
    /// The exit code of an exited status, or -1.
    fn code(status: i64) -> i64 {
        if status & 0x7f == 0 {
            (status >> 8) & 0xff
        } else {
            -1
        }
    }
    fn check(&self, native: &str) {
        let native: Vec<_> = native.trim().lines().collect();
        let lines: Vec<_> = self.lines.iter().map(String::as_str).collect();
        assert_eq!(lines, native);
    }
}

/// `ptrace-traceme`: the stop for a signal the child sends itself, its
/// siginfo, a peek and a poke, the registers, a cancelled signal, and the
/// SIGTRAP its exec sends it. The program it execs ends with the code
/// `exec-child` gives.
#[test]
fn traceme() {
    let mut g = Tracer::new();
    // The child waits on `go` before it execs, so that it still runs, not
    // stopped at the exec, when the tracer peeks it after PTRACE_CONT.
    let (go_read, go_write) = g.pipe();
    let (lines, tx) = std::sync::mpsc::channel();
    let (child, thread) = g.fork(move |c| {
        assert_eq!(c.sys(PTRACE, [TRACEME, 0, 0, 0, 0, 0]), Ok(0));
        let again = c.sys(PTRACE, [TRACEME, 0, 0, 0, 0, 0]).unwrap();
        lines
            .send(format!("child-traceme-again={}", neg(again)))
            .unwrap();
        c.catch(SIGUSR1, 0);
        let mut handled = false;
        c.raise(SIGUSR1, &mut |_, _, _| {
            handled = true;
            None
        })
        .unwrap();
        // The tracer cancelled the signal and changed the word.
        assert!(!handled);
        assert_eq!(
            c.m.read_u64(GuestAddr(WORD)).unwrap(),
            0x0102_0304_0506_0708
        );
        assert_eq!(c.sys(READ, [go_read, HEAP + 0x990, 1, 0, 0, 0]), Ok(1));
        assert_eq!(c.exec(), Ok(0));
        c.exit(7)
    });
    let status = g.wait(child, 0);
    g.lines.push(tx.recv().unwrap());
    g.stop("raise", status);
    let (tracer, state) = g.status_of(child);
    g.say("tracer-pid", i64::from(tracer == 1));
    g.say("state-tracing", i64::from(state == b't'));
    let own = g.status_of(1).0;
    g.say("own-tracer-pid", own);
    let (error, signo, code, pid) = g.siginfo(child);
    g.say("siginfo", error);
    g.say("si-signo", signo);
    g.say("si-code", code);
    g.say("si-pid", i64::from(u64::from(pid) == child));
    let word = HEAP + 0x180;
    let peek = g.pt(PEEKDATA, child, WORD, word);
    g.say("peek", peek);
    let peeked = g.m.read_u64(GuestAddr(word)).unwrap() == 0x1122_3344_5566_7788;
    g.say("peeked", i64::from(peeked));
    let poke = g.pt(POKEDATA, child, WORD, 0x0102_0304_0506_0708);
    g.say("poke", poke);
    let unmapped = g.pt(PEEKDATA, child, 8, word);
    g.say("peek-unmapped", unmapped);
    let unmapped = g.pt(POKEDATA, child, 8, 0);
    g.say("poke-unmapped", unmapped);
    let (error, regs) = g.regs(child);
    g.say("getregs", error);
    for (name, field) in [("orig-rax", ORIG_RAX), ("rax", RAX), ("cs", CS), ("ss", SS)] {
        let value = g.reg(regs, field) as i64;
        g.say(name, value);
    }
    let flags = g.reg(regs, EFLAGS);
    g.say("if", (flags >> 9) & 1);
    let bad = g.pt(CONT, child, 0, 65);
    g.say("bad-signal", bad);
    let bad = g.pt(0x4299, child, 0, 0);
    g.say("bad-request", bad);
    let cont = g.pt(CONT, child, 0, 0);
    g.say("cont", cont);
    let running = g.pt(PEEKDATA, child, WORD, word);
    g.say("running-peek", running);
    g.call(WRITE, [go_write, HEAP + 0x790, 1, 0, 0, 0]);
    let status = g.wait(child, 0);
    g.stop("exec", status);
    let (_, _, code, pid) = g.siginfo(child);
    g.say("exec-si-code", code);
    g.say("exec-si-pid", i64::from(u64::from(pid) == child));
    let cont = g.pt(CONT, child, 0, 0);
    g.say("cont-exec", cont);
    thread.join().unwrap();
    let status = g.wait(child, 0);
    g.say("exited", i64::from(status & 0x7f == 0));
    g.say("exit-code", (status >> 8) & 0xff);
    let gone = g.pt(CONT, child, 0, 0);
    g.say("no-tracee", gone);
    g.check(
        "child-traceme-again=-1
raise-stopped=1
raise-signal=10
raise-event=0
tracer-pid=1
state-tracing=1
own-tracer-pid=0
siginfo=0
si-signo=10
si-code=-6
si-pid=1
peek=0
peeked=1
poke=0
peek-unmapped=-5
poke-unmapped=-5
getregs=0
orig-rax=14
rax=0
cs=51
ss=43
if=1
bad-signal=-5
bad-request=-5
cont=0
running-peek=-3
exec-stopped=1
exec-signal=5
exec-event=0
exec-si-code=0
exec-si-pid=1
cont-exec=0
exited=1
exit-code=7
no-tracee=-3",
    );
}

/// `ptrace-attach`: the stop for the attach's SIGSTOP of a child in pause,
/// with the restart code in rax; a signal the tracer gives; a detach.
#[test]
fn attach() {
    let mut g = Tracer::new();
    let (ready, told) = g.pipe();
    let paused = Arc::new(Entered::new(0));
    let pausing = Arc::clone(&paused);
    let (child, thread) = g.fork(move |c| {
        c.catch(SIGUSR1, 0);
        c.sys(WRITE, [told, HEAP + 0x790, 1, 0, 0, 0]).unwrap();
        pausing.store(1, std::sync::atomic::Ordering::SeqCst);
        loop {
            if let Err(status) = c.call(PAUSE, [0; 6], &mut |_, _, _| None) {
                return status;
            }
        }
    });
    g.ready(child, ready, &paused);
    let r = g.pt(CONT, child, 0, 0);
    g.say("untraced", r);
    let r = g.pt(ATTACH, 1, 0, 0);
    g.say("self", r);
    let r = g.pt(ATTACH, child, 0, 0);
    g.say("attach", r);
    let r = g.pt(ATTACH, child, 0, 0);
    g.say("again", r);
    let status = g.wait(child, WALL);
    g.stop("attach", status);
    let (_, signo, code, _) = g.siginfo(child);
    g.say("si-signo", signo);
    g.say("si-code", code);
    let (_, regs) = g.regs(child);
    let orig = g.reg(regs, ORIG_RAX) as i64;
    g.say("orig-rax", orig);
    let rax = g.reg(regs, RAX) as i64;
    g.say("rax", rax);
    let reported = g.wait(child, WNOHANG | WALL);
    g.say("reported", reported);
    let r = g.pt(CONT, child, 0, SIGUSR1);
    g.say("cont-usr1", r);
    g.call(KILL, [child, SIGUSR2, 0, 0, 0, 0]);
    let status = g.wait(child, 0);
    g.stop("usr2", status);
    let running = g.regs(child).0 == 0;
    g.say("running", i64::from(running));
    let r = g.pt(DETACH, child, 0, 99);
    g.say("detach-bad", r);
    let r = g.pt(DETACH, child, 0, 0);
    g.say("detach", r);
    let r = g.pt(CONT, child, 0, 0);
    g.say("detached", r);
    g.call(KILL, [child, SIGTERM, 0, 0, 0, 0]);
    let status = g.wait(child, 0);
    thread.join().unwrap();
    g.say(
        "signaled",
        i64::from(status & 0x7f != 0 && status & 0x7f != 0x7f),
    );
    g.say("term", status & 0x7f);
    g.check(
        "untraced=-3
self=-1
attach=0
again=-1
attach-stopped=1
attach-signal=19
attach-event=0
si-signo=19
si-code=128
orig-rax=34
rax=-514
reported=0
cont-usr1=0
usr2-stopped=1
usr2-signal=12
usr2-event=0
running=1
detach-bad=-5
detach=0
detached=-3
signaled=1
term=15",
    );
}

/// `ptrace-seize`: no stop until PTRACE_INTERRUPT, a SIGSTOP's delivery
/// stop and then its group stop as PTRACE_EVENT_STOP, and PTRACE_KILL.
#[test]
fn seize() {
    let mut g = Tracer::new();
    let (child, thread) = g.fork(|c| {
        loop {
            if let Err(status) = c.sys(PAUSE, [0; 6]) {
                return status;
            }
        }
    });
    let r = g.pt(SEIZE, child, 1, 0);
    g.say("seize-addr", r);
    let r = g.pt(SEIZE, child, 0, 1 << 30);
    g.say("seize-options", r);
    let r = g.pt(SEIZE, child, 0, O_EXITKILL);
    g.say("seize", r);
    let r = g.wait(child, WNOHANG);
    g.say("no-stop", r);
    let r = g.pt(GETREGS, child, 0, 0);
    g.say("not-stopped", r);
    let r = g.pt(INTERRUPT, child, 0, 0);
    g.say("interrupt", r);
    let status = g.wait(child, 0);
    g.stop("interrupt", status);
    let (_, signo, code, pid) = g.siginfo(child);
    g.say("si-signo", signo);
    g.say("si-code", code);
    g.say("si-pid", i64::from(u64::from(pid) == child));
    let r = g.pt(SETOPTIONS, child, 0, 1 << 30);
    g.say("bad-options", r);
    let r = g.pt(CONT, child, 0, 0);
    g.say("cont", r);
    g.call(KILL, [child, SIGSTOP, 0, 0, 0, 0]);
    let status = g.wait(child, 0);
    g.stop("sigstop", status);
    let r = g.pt(CONT, child, 0, SIGSTOP);
    g.say("cont-stop", r);
    let status = g.wait(child, 0);
    g.stop("group", status);
    let (_, signo, code, _) = g.siginfo(child);
    g.say("group-si-signo", signo);
    g.say("group-si-code", code);
    let state = g.status_of(child).1;
    g.say("group-state-tracing", i64::from(state == b't'));
    let r = g.pt(KILL_REQUEST, child, 0, 0);
    g.say("kill", r);
    let status = g.wait(child, 0);
    thread.join().unwrap();
    g.say(
        "signaled",
        i64::from(status & 0x7f != 0 && status & 0x7f != 0x7f),
    );
    g.say("killed-by", status & 0x7f);
    g.check(
        "seize-addr=-5
seize-options=-5
seize=0
no-stop=0
not-stopped=-3
interrupt=0
interrupt-stopped=1
interrupt-signal=5
interrupt-event=128
si-signo=5
si-code=32773
si-pid=1
bad-options=-22
cont=0
sigstop-stopped=1
sigstop-signal=19
sigstop-event=0
cont-stop=0
group-stopped=1
group-signal=19
group-event=128
group-si-signo=19
group-si-code=32787
group-state-tracing=1
kill=0
signaled=1
killed-by=9",
    );
}

/// `ptrace-signals`: the group stop of a child traced without SEIZE has no
/// siginfo; SETSIGINFO changes a stopped signal's, and a signal the tracer
/// gives in place of another is the tracer's. The handler's checks are
/// made here from the siginfo the kernel gave it.
#[test]
fn signals() {
    let mut g = Tracer::new();
    for round in 0..2 {
        let (child, thread) = g.fork(|c| {
            c.catch(SIGUSR1, SA_SIGINFO);
            c.catch(SIGUSR2, SA_SIGINFO);
            assert_eq!(c.sys(PTRACE, [TRACEME, 0, 0, 0, 0, 0]), Ok(0));
            let mut handler = |c: &mut Tracee, signal: u64, info: u64| {
                let int = |at| read32(&c.m, info + at) as i32;
                let (code, value, pid) = (int(8), int(24), int(16));
                Some(if signal == SIGUSR1 {
                    if code == -60 && value == 42 { 10 } else { 11 }
                } else {
                    let parent = c.sys(GETPPID, [0; 6]).unwrap() as i32;
                    if code == 0 && pid == parent { 20 } else { 21 }
                })
            };
            if let Err(status) = c.raise(SIGSTOP, &mut handler) {
                return status;
            }
            if let Err(status) = c.raise(SIGUSR1, &mut handler) {
                return status;
            }
            c.exit(30)
        });
        let name = |n: &str| format!("{}-{n}", if round == 1 { "b" } else { "a" });
        let status = g.wait(child, 0);
        g.stop(&name("sigstop"), status);
        g.pt(CONT, child, 0, SIGSTOP);
        let status = g.wait(child, 0);
        g.stop(&name("group"), status);
        let error = g.siginfo(child).0;
        g.say(&name("group-siginfo"), error);
        let empty = HEAP + 0x280;
        g.m.write(GuestAddr(empty), &[0; 128]).unwrap();
        let r = g.pt(SETSIGINFO, child, 0, empty);
        g.say("group-setsiginfo", r);
        g.pt(CONT, child, 0, 0);
        let status = g.wait(child, 0);
        g.stop(&name("usr1"), status);
        if round == 0 {
            let info = HEAP + 0x200;
            g.siginfo(child);
            write32(&g.m, info + 8, (-60i32) as u32);
            write32(&g.m, info + 24, 42);
            let r = g.pt(SETSIGINFO, child, 0, info);
            g.say("setsiginfo", r);
            g.pt(CONT, child, 0, SIGUSR1);
        } else {
            g.pt(CONT, child, 0, SIGUSR2);
        }
        let status = g.wait(child, 0);
        thread.join().unwrap();
        let code = if status & 0x7f == 0 {
            (status >> 8) & 0xff
        } else {
            -1
        };
        g.say(&name("exit"), code);
    }
    g.check(
        "a-sigstop-stopped=1
a-sigstop-signal=19
a-sigstop-event=0
a-group-stopped=1
a-group-signal=19
a-group-event=0
a-group-siginfo=-22
group-setsiginfo=-22
a-usr1-stopped=1
a-usr1-signal=10
a-usr1-event=0
setsiginfo=0
a-exit=10
b-sigstop-stopped=1
b-sigstop-signal=19
b-sigstop-event=0
b-group-stopped=1
b-group-signal=19
b-group-event=0
b-group-siginfo=-22
group-setsiginfo=-22
b-usr1-stopped=1
b-usr1-signal=10
b-usr1-event=0
b-exit=20",
    );
}

/// `ptrace-regs`: a tracee stopped at the end of its own tkill; what
/// GETREGS, PEEKUSER and the register sets show and change, which the
/// tracee then runs with. The checks it makes after the call are made here
/// from its registers.
#[test]
fn regs() {
    const PATTERN: u128 = 0x5555_aaaa_5555_aaaa_0123_4567_89ab_cdef;
    let mut g = Tracer::new();
    let (child, thread) = g.fork(|c| {
        assert_eq!(c.sys(PTRACE, [TRACEME, 0, 0, 0, 0, 0]), Ok(0));
        // musl's start sets the thread pointer.
        c.sys(ARCH_PRCTL, [0x1002, HEAP + 0xf00, 0, 0, 0, 0])
            .unwrap();
        let tid = c.sys(GETTID, [0; 6]).unwrap();
        c.t.cpu.gpr[reg::R12] = 0x1111;
        c.t.cpu.gpr[reg::R13] = 0x3333;
        c.t.cpu.xmm[0] = PATTERN;
        let ret = match c.sys(TKILL, [tid, SIGSTOP, 0, 0, 0, 0]) {
            Ok(ret) => ret,
            Err(status) => return status,
        };
        let cpu = &c.t.cpu;
        let code = i32::from(cpu.gpr[reg::R12] == 0x2222)
            | i32::from(cpu.gpr[reg::R13] == 0x4444) << 1
            | i32::from(cpu.xmm[0] as u64 == 0x0f0e_0d0c_0b0a_0908) << 2
            | i32::from(ret == 0) << 3;
        c.exit(code)
    });
    let status = g.wait(child, 0);
    g.stop("stop", status);
    let (error, regs) = g.regs(child);
    g.say("getregs", error);
    for (name, field) in [
        ("r12", R12),
        ("r13", R13),
        ("orig-rax", ORIG_RAX),
        ("rax", RAX),
        ("cs", CS),
        ("ss", SS),
        ("ds", DS),
    ] {
        let value = g.reg(regs, field) as i64;
        g.say(name, value);
    }
    let fs = g.reg(regs, FS_BASE) != 0;
    g.say("fs-base", i64::from(fs));
    let (r14, flags) = (g.reg(regs, R14), g.reg(regs, EFLAGS));
    let word = HEAP + 0x180;
    let peek = |g: &mut Tracer, at: u64| {
        let r = g.pt(PEEKUSER, child, at, word);
        (r, g.m.read_u64(GuestAddr(word)).unwrap() as i64)
    };
    let (r, value) = peek(&mut g, R12);
    g.say("peekuser", r);
    g.say("peeked-r12", value);
    let value = peek(&mut g, DEBUGREG + 6 * 8).1;
    g.say("dr6", value);
    let value = peek(&mut g, DEBUGREG + 7 * 8).1;
    g.say("dr7", value);
    g.m.write_u64(GuestAddr(word), u64::MAX).unwrap();
    let value = peek(&mut g, TSIZE).1;
    g.say("tsize", value);
    let r = peek(&mut g, 3).0;
    g.say("peek-unaligned", r);
    let r = peek(&mut g, USER).0;
    g.say("peek-past", r);
    for (name, at, value) in [
        ("poke-r12", R12, 0x2222),
        ("poke-cs-null", CS, 0),
        ("poke-ds-kernel", DS, 0x10),
        ("poke-fs-base", FS_BASE, 0xffff_8000_0000_0000),
        ("poke-tsize", TSIZE, 0),
        ("poke-dr7", DEBUGREG + 7 * 8, 0),
    ] {
        let r = g.pt(POKEUSER, child, at, value);
        g.say(name, r);
    }
    // IF cannot be cleared; the status flags can be set.
    g.pt(POKEUSER, child, EFLAGS, (flags & !0x200) | 1);
    let value = peek(&mut g, EFLAGS).1;
    g.say("eflags-if", (value >> 9) & 1);
    g.say("eflags-cf", value & 1);
    g.pt(POKEUSER, child, EFLAGS, flags);
    let (iov, set) = (HEAP + 0x500, HEAP + 0x600);
    let vector = |g: &mut Tracer, base: u64, len: u64| {
        g.m.write_u64(GuestAddr(iov), base).unwrap();
        g.m.write_u64(GuestAddr(iov + 8), len).unwrap();
    };
    let len = |g: &Tracer| g.m.read_u64(GuestAddr(iov + 8)).unwrap();
    vector(&mut g, set, REGS + 64);
    let r = g.pt(GETREGSET, child, NT_PRSTATUS, iov);
    g.say("getregset", r);
    let n = len(&g);
    g.say("getregset-len", n);
    let value = g.reg(set, R12);
    g.say("getregset-r12", value);
    g.m.write_u64(GuestAddr(set + R13), 0x4444).unwrap();
    let r = g.pt(SETREGSET, child, NT_PRSTATUS, iov);
    g.say("setregset", r);
    vector(&mut g, set, 7);
    let r = g.pt(GETREGSET, child, NT_PRSTATUS, iov);
    g.say("regset-odd", r);
    vector(&mut g, set, 8);
    let r = g.pt(GETREGSET, child, 0x999, iov);
    g.say("regset-unknown", r);
    vector(&mut g, set, 16);
    g.m.write(GuestAddr(set), &[0; REGS as usize]).unwrap();
    let r = g.pt(GETREGSET, child, NT_PRSTATUS, iov);
    g.say("regset-part", r);
    let n = len(&g);
    g.say("regset-part-len", n);
    let same = g.reg(set, R14) == r14;
    g.say("regset-part-r14", i64::from(same));
    let value = g.reg(set, R13);
    g.say("regset-part-r13", value);
    let fp = HEAP + 0x1800;
    let r = g.pt(GETFPREGS, child, 0, fp);
    g.say("getfpregs", r);
    let half = |g: &Tracer, at: u64| u64::from(read32(&g.m, fp + at));
    let cwd = half(&g, 0) & 0xffff;
    g.say("cwd", cwd);
    let mxcsr = half(&g, 24);
    g.say("mxcsr", mxcsr);
    let low = half(&g, 160) == 0x89ab_cdef && half(&g, 164) == 0x0123_4567;
    g.say("xmm0-low", i64::from(low));
    let high = half(&g, 168) == 0x5555_aaaa;
    g.say("xmm0-high", i64::from(high));
    write32(&g.m, fp + 160, 0x0b0a_0908);
    write32(&g.m, fp + 164, 0x0f0e_0d0c);
    let r = g.pt(SETFPREGS, child, 0, fp);
    g.say("setfpregs", r);
    write32(&g.m, fp + 24, u32::MAX);
    let r = g.pt(SETFPREGS, child, 0, fp);
    g.say("setfpregs-mxcsr", r);
    let fp2 = HEAP + 0x2000;
    vector(&mut g, fp2, 512);
    let r = g.pt(GETREGSET, child, NT_PRFPREG, iov);
    g.say("fpregset", r);
    let n = len(&g);
    g.say("fpregset-len", n);
    let set_xmm = read32(&g.m, fp2 + 160) == 0x0b0a_0908;
    g.say("fpregset-xmm0", i64::from(set_xmm));
    vector(&mut g, fp2, 64);
    let r = g.pt(SETREGSET, child, NT_PRFPREG, iov);
    g.say("fpregset-set-part", r);
    g.pt(CONT, child, 0, 0);
    let status = g.wait(child, 0);
    thread.join().unwrap();
    let code = if status & 0x7f == 0 {
        (status >> 8) & 0xff
    } else {
        -1
    };
    g.say("exit", code);
    g.check(
        "stop-stopped=1
stop-signal=19
stop-event=0
getregs=0
r12=4369
r13=13107
orig-rax=200
rax=0
cs=51
ss=43
ds=0
fs-base=1
peekuser=0
peeked-r12=4369
dr6=4294905840
dr7=0
tsize=0
peek-unaligned=-5
peek-past=0
poke-r12=0
poke-cs-null=-5
poke-ds-kernel=-5
poke-fs-base=-5
poke-tsize=-5
poke-dr7=0
eflags-if=1
eflags-cf=1
getregset=0
getregset-len=216
getregset-r12=8738
setregset=0
regset-odd=-22
regset-unknown=-22
regset-part=0
regset-part-len=16
regset-part-r14=1
regset-part-r13=0
getfpregs=0
cwd=895
mxcsr=8064
xmm0-low=1
xmm0-high=1
setfpregs=0
setfpregs-mxcsr=-22
fpregset=0
fpregset-len=512
fpregset-xmm0=1
fpregset-set-part=-22
exit=15",
    );
}

/// `ptrace-memory`: a tracer writes a read-only private page, reads a
/// PROT_NONE one, and is refused a shared read-only one.
#[test]
fn memory() {
    let mut g = Tracer::new();
    let mut page = |shared: bool, fill: u8| {
        let flags = if shared { 0x21 } else { 0x22 };
        let at = g.call(MMAP, [0, PAGE_SIZE, 3, flags, u64::MAX, 0]);
        g.m.write(GuestAddr(at), &[fill; PAGE_SIZE as usize])
            .unwrap();
        at
    };
    let (ro, none, shared) = (page(false, 1), page(false, 2), page(true, 3));
    for (at, prot) in [(ro, 1), (none, 0), (shared, 1)] {
        assert_eq!(g.call(MPROTECT, [at, PAGE_SIZE, prot, 0, 0, 0]), 0);
    }
    let (child, thread) = g.fork(move |c| {
        assert_eq!(c.sys(PTRACE, [TRACEME, 0, 0, 0, 0, 0]), Ok(0));
        if let Err(status) = c.raise(SIGSTOP, &mut |_, _, _| None) {
            return status;
        }
        let mut byte = [0];
        c.m.read(GuestAddr(ro + 8), &mut byte).unwrap();
        c.exit(i32::from(byte[0] != 9))
    });
    let status = g.wait(child, 0);
    g.stop("stop", status);
    let word = HEAP + 0x180;
    let look = |g: &mut Tracer, name: &str, at: u64| {
        let r = g.pt(PEEKDATA, child, at, word);
        g.say(&format!("peek-{name}"), r);
        g.m.read_u64(GuestAddr(word)).unwrap() & 0xff
    };
    let value = look(&mut g, "ro", ro);
    g.say("peeked-ro", value);
    let r = g.pt(POKEDATA, child, ro + 8, 9);
    g.say("poke-ro", r);
    let value = look(&mut g, "none", none);
    g.say("peeked-none", value);
    let r = g.pt(POKEDATA, child, none, 4);
    g.say("poke-none", r);
    look(&mut g, "shared", shared);
    let r = g.pt(POKEDATA, child, shared, 5);
    g.say("poke-shared", r);
    let mut byte = [0];
    g.m.read(GuestAddr(ro + 8), &mut byte).unwrap();
    g.say("parent-ro", byte[0]);
    g.pt(CONT, child, 0, 0);
    let status = g.wait(child, 0);
    thread.join().unwrap();
    let code = if status & 0x7f == 0 {
        (status >> 8) & 0xff
    } else {
        -1
    };
    g.say("exit", code);
    g.check(
        "stop-stopped=1
stop-signal=19
stop-event=0
peek-ro=0
peeked-ro=1
poke-ro=0
peek-none=0
peeked-none=2
poke-none=0
peek-shared=0
poke-shared=-5
parent-ro=1
exit=0",
    );
}

/// `struct ptrace_syscall_info`'s size, as Linux 6.16 and later have it.
const INFO: u64 = 88;

/// What `ptrace-strace`'s tracer keeps: the tasks it names, and whether it
/// has seen a syscall-entry stop yet.
struct Strace {
    named: [u64; 4],
    first_entry: bool,
}

impl Strace {
    const NAMES: [&'static str; 4] = ["parent", "child", "second", "other"];
    fn who(&self, pid: u64) -> &'static str {
        self.named
            .iter()
            .position(|&n| n == pid)
            .map_or("?", |i| Self::NAMES[i])
    }
    fn value(&self, v: i64) -> String {
        match self.named.iter().position(|&n| n != 0 && n as i64 == v) {
            Some(i) => Self::NAMES[i].to_owned(),
            None => v.to_string(),
        }
    }
    /// The guest's `expect`: the next stop of `pid`, or its end.
    fn expect(&self, g: &mut Tracer, pid: u64, name: &str) {
        let status = g.wait(pid, WALL);
        let who = self.who(pid);
        if status < 0 || status & 0xff != 0x7f {
            let exited = i64::from(status >= 0 && status & 0x7f == 0);
            let code = (status >> 8) & 0xff;
            g.lines
                .push(format!("{name}: {who} exited={exited} code={code}"));
            return;
        }
        let at = HEAP + 0x500;
        g.m.write_u64(GuestAddr(at), 0).unwrap();
        g.pt(GETEVENTMSG, pid, 0, at);
        let message = g.m.read_u64(GuestAddr(at)).unwrap() as i64;
        let (_, regs) = g.regs(pid);
        let (nr, rax) = (g.reg(regs, ORIG_RAX) as i64, g.reg(regs, RAX) as i64);
        g.lines.push(format!(
            "{name}: {who} signal={} event={} nr={nr} rax={} message={}",
            (status >> 8) & 0xff,
            status >> 16,
            self.value(rax),
            self.value(message)
        ));
    }
    /// PTRACE_GET_SYSCALL_INFO into the tracer's buffer: the size, and the
    /// buffer.
    fn info(g: &mut Tracer, pid: u64) -> (i64, u64) {
        let info = HEAP + 0x600;
        g.m.write(GuestAddr(info), &[0; INFO as usize]).unwrap();
        (g.pt(GET_SYSCALL_INFO, pid, INFO, info), info)
    }
    /// The stop syscall info describes: 1 for an entry, 2 for an exit.
    fn op(g: &mut Tracer, pid: u64) -> u8 {
        let (_, info) = Self::info(g, pid);
        let mut op = [0];
        g.m.read(GuestAddr(info), &mut op).unwrap();
        op[0]
    }
    fn entry(&mut self, g: &mut Tracer, pid: u64, regs: u64) {
        let nr = g.reg(regs, ORIG_RAX) as i64;
        let rax = g.reg(regs, RAX) as i64;
        g.lines
            .push(format!("{} enter {nr} rax={rax}", self.who(pid)));
        let (size, info) = Self::info(g, pid);
        let word = |g: &Tracer, at: u64| g.m.read_u64(GuestAddr(info + at)).unwrap();
        if self.first_entry {
            self.first_entry = false;
            let mut op = [0];
            g.m.read(GuestAddr(info), &mut op).unwrap();
            let arch = read32(&g.m, info + 4);
            let same = |g: &Tracer, at, field| i32::from(word(g, at) == g.reg(regs, field));
            let (ip, sp, nr) = (same(g, 8, RIP), same(g, 16, RSP), same(g, 24, ORIG_RAX));
            g.lines.push(format!(
                "info size={size} op={} arch={arch:#x} ip={ip} sp={sp} nr={nr}",
                op[0]
            ));
            let short = g.pt(GET_SYSCALL_INFO, pid, 8, info);
            g.say("info short", short);
            let args = word(g, 32) == g.reg(regs, RDI) && word(g, 56) == g.reg(regs, R10);
            g.say("info args", i32::from(args));
        }
        if nr == GETPPID as i64 {
            // Skipped, with the value the tracer leaves in rax.
            g.m.write_u64(GuestAddr(regs + ORIG_RAX), u64::MAX).unwrap();
            g.m.write_u64(GuestAddr(regs + RAX), 42).unwrap();
            let r = g.pt(SETREGS, pid, 0, regs);
            g.say("setregs", r);
        } else if nr == GETUID as i64 {
            let set = HEAP + 0x680;
            let mut bytes = [0; INFO as usize];
            g.m.read(GuestAddr(info), &mut bytes).unwrap();
            g.m.write(GuestAddr(set), &bytes).unwrap();
            let r = g.pt(SET_SYSCALL_INFO, pid, INFO - 1, set);
            g.say("set-small", r);
            g.m.write(GuestAddr(set + 2), &1u16.to_le_bytes()).unwrap();
            let r = g.pt(SET_SYSCALL_INFO, pid, INFO, set);
            g.say("set-flags", r);
            g.m.write(GuestAddr(set + 2), &0u16.to_le_bytes()).unwrap();
            g.m.write(GuestAddr(set), &[2]).unwrap();
            let r = g.pt(SET_SYSCALL_INFO, pid, INFO, set);
            g.say("set-op", r);
            g.m.write(GuestAddr(set), &[1]).unwrap();
            g.m.write_u64(GuestAddr(set + 24), 1 << 40).unwrap();
            let r = g.pt(SET_SYSCALL_INFO, pid, INFO, set);
            g.say("set-range", r);
            g.m.write_u64(GuestAddr(set + 24), GETPID).unwrap();
            let r = g.pt(SET_SYSCALL_INFO, pid, INFO, set);
            g.say("set-entry", r);
        }
    }
    fn exit(&mut self, g: &mut Tracer, pid: u64, regs: u64) {
        let (size, info) = Self::info(g, pid);
        let mut head = [0; 33];
        g.m.read(GuestAddr(info), &mut head).unwrap();
        let rval = i64::from_le_bytes(head[24..32].try_into().unwrap());
        let nr = g.reg(regs, ORIG_RAX) as i64;
        g.lines.push(format!(
            "{} exit {nr} = {} error={} size={size} op={}",
            self.who(pid),
            self.value(rval),
            head[32],
            head[0]
        ));
        if nr == SCHED_YIELD as i64 {
            g.m.write(GuestAddr(info + 32), &[1]).unwrap();
            g.m.write_u64(GuestAddr(info + 24), -1i64 as u64).unwrap();
            let r = g.pt(SET_SYSCALL_INFO, pid, INFO, info);
            g.say("set-exit", r);
        }
    }
    /// Follows `pid` until it exits, as `strace -f` does, a child it forks
    /// first, while `pid` waits at the event.
    fn follow(&mut self, g: &mut Tracer, pid: u64) {
        loop {
            let status = g.wait(pid, WALL);
            let who = self.who(pid);
            if status < 0 || status & 0xff != 0x7f {
                let exited = i32::from(status & 0x7f == 0);
                g.lines.push(format!(
                    "{who} exited={exited} code={}",
                    (status >> 8) & 0xff
                ));
                return;
            }
            let (signal, event) = ((status >> 8) & 0xff, status >> 16);
            let mut give = 0;
            if event != 0 {
                let at = HEAP + 0x6e0;
                g.pt(GETEVENTMSG, pid, 0, at);
                let message = g.m.read_u64(GuestAddr(at)).unwrap();
                if event == 1 {
                    self.named[1] = message;
                }
                let shown = self.value(message as i64);
                g.lines.push(format!("{who} event={event} message={shown}"));
                if event == 1 {
                    self.follow(g, message);
                }
            } else if signal == SIGTRAP | 0x80 || signal == SIGTRAP {
                let (_, regs) = g.regs(pid);
                if signal == SIGTRAP {
                    // Without PTRACE_O_TRACESYSGOOD: a plain SIGTRAP, which
                    // syscall info cannot tell from another.
                    let (size, _) = Self::info(g, pid);
                    let op = Self::op(g, pid);
                    let (_, _, code, _) = g.siginfo(pid);
                    let nr = g.reg(regs, ORIG_RAX) as i64;
                    g.lines.push(format!(
                        "{who} plain nr={nr} op={op} size={size} si-code={code}"
                    ));
                    let r = g.pt(SETOPTIONS, pid, 0, O_TRACESYSGOOD | O_TRACEFORK);
                    g.say("options", r);
                } else if Self::op(g, pid) == 1 {
                    self.entry(g, pid, regs);
                } else {
                    self.exit(g, pid, regs);
                }
            } else {
                g.lines.push(format!("{who} signal={signal}"));
                if signal != SIGSTOP as i64 {
                    give = signal as u64;
                }
            }
            g.pt(SYSCALL, pid, 0, give);
        }
    }
}

/// `ptrace-strace`: syscall-entry and -exit stops, a plain SIGTRAP before
/// PTRACE_O_TRACESYSGOOD, PTRACE_GET_SYSCALL_INFO and
/// PTRACE_SET_SYSCALL_INFO, a call the tracer skips and ones it changes,
/// and the fork event with the child it follows. The lines are what the
/// guest prints, which `diff_processes` checks against native Linux.
#[test]
fn strace() {
    let mut g = Tracer::new();
    let (child, thread) = g.fork(|c| {
        let chld = HEAP + 0x910;
        c.m.write_u64(GuestAddr(chld), 1 << (SIGCHLD - 1)).unwrap();
        c.sys(RT_SIGPROCMASK, [0, chld, 0, 8, 0, 0]).unwrap();
        assert_eq!(c.sys(PTRACE, [TRACEME, 0, 0, 0, 0, 0]), Ok(0));
        c.raise(SIGSTOP, &mut |_, _, _| None).unwrap();
        let own = c.sys(GETPID, [0; 6]).unwrap();
        c.sys(CLOSE, [u64::MAX, 0, 0, 0, 0, 0]).unwrap();
        let skipped = c.sys(GETPPID, [0; 6]).unwrap();
        let changed = c.sys(GETUID, [0; 6]).unwrap();
        let failed = c.sys(SCHED_YIELD, [0; 6]).unwrap();
        let none = c.sys(1000, [0; 6]).unwrap();
        let forked = c.fork(|grandchild| {
            grandchild.sys(GETPID, [0; 6]).unwrap();
            grandchild.exit(2)
        });
        let status = HEAP + 0x920;
        c.sys(WAIT4, [forked, status, 0, 0, 0, 0]).unwrap();
        let code = i32::from(skipped == 42)
            | i32::from(changed == own) << 1
            | i32::from(neg(failed) == -1) << 2
            | i32::from(neg(none) == -38) << 3
            | i32::from(read32(&c.m, status) >> 8 & 0xff == 2) << 4;
        c.exit(code)
    });
    let mut strace = Strace {
        named: [child, 0, 0, 0],
        first_entry: true,
    };
    strace.follow(&mut g, child);
    thread.join().unwrap();
    g.check(
        "parent signal=19
parent plain nr=14 op=0 size=24 si-code=5
options=0
parent exit 14 = 0 error=0 size=33 op=2
parent enter 39 rax=-38
info size=80 op=1 arch=0xc000003e ip=1 sp=1 nr=1
info short=80
info args=1
parent exit 39 = parent error=0 size=33 op=2
parent enter 3 rax=-38
parent exit 3 = -9 error=1 size=33 op=2
parent enter 110 rax=-38
setregs=0
parent exit -1 = 42 error=0 size=33 op=2
parent enter 102 rax=-38
set-small=-22
set-flags=-22
set-op=-22
set-range=-34
set-entry=0
parent exit 39 = parent error=0 size=33 op=2
parent enter 24 rax=-38
parent exit 24 = 0 error=0 size=33 op=2
set-exit=0
parent enter 1000 rax=-38
parent exit 1000 = -38 error=1 size=33 op=2
parent enter 57 rax=-38
parent event=1 message=child
child signal=19
child enter 39 rax=-38
child exit 39 = child error=0 size=33 op=2
child enter 231 rax=-38
child exited=1 code=2
parent exit 57 = child error=0 size=33 op=2
parent enter 61 rax=-38
parent exit 61 = child error=0 size=33 op=2
parent enter 231 rax=-38
parent exited=1 code=31",
    );
}

/// `ptrace-sysemu`: under PTRACE_SYSEMU each call stops at its entry only
/// and does not run, with the value the tracer leaves in rax; resumed with
/// PTRACE_SYSCALL, the call it entered under PTRACE_SYSEMU still does not
/// run, though it stops at its exit. The lines are what the guest prints,
/// which `diff_processes` checks against native Linux.
#[test]
fn sysemu() {
    let mut g = Tracer::new();
    let (child, thread) = g.fork(|c| {
        assert_eq!(c.sys(PTRACE, [TRACEME, 0, 0, 0, 0, 0]), Ok(0));
        c.raise(SIGSTOP, &mut |_, _, _| None).unwrap();
        let emulated = c.sys(GETPID, [0; 6]).unwrap();
        let skipped = c.sys(GETPPID, [0; 6]).unwrap();
        c.exit(i32::from(emulated == 77) | i32::from(neg(skipped) == -38) << 1)
    });
    let status = g.wait(child, 0);
    let stop = if status & 0xff == 0x7f {
        (status >> 8) & 0xff
    } else {
        -1
    };
    g.say("stop", stop);
    g.pt(SETOPTIONS, child, 0, O_TRACESYSGOOD);
    let line = |g: &mut Tracer, name: &str, status: i64| {
        let (_, regs) = g.regs(child);
        let (nr, rax) = (g.reg(regs, ORIG_RAX) as i64, g.reg(regs, RAX) as i64);
        let signal = (status >> 8) & 0xff;
        g.lines
            .push(format!("{name} signal={signal} nr={nr} rax={rax}"));
        (regs, nr)
    };
    for round in 0.. {
        let r = g.pt(SYSEMU, child, 0, 0);
        g.say("sysemu", r);
        let status = g.wait(child, 0);
        let (regs, nr) = line(&mut g, "entry", status);
        if nr == GETPID as i64 {
            g.m.write_u64(GuestAddr(regs + RAX), 77).unwrap();
            g.pt(SETREGS, child, 0, regs);
        }
        if nr == GETPPID as i64 || round > 8 {
            break;
        }
    }
    g.pt(SYSCALL, child, 0, 0);
    let status = g.wait(child, 0);
    line(&mut g, "exit", status);
    g.pt(CONT, child, 0, 0);
    let status = g.wait(child, 0);
    thread.join().unwrap();
    let code = if status & 0x7f == 0 {
        (status >> 8) & 0xff
    } else {
        -1
    };
    g.say("exit", code);
    g.check(
        "stop=19
sysemu=0
entry signal=133 nr=14 rax=-38
sysemu=0
entry signal=133 nr=39 rax=-38
sysemu=0
entry signal=133 nr=110 rax=-38
exit signal=133 nr=110 rax=-38
exit=3",
    );
}

/// `ptrace-sigmask`: PTRACE_GETSIGMASK and SETSIGMASK, and the thread's and
/// the process's pending signals through PTRACE_PEEKSIGINFO, then their
/// delivery once the mask the tracer set lets them in.
#[test]
fn sigmask() {
    let mut g = Tracer::new();
    let (child, thread) = g.fork(|c| {
        c.catch(SIGUSR1, SA_RESTART);
        c.catch(SIGRTMIN, SA_RESTART);
        let set = HEAP + 0x900;
        let blocked = 1u64 << (SIGUSR1 - 1) | 1 << (SIGRTMIN - 1);
        c.m.write_u64(GuestAddr(set), blocked).unwrap();
        c.sys(RT_SIGPROCMASK, [0, set, 0, 8, 0, 0]).unwrap();
        assert_eq!(c.sys(PTRACE, [TRACEME, 0, 0, 0, 0, 0]), Ok(0));
        let pid = c.sys(GETPID, [0; 6]).unwrap();
        let tid = c.sys(GETTID, [0; 6]).unwrap();
        c.sys(TGKILL, [pid, tid, SIGUSR1, 0, 0, 0]).unwrap();
        // musl's sigqueue: SI_QUEUE, the sender and the value.
        let info = HEAP + 0xb00;
        for value in 1..=2u32 {
            c.m.write(GuestAddr(info), &[0; 128]).unwrap();
            write32(&c.m, info, SIGRTMIN as u32);
            write32(&c.m, info + 8, -1i32 as u32);
            write32(&c.m, info + 16, pid as u32);
            write32(&c.m, info + 24, value);
            c.sys(RT_SIGQUEUEINFO, [pid, SIGRTMIN, info, 0, 0, 0])
                .unwrap();
        }
        let mut handled = 0i32;
        let mut count = |_: &mut Tracee, signal: u64, _| {
            handled = handled * 100 + signal as i32;
            None
        };
        c.call(TKILL, [tid, SIGSTOP, 0, 0, 0, 0], &mut count)
            .unwrap();
        c.exit(handled % 1_000_000)
    });
    let status = g.wait(child, 0);
    g.show("stop", status);
    let (mask, infos, args) = (HEAP + 0x500, HEAP + 0x2000, HEAP + 0x600);
    let r = g.pt(GETSIGMASK, child, 4, mask);
    g.say("getmask-size", r);
    let r = g.pt(GETSIGMASK, child, 8, mask);
    g.say("getmask", r);
    let bits = g.m.read_u64(GuestAddr(mask)).unwrap();
    g.lines.push(format!(
        "mask-usr1={} mask-rtmin={}",
        bits >> (SIGUSR1 - 1) & 1,
        bits >> (SIGRTMIN - 1) & 1
    ));
    let peek = |g: &mut Tracer, offset: u64, flags: u32, count: i32, to: u64| {
        g.m.write_u64(GuestAddr(args), offset).unwrap();
        write32(&g.m, args + 8, flags);
        write32(&g.m, args + 12, count as u32);
        g.pt(PEEKSIGINFO, child, args, to)
    };
    let n = peek(&mut g, 0, 0, 4, infos);
    let mut line = format!("thread-queue={n}");
    for i in 0..n.max(0) as u64 {
        let at = infos + i * 128;
        line += &format!(" {}/{}", read32(&g.m, at), read32(&g.m, at + 8) as i32);
    }
    g.lines.push(line);
    let n = peek(&mut g, 0, 1, 4, infos);
    let mut line = format!("process-queue={n}");
    for i in 0..n.max(0) as u64 {
        let at = infos + i * 128;
        line += &format!(
            " {}/{}/{}",
            i32::from(u64::from(read32(&g.m, at)) == SIGRTMIN),
            read32(&g.m, at + 8) as i32,
            read32(&g.m, at + 24) as i32
        );
    }
    g.lines.push(line);
    let r = peek(&mut g, 1, 1, 4, infos);
    g.say("offset", r);
    let r = peek(&mut g, 9, 1, 4, infos);
    g.say("beyond", r);
    let r = peek(&mut g, 0, 2, 4, infos);
    g.say("bad-flags", r);
    let r = peek(&mut g, 0, 1, -1, infos);
    g.say("bad-nr", r);
    let r = peek(&mut g, 0, 1, 1, 8);
    g.say("bad-buffer", r);
    let none = !(1u64 << (SIGUSR1 - 1) | 1 << (SIGRTMIN - 1));
    g.m.write_u64(GuestAddr(mask), none).unwrap();
    let r = g.pt(SETSIGMASK, child, 8, mask);
    g.say("setmask", r);
    g.pt(GETSIGMASK, child, 8, mask);
    let bits = g.m.read_u64(GuestAddr(mask)).unwrap();
    g.lines.push(format!(
        "kill-blocked={} stop-blocked={} usr2-blocked={}",
        bits >> (SIGKILL - 1) & 1,
        bits >> (SIGSTOP - 1) & 1,
        bits >> (SIGUSR2 - 1) & 1
    ));
    g.m.write_u64(GuestAddr(mask), 0).unwrap();
    let r = g.pt(SETSIGMASK, child, 16, mask);
    g.say("setmask-size", r);
    g.pt(SETSIGMASK, child, 8, mask);
    g.pt(CONT, child, 0, 0);
    let status = loop {
        let status = g.wait(child, 0);
        if status & 0xff != 0x7f {
            break status;
        }
        let signal = (status >> 8) & 0xff;
        g.say("delivery", signal);
        g.pt(CONT, child, 0, signal as u64);
    };
    thread.join().unwrap();
    g.say("exit", Tracer::code(status));
    g.check(
        "stop: stopped=1 signal=19 event=0
getmask-size=-22
getmask=0
mask-usr1=1 mask-rtmin=1
thread-queue=1 10/-6
process-queue=2 1/-1/1 1/-1/2
offset=1
beyond=0
bad-flags=-22
bad-nr=-22
bad-buffer=-14
setmask=0
kill-blocked=0 stop-blocked=0 usr2-blocked=1
setmask-size=-22
delivery=10
delivery=35
delivery=35
exit=230",
    );
}

/// `ptrace-arch-rseq`: PTRACE_ARCH_PRCTL on the stopped tracee's fs and gs
/// bases, PTRACE_GET_RSEQ_CONFIGURATION, and a gs base the tracee keeps
/// after the detach.
#[test]
fn arch_rseq() {
    const AREA: u64 = HEAP + 0xc00;
    const RSEQ_SIG: u64 = 0x5305_3053;
    let mut g = Tracer::new();
    let (child, thread) = g.fork(|c| {
        // musl's thread pointer, which it sets as it starts.
        c.sys(ARCH_PRCTL, [0x1002, HEAP + 0xf00, 0, 0, 0, 0])
            .unwrap();
        let registered = c.sys(RSEQ, [AREA, 32, 0, RSEQ_SIG, 0, 0]).unwrap();
        assert_eq!(c.sys(PTRACE, [TRACEME, 0, 0, 0, 0, 0]), Ok(0));
        c.raise(SIGSTOP, &mut |_, _, _| None).unwrap();
        let gs = HEAP + 0xd00;
        c.sys(ARCH_PRCTL, [0x1004, gs, 0, 0, 0, 0]).unwrap();
        let gs = c.m.read_u64(GuestAddr(gs)).unwrap();
        c.exit(i32::from(registered == 0) | i32::from(gs == 0x1234) << 1)
    });
    let status = g.wait(child, 0);
    g.show("stop", status);
    let (_, regs) = g.regs(child);
    let fs_base = g.reg(regs, FS_BASE);
    let value = HEAP + 0x500;
    // The guest's printf reads `fs` and `gs` before the call that fills
    // them in: gcc evaluates its arguments right to left.
    g.m.write_u64(GuestAddr(value), 0).unwrap();
    let same = g.m.read_u64(GuestAddr(value)).unwrap() == fs_base;
    let r = g.pt(ARCH_PRCTL_REQUEST, child, value, 0x1003);
    g.lines.push(format!("get-fs={r} same={}", i32::from(same)));
    let r = g.pt(ARCH_PRCTL_REQUEST, child, 0x1234, 0x1001);
    g.say("set-gs", r);
    let (_, regs) = g.regs(child);
    let gs_base = g.reg(regs, GS_BASE);
    g.say("gs-base", format!("{gs_base:#x}"));
    g.m.write_u64(GuestAddr(value), 0).unwrap();
    let gs = g.m.read_u64(GuestAddr(value)).unwrap();
    let r = g.pt(ARCH_PRCTL_REQUEST, child, value, 0x1004);
    g.lines.push(format!("get-gs={r} gs={}", hex(gs)));
    let r = g.pt(ARCH_PRCTL_REQUEST, child, 1 << 63, 0x1002);
    g.say("set-fs-high", r);
    let r = g.pt(ARCH_PRCTL_REQUEST, child, 8, 0x1003);
    g.say("get-fs-fault", r);
    let r = g.pt(ARCH_PRCTL_REQUEST, child, 0, 0x1fff);
    g.say("other", r);
    let conf = HEAP + 0x600;
    let read_conf = |g: &mut Tracer, length: u64| {
        g.m.write(GuestAddr(conf), &[0; 24]).unwrap();
        let size = g.pt(GET_RSEQ_CONFIGURATION, child, length, conf);
        let pointer = g.m.read_u64(GuestAddr(conf)).unwrap() == AREA;
        let int = |at| read32(&g.m, conf + at);
        (size, i32::from(pointer), int(8), int(12), int(16))
    };
    let (size, pointer, length, signature, flags) = read_conf(&mut g, 24);
    g.lines.push(format!(
        "rseq size={size} pointer={pointer} length={length} signature={signature:#x} flags={flags}"
    ));
    let (size, pointer, length, _, _) = read_conf(&mut g, 8);
    g.lines.push(format!(
        "rseq-short size={size} pointer={pointer} length={length}"
    ));
    let r = g.pt(DETACH, child, 0, 0);
    g.say("detach", r);
    let status = g.wait(child, 0);
    thread.join().unwrap();
    g.say("exit", Tracer::code(status));
    g.check(
        "stop: stopped=1 signal=19 event=0
get-fs=0 same=0
set-gs=0
gs-base=0x1234
get-gs=0 gs=0
set-fs-high=-1
get-fs-fault=-14
other=-22
rseq size=24 pointer=1 length=32 signature=0x53053053 flags=0
rseq-short size=24 pointer=1 length=0
detach=0
exit=3",
    );
}

/// C's `%#x`: no prefix on zero.
fn hex(value: u64) -> String {
    if value == 0 {
        "0".into()
    } else {
        format!("{value:#x}")
    }
}

/// `ptrace-listen`: PTRACE_LISTEN in a group stop of a seized tracee, which
/// neither a wait nor a request then sees stopped, the trap as the group
/// stop ends, and PTRACE_INTERRUPT of a listening tracee.
#[test]
fn listen() {
    let mut g = Tracer::new();
    let (ready, told) = g.pipe();
    let paused = Arc::new(Entered::new(0));
    let pausing = Arc::clone(&paused);
    let (child, thread) = g.fork(move |c| {
        c.sys(WRITE, [told, HEAP + 0x790, 1, 0, 0, 0]).unwrap();
        pausing.store(1, std::sync::atomic::Ordering::SeqCst);
        loop {
            if let Err(status) = c.sys(PAUSE, [0; 6]) {
                return status;
            }
        }
    });
    g.ready(child, ready, &paused);
    let r = g.pt(SEIZE, child, 0, 0);
    g.say("seize", r);
    let kill = |g: &mut Tracer, signal: u64| g.call(KILL, [child, signal, 0, 0, 0, 0]);
    kill(&mut g, SIGSTOP);
    let status = g.wait(child, 0);
    g.show("sigstop", status);
    let r = g.pt(LISTEN, child, 0, 0);
    g.say("listen-signal", r);
    g.pt(CONT, child, 0, SIGSTOP);
    let status = g.wait(child, 0);
    g.show("group", status);
    let r = g.pt(LISTEN, child, 0, 0);
    g.say("listen", r);
    let r = g.wait(child, WNOHANG);
    g.say("wait", r);
    let r = g.regs(child).0;
    g.say("getregs", r);
    let r = g.pt(LISTEN, child, 0, 0);
    g.say("listen-again", r);
    let state = g.status_of(child).1;
    g.say("state", char::from(state));
    kill(&mut g, SIGCONT);
    let status = g.wait(child, 0);
    g.show("continued", status);
    g.pt(CONT, child, 0, 0);
    let status = g.wait(child, 0);
    g.show("sigcont", status);
    g.pt(CONT, child, 0, 0);
    kill(&mut g, SIGSTOP);
    let status = g.wait(child, 0);
    g.show("sigstop-2", status);
    g.pt(CONT, child, 0, SIGSTOP);
    let status = g.wait(child, 0);
    g.show("group-2", status);
    let r = g.pt(LISTEN, child, 0, 0);
    g.say("listen-2", r);
    let r = g.pt(INTERRUPT, child, 0, 0);
    g.say("interrupt", r);
    let status = g.wait(child, 0);
    g.show("interrupted", status);
    kill(&mut g, SIGKILL);
    let status = g.wait(child, 0);
    thread.join().unwrap();
    let signaled = status & 0x7f != 0 && status & 0x7f != 0x7f;
    g.say("killed", if signaled { status & 0x7f } else { -1 });
    g.check(
        "seize=0
sigstop: stopped=1 signal=19 event=0
listen-signal=-5
group: stopped=1 signal=19 event=128
listen=0
wait=0
getregs=-3
listen-again=-3
state=t
continued: stopped=1 signal=5 event=128
sigcont: stopped=1 signal=18 event=0
sigstop-2: stopped=1 signal=19 event=0
group-2: stopped=1 signal=19 event=128
listen-2=0
interrupt=0
interrupted: stopped=1 signal=19 event=128
killed=9",
    );
}

/// `ptrace-seccomp`: the stops SECCOMP_RET_TRACE makes once the tracer sets
/// PTRACE_O_TRACESECCOMP (ENOSYS before), their message and syscall info,
/// and a call the tracer skips or changes there.
#[test]
fn seccomp() {
    let mut g = Tracer::new();
    let (child, thread) = g.fork(|c| {
        // seccomp_data's number; getppid traced with 0x42, getuid with 7.
        let (fprog, code) = (HEAP + 0xe00, HEAP + 0xe40);
        let filter: [(u16, u8, u8, u32); 6] = [
            (0x20, 0, 0, 0),
            (0x15, 0, 1, GETPPID as u32),
            (0x06, 0, 0, 0x7ff0_0042),
            (0x15, 0, 1, GETUID as u32),
            (0x06, 0, 0, 0x7ff0_0007),
            (0x06, 0, 0, 0x7fff_0000),
        ];
        for (i, (op, jt, jf, k)) in filter.into_iter().enumerate() {
            let at = code + i as u64 * 8;
            let mut insn = [0u8; 8];
            insn[..2].copy_from_slice(&op.to_le_bytes());
            insn[2] = jt;
            insn[3] = jf;
            insn[4..].copy_from_slice(&k.to_le_bytes());
            c.m.write(GuestAddr(at), &insn).unwrap();
        }
        c.m.write_u64(GuestAddr(fprog), filter.len() as u64)
            .unwrap();
        c.m.write_u64(GuestAddr(fprog + 8), code).unwrap();
        assert_eq!(c.sys(PRCTL, [38, 1, 0, 0, 0, 0]), Ok(0));
        assert_eq!(c.sys(SECCOMP, [1, 0, fprog, 0, 0, 0]), Ok(0));
        assert_eq!(c.sys(PTRACE, [TRACEME, 0, 0, 0, 0, 0]), Ok(0));
        let untraced = neg(c.sys(GETPPID, [0; 6]).unwrap());
        c.raise(SIGSTOP, &mut |_, _, _| None).unwrap();
        let skipped = c.sys(GETPPID, [0; 6]).unwrap();
        let changed = c.sys(GETUID, [0; 6]).unwrap();
        let rechecked = neg(c.sys(GETPPID, [0; 6]).unwrap());
        let pid = c.sys(GETPID, [0; 6]).unwrap();
        c.exit(
            i32::from(untraced == -38)
                | i32::from(skipped == 99) << 1
                | i32::from(changed == pid) << 2
                | i32::from(rechecked > 0) << 3,
        )
    });
    let status = g.wait(child, 0);
    g.show("stop", status);
    let r = g.pt(SETOPTIONS, child, 0, O_TRACESECCOMP);
    g.say("options", r);
    let (message, info) = (HEAP + 0x500, HEAP + 0x600);
    for round in 0..3 {
        g.pt(CONT, child, 0, 0);
        let status = g.wait(child, 0);
        g.show("seccomp", status);
        g.m.write_u64(GuestAddr(message), 0).unwrap();
        g.pt(GETEVENTMSG, child, 0, message);
        let (_, regs) = g.regs(child);
        g.m.write(GuestAddr(info), &[0; INFO as usize]).unwrap();
        let size = g.pt(GET_SYSCALL_INFO, child, INFO, info);
        let message = g.m.read_u64(GuestAddr(message)).unwrap();
        let (nr, rax) = (g.reg(regs, ORIG_RAX) as i64, g.reg(regs, RAX) as i64);
        let op = g.m.read_u64(GuestAddr(info)).unwrap() & 0xff;
        let info_nr = g.m.read_u64(GuestAddr(info + 24)).unwrap() as i64;
        let ret_data = read32(&g.m, info + 80);
        g.lines.push(format!(
            "message={} nr={nr} rax={rax} info-size={size} op={op} info-nr={info_nr} ret-data={}",
            hex(message),
            hex(u64::from(ret_data))
        ));
        let set = match round {
            0 => {
                g.m.write_u64(GuestAddr(regs + RAX), 99).unwrap();
                Some(u64::MAX)
            }
            1 => Some(GETPID),
            _ => None,
        };
        if let Some(number) = set {
            g.m.write_u64(GuestAddr(regs + ORIG_RAX), number).unwrap();
            g.pt(SETREGS, child, 0, regs);
        }
    }
    g.pt(CONT, child, 0, 0);
    let status = g.wait(child, 0);
    thread.join().unwrap();
    g.say("exit", Tracer::code(status));
    g.check(
        "stop: stopped=1 signal=19 event=0
options=0
seccomp: stopped=1 signal=5 event=7
message=0x42 nr=110 rax=-38 info-size=84 op=3 info-nr=110 ret-data=0x42
seccomp: stopped=1 signal=5 event=7
message=0x7 nr=102 rax=-38 info-size=84 op=3 info-nr=102 ret-data=0x7
seccomp: stopped=1 signal=5 event=7
message=0x42 nr=110 rax=-38 info-size=84 op=3 info-nr=110 ret-data=0x42
exit=15",
    );
}

/// `ptrace-thread`: a tracer attaches to one thread of a process, whose
/// other thread stays untraced, and waits for that thread's exit.
#[test]
fn thread() {
    let mut g = Tracer::new();
    let fds = HEAP + 0x700;
    g.call(PIPE, [fds, 0, 0, 0, 0, 0]);
    g.call(PIPE, [fds + 8, 0, 0, 0, 0, 0]);
    let fd = |g: &Tracer, at: u64| u64::from(read32(&g.m, fds + at * 4));
    let (tid_read, tid_write, wake_read, wake_write) = (fd(&g, 0), fd(&g, 1), fd(&g, 2), fd(&g, 3));
    let (child, process) = g.fork(move |c| {
        c.sys(CLOSE, [tid_read, 0, 0, 0, 0, 0]).unwrap();
        let ctid = HEAP + 0xf00;
        c.thread(ctid, move |t| {
            let tid = t.sys(GETTID, [0; 6]).unwrap();
            let at = HEAP + 0xf10;
            write32(&t.m, at, tid as u32);
            t.sys(WRITE, [tid_write, at, 4, 0, 0, 0]).unwrap();
            let byte = HEAP + 0xf20;
            if let Err(status) = t.sys(READ, [wake_read, byte, 1, 0, 0, 0]) {
                return status;
            }
            match t.sys(EXIT, [0; 6]) {
                Err(status) => status,
                Ok(r) => panic!("exit returned {r}"),
            }
        });
        c.join(ctid);
        c.sys(READ, [wake_read, HEAP + 0xf30, 1, 0, 0, 0]).unwrap();
        c.exit(5)
    });
    let at = HEAP + 0x710;
    assert_eq!(g.call(READ, [tid_read, at, 4, 0, 0, 0]), 4);
    let tid = u64::from(read32(&g.m, at));
    let r = g.pt(ATTACH, tid, 0, 0);
    g.say("attach", r);
    let status = g.wait(tid, 0);
    g.stop("thread", status);
    let r = g.pt(CONT, child, 0, 0);
    g.say("process-untraced", r);
    let r = g.pt(CONT, tid, 0, 0);
    g.say("cont", r);
    g.call(WRITE, [wake_write, at, 1, 0, 0, 0]);
    let status = g.wait(tid, WALL);
    g.say("thread-exited", i64::from(status & 0x7f == 0));
    g.say("thread-code", (status >> 8) & 0xff);
    g.call(WRITE, [wake_write, at, 1, 0, 0, 0]);
    let status = g.wait(child, 0);
    process.join().unwrap();
    g.say("process-exit", Tracer::code(status));
    g.check(
        "attach=0
thread-stopped=1
thread-signal=19
thread-event=0
process-untraced=-3
cont=0
thread-exited=1
thread-code=0
process-exit=5",
    );
}

/// `ptrace-events`: PTRACE_EVENT_FORK and VFORK with their children
/// attached as they start, VFORK_DONE, EXEC with the tracee's PID, and
/// EXIT as each ends. The program it execs ends with the code
/// `exec-child` gives.
#[test]
fn events() {
    let mut g = Tracer::new();
    let (child, thread) = g.fork(|c| {
        let chld = HEAP + 0x980;
        c.m.write_u64(GuestAddr(chld), 1 << (SIGCHLD - 1)).unwrap();
        c.sys(RT_SIGPROCMASK, [0, chld, 0, 8, 0, 0]).unwrap();
        assert_eq!(c.sys(PTRACE, [TRACEME, 0, 0, 0, 0, 0]), Ok(0));
        c.raise(SIGSTOP, &mut |_, _, _| None).unwrap();
        let forked = c.fork(|c| c.exit(3));
        c.sys(WAIT4, [forked, HEAP + 0x990, 0, 0, 0, 0]).unwrap();
        c.vfork(|c| c.exit(4));
        assert_eq!(c.exec(), Ok(0));
        c.exit(7)
    });
    let mut s = Strace {
        named: [child, 0, 0, 0],
        first_entry: false,
    };
    s.expect(&mut g, child, "start");
    // FORK, VFORK, EXEC, VFORK_DONE and EXIT.
    let r = g.pt(SETOPTIONS, child, 0, 0x76);
    g.say("options", r);
    let message = |g: &mut Tracer, pid: u64| {
        let at = HEAP + 0x500;
        g.pt(GETEVENTMSG, pid, 0, at);
        g.m.read_u64(GuestAddr(at)).unwrap()
    };
    g.pt(CONT, child, 0, 0);
    let status = g.wait(child, WALL);
    s.named[1] = message(&mut g, child);
    g.lines.push(format!("fork event={}", status >> 16));
    let (_, signo, code, _) = g.siginfo(child);
    g.lines.push(format!(
        "fork si-signo={signo} si-code={}",
        hex(code as u64)
    ));
    s.expect(&mut g, s.named[1], "forked");
    let (_, _, code, pid) = g.siginfo(s.named[1]);
    g.lines.push(format!("forked si-code={code} si-pid={pid}"));
    g.pt(CONT, s.named[1], 0, 0);
    s.expect(&mut g, s.named[1], "forked-exit");
    g.pt(CONT, s.named[1], 0, 0);
    s.expect(&mut g, s.named[1], "forked-gone");
    g.pt(CONT, child, 0, 0);
    let status = g.wait(child, WALL);
    s.named[2] = message(&mut g, child);
    g.lines.push(format!("vfork event={}", status >> 16));
    s.expect(&mut g, s.named[2], "vforked");
    g.pt(CONT, s.named[2], 0, 0);
    s.expect(&mut g, s.named[2], "vforked-exit");
    g.pt(CONT, s.named[2], 0, 0);
    s.expect(&mut g, s.named[2], "vforked-gone");
    g.pt(CONT, child, 0, 0);
    s.expect(&mut g, child, "vfork-done");
    g.pt(CONT, child, 0, 0);
    s.expect(&mut g, child, "exec");
    g.pt(CONT, child, 0, 0);
    s.expect(&mut g, child, "exit");
    g.pt(CONT, child, 0, 0);
    s.expect(&mut g, child, "gone");
    thread.join().unwrap();
    g.check(
        "start: parent signal=19 event=0 nr=200 rax=0 message=0
options=0
fork event=1
fork si-signo=5 si-code=0x105
forked: child signal=19 event=0 nr=57 rax=0 message=0
forked si-code=0 si-pid=0
forked-exit: child signal=5 event=6 nr=231 rax=-38 message=768
forked-gone: child exited=1 code=3
vfork event=2
vforked: second signal=19 event=0 nr=58 rax=0 message=0
vforked-exit: second signal=5 event=6 nr=231 rax=-38 message=1024
vforked-gone: second exited=1 code=4
vfork-done: parent signal=5 event=5 nr=58 rax=-38 message=second
exec: parent signal=5 event=4 nr=59 rax=-38 message=parent
exit: parent signal=5 event=6 nr=231 rax=-38 message=1792
gone: parent exited=1 code=7",
    );
}

/// `ptrace-clone`: PTRACE_EVENT_CLONE for a thread of a seized tracee,
/// the thread seized as its maker and starting in PTRACE_EVENT_STOP, and
/// its exit as the tracer waits for it.
#[test]
fn clone() {
    let mut g = Tracer::new();
    let (go_read, go_write) = g.pipe();
    let (done_read, done_write) = g.pipe();
    let (child, thread) = g.fork(move |c| {
        c.sys(READ, [go_read, HEAP + 0x990, 1, 0, 0, 0]).unwrap();
        let ctid = HEAP + 0xf00;
        c.thread(ctid, |t| match t.sys(EXIT, [0; 6]) {
            Err(status) => status,
            Ok(r) => panic!("exit returned {r}"),
        });
        c.join(ctid);
        c.sys(READ, [done_read, HEAP + 0x990, 1, 0, 0, 0]).unwrap();
        c.exit(0)
    });
    let mut s = Strace {
        named: [child, 0, 0, 0],
        first_entry: false,
    };
    // PTRACE_O_TRACECLONE.
    let r = g.pt(SEIZE, child, 0, 8 | O_EXITKILL);
    g.say("seize", r);
    g.call(WRITE, [go_write, HEAP + 0x790, 1, 0, 0, 0]);
    let status = g.wait(child, WALL);
    let at = HEAP + 0x500;
    g.pt(GETEVENTMSG, child, 0, at);
    s.named[2] = g.m.read_u64(GuestAddr(at)).unwrap();
    let (_, regs) = g.regs(child);
    let (nr, rax) = (g.reg(regs, ORIG_RAX) as i64, g.reg(regs, RAX) as i64);
    let (size, info) = Strace::info(&mut g, child);
    let op = g.m.read_u64(GuestAddr(info)).unwrap() & 0xff;
    g.lines.push(format!(
        "clone signal={} event={} nr={nr} rax={rax} info-op={op} size={size}",
        (status >> 8) & 0xff,
        status >> 16
    ));
    s.expect(&mut g, s.named[2], "thread");
    g.pt(CONT, s.named[2], 0, 0);
    g.pt(CONT, child, 0, 0);
    s.expect(&mut g, s.named[2], "thread-gone");
    g.call(WRITE, [done_write, HEAP + 0x790, 1, 0, 0, 0]);
    s.expect(&mut g, child, "gone");
    thread.join().unwrap();
    g.check(
        "seize=0
clone signal=5 event=3 nr=56 rax=-38 info-op=0 size=24
thread: second signal=5 event=128 nr=56 rax=0 message=0
thread-gone: second exited=1 code=0
gone: parent exited=1 code=0",
    );
}

/// Where a stopped tracee is, as `single-step.c` prints it: `end`, the
/// offset into the case's sequence of the end of the system call the
/// tracee made last, when it is there, or `outside`.
fn at(rip: u64, end: u64) -> String {
    if rip == CODE {
        end.to_string()
    } else {
        "outside".into()
    }
}

/// `ptrace-singlestep`: each round from the stop for the child's SIGSTOP,
/// whose call ends at offset 12 of `seq_trace`, to the `getpid` that ends
/// at 25. PTRACE_SINGLESTEP over the call gives SIGTRAP with TRAP_BRKPT
/// after it; PTRACE_SYSEMU_SINGLESTEP stops at its entry and skips it. The
/// trap flag the tracer set is not shown, and is gone once it continues.
/// The traps of the other instructions, which only the CPU gives, are left
/// out, and the tracer continues where the guest steps them.
#[test]
fn singlestep() {
    let mut g = Tracer::new();
    let (child, thread) = g.fork(|c| {
        assert_eq!(c.sys(PTRACE, [TRACEME, 0, 0, 0, 0, 0]), Ok(0));
        for _ in 0..2 {
            let pid = c.sys(GETPID, [0; 6]).unwrap();
            c.sys(KILL, [pid, SIGSTOP, 0, 0, 0, 0]).unwrap();
            c.sys(GETPID, [0; 6]).unwrap();
        }
        // The guest's exit on the flag it has.
        let tf = c.t.cpu.rflags & TF != 0;
        c.exit(i32::from(tf))
    });
    g.wait(child, 0);
    let mut status = 0;
    for (request, name) in [
        (SINGLESTEP, "singlestep"),
        (SYSEMU_SINGLESTEP, "sysemu-singlestep"),
    ] {
        if request == SYSEMU_SINGLESTEP {
            g.pt(SETOPTIONS, child, 0, O_TRACESYSGOOD);
        }
        let (_, regs) = g.regs(child);
        let rip = g.reg(regs, RIP);
        g.lines.push(format!("{name}: stopped at={}", at(rip, 12)));
        let r = g.pt(request, child, 0, 0);
        let stop = g.wait(child, 0);
        assert_eq!((r, stop & 0xff), (0, 0x7f));
        let (_, _, code, _) = g.siginfo(child);
        let (_, regs) = g.regs(child);
        let signal = (stop >> 8) & 0xff;
        let mut line = format!(
            "{name}: signal={} code={} at={} nr={} tf-shown={}",
            hex(signal as u64),
            hex(code as u64),
            at(g.reg(regs, RIP), 25),
            g.reg(regs, ORIG_RAX) as i64,
            i64::from(g.reg(regs, EFLAGS) & TF != 0),
        );
        if signal == SIGTRAP | 0x80 {
            line += &format!(" rax={}", g.reg(regs, RAX) as i64);
        }
        g.lines.push(line);
        g.pt(CONT, child, 0, 0);
        status = g.wait(child, 0);
    }
    g.say("exit", Tracer::code(status));
    thread.join().unwrap();
    g.check(
        "singlestep: stopped at=12
singlestep: signal=0x5 code=0x1 at=25 nr=39 tf-shown=0
sysemu-singlestep: stopped at=12
sysemu-singlestep: signal=0x85 code=0x85 at=25 nr=39 tf-shown=0 rax=-38
exit=0",
    );
}

/// `ptrace-forced-frame`: stepped from the stop for its SIGSTOP over the
/// `kill` that sends it SIGUSR1, whose call ends at offset 24 of
/// `seq_frame`, then stepped into the handler: stepping ends there, so the
/// handler's frame keeps no trap flag the tracer set, and nothing traps
/// once the tracer lets it run. The traps of the two moves before the
/// call, which only the CPU gives, are left out.
#[test]
fn forced_frame() {
    let mut g = Tracer::new();
    let (child, thread) = g.fork(|c| {
        // musl's `signal`.
        c.catch(SIGUSR1, SA_RESTART);
        assert_eq!(c.sys(PTRACE, [TRACEME, 0, 0, 0, 0, 0]), Ok(0));
        let pid = c.sys(GETPID, [0; 6]).unwrap();
        c.sys(KILL, [pid, SIGSTOP, 0, 0, 0, 0]).unwrap();
        let mut handled = false;
        c.call(KILL, [pid, SIGUSR1, 0, 0, 0, 0], &mut |_, signal, _| {
            handled = signal == SIGUSR1;
            None
        })
        .unwrap();
        assert!(handled);
        // rt_sigreturn gave back no trap flag, so nothing traps after.
        let tf = c.t.cpu.rflags & TF != 0;
        c.exit(i32::from(tf))
    });
    g.wait(child, 0);
    let mut status = 0;
    for _ in 0..20 {
        g.pt(SINGLESTEP, child, 0, 0);
        status = g.wait(child, 0);
        if status & 0xff != 0x7f || (status >> 8) & 0xff == SIGUSR1 as i64 {
            break;
        }
        let (_, _, code, _) = g.siginfo(child);
        let (_, regs) = g.regs(child);
        let line = format!(
            "step: signal={} code={} at={}",
            (status >> 8) & 0xff,
            hex(code as u64),
            at(g.reg(regs, RIP), 24)
        );
        g.lines.push(line);
    }
    let stopped = status & 0xff == 0x7f;
    g.lines.push(format!(
        "delivery: signal={}",
        if stopped { (status >> 8) & 0xff } else { -1 }
    ));
    g.pt(SINGLESTEP, child, 0, SIGUSR1);
    let status = g.wait(child, 0);
    let (_, _, code, _) = g.siginfo(child);
    let (_, regs) = g.regs(child);
    let line = format!(
        "handler: signal={} code={} in-handler={} tf-shown={}",
        (status >> 8) & 0xff,
        hex(code as u64),
        i64::from(g.reg(regs, RIP) == HANDLER),
        i64::from(g.reg(regs, EFLAGS) & TF != 0)
    );
    g.lines.push(line);
    g.pt(CONT, child, 0, 0);
    let status = g.wait(child, 0);
    g.say("exit", Tracer::code(status));
    thread.join().unwrap();
    g.check(
        "step: signal=5 code=0x1 at=24
delivery: signal=10
handler: signal=5 code=0x5 in-handler=1 tf-shown=0
exit=0",
    );
}

/// `ptrace-attach-stopped`: PTRACE_ATTACH and PTRACE_SEIZE of a child
/// already in a group stop return once it has stopped for its new tracer,
/// which sees the group stop at once (PTRACE_EVENT_STOP for the seize,
/// with no siginfo for the attach); the attach's own SIGSTOP then has its
/// delivery stop.
#[test]
fn attach_stopped() {
    let mut g = Tracer::new();
    for (seize, name) in [(false, "attach"), (true, "seize")] {
        let (child, thread) = g.fork(|c| {
            loop {
                if let Err(status) = c.sys(PAUSE, [0; 6]) {
                    return status;
                }
            }
        });
        g.call(KILL, [child, SIGSTOP, 0, 0, 0, 0]);
        let status = g.wait(child, WUNTRACED);
        g.stop(&format!("{name}-group"), status);
        let r = g.pt(if seize { SEIZE } else { ATTACH }, child, 0, 0);
        g.say(name, r);
        let status = g.wait(child, WNOHANG | WALL);
        g.stop(&format!("{name}-trap"), status);
        let (error, signo, _, _) = g.siginfo(child);
        g.say(&format!("{name}-siginfo"), error);
        g.say(&format!("{name}-si-signo"), signo);
        if !seize {
            let r = g.pt(CONT, child, 0, 0);
            g.say("cont", r);
            let status = g.wait(child, WALL);
            g.stop("sigstop", status);
        }
        g.call(KILL, [child, SIGKILL, 0, 0, 0, 0]);
        let status = g.wait(child, WALL);
        let killed = if status & 0x7f != 0 && status & 0xff != 0x7f {
            status & 0x7f
        } else {
            -1
        };
        g.say(&format!("{name}-killed"), killed);
        thread.join().unwrap();
    }
    g.check(
        "attach-group-stopped=1
attach-group-signal=19
attach-group-event=0
attach=0
attach-trap-stopped=1
attach-trap-signal=19
attach-trap-event=0
attach-siginfo=-22
attach-si-signo=0
cont=0
sigstop-stopped=1
sigstop-signal=19
sigstop-event=0
attach-killed=9
seize-group-stopped=1
seize-group-signal=19
seize-group-event=0
seize=0
seize-trap-stopped=1
seize-trap-signal=19
seize-trap-event=128
seize-siginfo=0
seize-si-signo=19
seize-killed=9",
    );
}

/// `ptrace-tracer-exit`: a sibling seizes two children, which let any
/// task trace them (Yama's PR_SET_PTRACER), and exits while it traces
/// them: the one seized with PTRACE_O_EXITKILL gets SIGKILL, and the
/// other is let go and runs on.
#[test]
fn tracer_exit() {
    let mut g = Tracer::new();
    let (ready_read, ready_write) = g.pipe();
    let mut kids = Vec::new();
    for _ in 0..2 {
        kids.push(g.fork(move |c| {
            // PR_SET_PTRACER, PR_SET_PTRACER_ANY.
            c.sys(PRCTL, [0x5961_6d61, u64::MAX, 0, 0, 0, 0]).unwrap();
            c.sys(WRITE, [ready_write, HEAP + 0x790, 1, 0, 0, 0])
                .unwrap();
            loop {
                if let Err(status) = c.sys(PAUSE, [0; 6]) {
                    return status;
                }
            }
        }));
    }
    for _ in 0..2 {
        assert_eq!(g.call(READ, [ready_read, HEAP + 0x798, 1, 0, 0, 0]), 1);
    }
    let (kill_pid, keep_pid) = (kids[0].0, kids[1].0);
    let (lines, rx) = std::sync::mpsc::channel();
    let (tracer, tracer_thread) = g.fork(move |c| {
        for (name, pid, options) in [
            ("seize-kill", kill_pid, O_EXITKILL),
            ("seize-keep", keep_pid, 0),
        ] {
            let r = c.sys(PTRACE, [SEIZE, pid, 0, options, 0, 0]).unwrap();
            lines.send(format!("{name}={}", neg(r))).unwrap();
        }
        c.exit(0)
    });
    let status = g.wait(tracer, 0);
    g.lines.extend(rx.try_iter());
    g.say("tracer-exit", Tracer::code(status));
    tracer_thread.join().unwrap();
    let signaled = |status: i64| {
        if status & 0x7f != 0 && status & 0xff != 0x7f {
            status & 0x7f
        } else {
            -1
        }
    };
    let status = g.wait(kill_pid, 0);
    g.say("killed", signaled(status));
    let running = g.wait(keep_pid, WNOHANG);
    g.say("kept-running", running);
    g.call(KILL, [keep_pid, SIGTERM, 0, 0, 0, 0]);
    let status = g.wait(keep_pid, 0);
    g.say("kept-term", signaled(status));
    for (_, thread) in kids {
        thread.join().unwrap();
    }
    g.check(
        "seize-kill=0
seize-keep=0
tracer-exit=0
killed=9
kept-running=0
kept-term=15",
    );
}

/// `ptrace-restart-codes`: the restart code a tracer sees in `rax` at the
/// stop for a signal that interrupts a blocked `read`, and what each code
/// it leaves there does: -ERESTARTNOINTR restarts the call after the
/// handler, -ERESTARTNOHAND gives EINTR after even an SA_RESTART handler,
/// an `orig_rax` of -1 leaves no call to restart, and
/// -ERESTART_RESTARTBLOCK, with the signal taken back, gives EINTR from
/// `restart_syscall`.
#[test]
fn restart_codes() {
    let mut g = Tracer::new();
    let (pipe_read, pipe_write) = g.pipe();
    let (lines, rx) = std::sync::mpsc::channel();
    // The reads the child has gone into: each signal waits for the next.
    let reads = Arc::new(Entered::new(0));
    let entered = Arc::clone(&reads);
    let (child, thread) = g.fork(move |c| {
        c.catch(SIGUSR1, 0);
        c.catch(SIGUSR2, SA_RESTART);
        assert_eq!(c.sys(PTRACE, [TRACEME, 0, 0, 0, 0, 0]), Ok(0));
        let tid = u64::from(c.t.tid);
        c.sys(TKILL, [tid, SIGSTOP, 0, 0, 0, 0]).unwrap();
        let mut read = || {
            entered.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            neg(c
                .call(
                    READ,
                    [pipe_read, HEAP + 0x990, 1, 0, 0, 0],
                    &mut |_, _, _| None,
                )
                .unwrap())
        };
        let (nointr, nohand, literal, block) = (read(), read(), read(), read());
        lines
            .send(format!(
                "nointr={nointr} nohand={nohand} literal={literal} block={block}"
            ))
            .unwrap();
        c.exit(0)
    });
    g.wait(child, 0);
    g.pt(CONT, child, 0, 0);
    let mut nth = 0;
    let mut interrupt = |g: &mut Tracer, signal: u64, rax: i64, orig: i64, resume: u64| {
        nth += 1;
        g.sleeping_in(child, &reads, nth);
        g.call(KILL, [child, signal, 0, 0, 0, 0]);
        let status = g.wait(child, 0);
        let (_, regs) = g.regs(child);
        let stopped = status & 0xff == 0x7f;
        g.lines.push(format!(
            "stop={} rax={}",
            if stopped { (status >> 8) & 0xff } else { -1 },
            g.reg(regs, RAX) as i64
        ));
        g.m.write_u64(GuestAddr(regs + RAX), rax as u64).unwrap();
        if orig != 0 {
            g.m.write_u64(GuestAddr(regs + ORIG_RAX), orig as u64)
                .unwrap();
        }
        g.pt(SETREGS, child, 0, regs);
        g.pt(CONT, child, 0, resume);
    };
    interrupt(&mut g, SIGUSR1, -513, 0, SIGUSR1);
    g.call(WRITE, [pipe_write, HEAP + 0x790, 1, 0, 0, 0]);
    interrupt(&mut g, SIGUSR2, -514, 0, SIGUSR2);
    interrupt(&mut g, SIGUSR1, -512, -1, SIGUSR1);
    interrupt(&mut g, SIGUSR1, -516, 0, 0);
    let status = g.wait(child, 0);
    g.lines.extend(rx.try_iter());
    g.say("exit", Tracer::code(status));
    thread.join().unwrap();
    g.check(
        "stop=10 rax=-512
stop=12 rax=-512
stop=10 rax=-512
stop=10 rax=-512
nointr=1 nohand=-4 literal=-512 block=-4
exit=0",
    );
}

/// `ptrace-exit-core`: PTRACE_EVENT_EXIT of a process a fatal signal ends,
/// with a core and without: the event's status has 0x80 only when it
/// dumps one.
#[test]
fn exit_core() {
    let mut g = Tracer::new();
    for (name, limit) in [("core", u64::MAX), ("no-core", 0)] {
        let (child, thread) = g.fork(move |c| {
            // setrlimit(RLIMIT_CORE), the soft limit up to the hard one.
            let at = HEAP + 0x9a0;
            c.sys(PRLIMIT64, [0, 4, 0, at, 0, 0]).unwrap();
            let hard = c.m.read_u64(GuestAddr(at + 8)).unwrap();
            c.m.write_u64(GuestAddr(at), limit.min(hard)).unwrap();
            c.sys(PRLIMIT64, [0, 4, at, 0, 0, 0]).unwrap();
            assert_eq!(c.sys(PTRACE, [TRACEME, 0, 0, 0, 0, 0]), Ok(0));
            let tid = u64::from(c.t.tid);
            for signal in [SIGSTOP, SIGQUIT] {
                if let Err(status) = c.sys(TKILL, [tid, signal, 0, 0, 0, 0]) {
                    return status;
                }
            }
            c.exit(91)
        });
        g.wait(child, 0);
        g.pt(SETOPTIONS, child, 0, O_TRACEEXIT);
        g.pt(CONT, child, 0, 0);
        let status = g.wait(child, 0);
        g.lines
            .push(format!("{name}: delivery={}", (status >> 8) & 0xff));
        g.pt(CONT, child, 0, SIGQUIT);
        let status = g.wait(child, 0);
        let at = HEAP + 0x500;
        g.pt(GETEVENTMSG, child, 0, at);
        let message = g.m.read_u64(GuestAddr(at)).unwrap();
        g.lines.push(format!(
            "{name}: event={} message={}",
            status >> 16,
            hex(message)
        ));
        g.pt(CONT, child, 0, 0);
        let status = g.wait(child, 0);
        let signaled = status & 0x7f != 0 && status & 0xff != 0x7f;
        g.lines.push(format!(
            "{name}: signal={} core={}",
            if signaled { status & 0x7f } else { -1 },
            i64::from(status & 0x80 != 0)
        ));
        thread.join().unwrap();
    }
    g.check(
        "core: delivery=3
core: event=6 message=0x83
core: signal=3 core=1
no-core: delivery=3
no-core: event=6 message=0x3
no-core: signal=3 core=0",
    );
}

/// `ptrace-selectors`: the segment selectors a tracer reads and writes. A
/// data selector may be set to a user one, not to a kernel one, and `cs`
/// not to the null one (`EIO`); SETREGS keeps only a selector's 16 bits.
#[test]
fn selectors() {
    const ES: u64 = 192;
    const FS: u64 = 200;
    const GS: u64 = 208;
    let mut g = Tracer::new();
    let (child, thread) = g.fork(|c| {
        assert_eq!(c.sys(PTRACE, [TRACEME, 0, 0, 0, 0, 0]), Ok(0));
        let tid = u64::from(c.t.tid);
        if let Err(status) = c.sys(TKILL, [tid, SIGSTOP, 0, 0, 0, 0]) {
            return status;
        }
        c.exit(0)
    });
    g.wait(child, 0);
    let (_, regs) = g.regs(child);
    let line = [
        ("ds", DS),
        ("es", ES),
        ("fs", FS),
        ("gs", GS),
        ("cs", CS),
        ("ss", SS),
    ]
    .map(|(name, field)| format!("{name}={}", hex(g.reg(regs, field))))
    .join(" ");
    g.lines.push(line);
    let r = g.pt(POKEUSER, child, DS, 0x2b);
    g.say("poke-ds", r);
    let word = HEAP + 0x500;
    let peeked = g.pt(PEEKUSER, child, DS, word);
    let value = g.m.read_u64(GuestAddr(word)).unwrap();
    g.lines
        .push(format!("peek-ds={peeked} word={}", hex(value)));
    let r = g.pt(POKEUSER, child, DS, 0x10);
    g.say("poke-ds-kernel", r);
    let r = g.pt(POKEUSER, child, CS, 0);
    g.say("poke-cs-null", r);
    let (_, regs) = g.regs(child);
    g.m.write_u64(GuestAddr(regs + ES), 0x1002b).unwrap();
    let r = g.pt(SETREGS, child, 0, regs);
    g.say("setregs", r);
    let (_, regs) = g.regs(child);
    let line = format!("ds={} es={}", hex(g.reg(regs, DS)), hex(g.reg(regs, ES)));
    g.lines.push(line);
    g.pt(CONT, child, 0, 0);
    let status = g.wait(child, 0);
    g.say("exit", Tracer::code(status));
    thread.join().unwrap();
    g.check(
        "ds=0 es=0 fs=0 gs=0 cs=0x33 ss=0x2b
poke-ds=0
peek-ds=0 word=0x2b
poke-ds-kernel=-5
poke-cs-null=-5
setregs=0
ds=0x2b es=0x2b
exit=0",
    );
}

/// `ptrace-syscall-signal`: a signal given at a syscall-entry stop comes
/// as the call returns. At the exit stop it waits in the thread's queue,
/// from the kernel (SI_KERNEL), not the process's; its delivery stop
/// follows, and the handler gets it with that code.
#[test]
fn syscall_signal() {
    let mut g = Tracer::new();
    let (child, thread) = g.fork(|c| {
        c.catch(SIGUSR1, SA_SIGINFO);
        assert_eq!(c.sys(PTRACE, [TRACEME, 0, 0, 0, 0, 0]), Ok(0));
        let tid = u64::from(c.t.tid);
        if let Err(status) = c.sys(TKILL, [tid, SIGSTOP, 0, 0, 0, 0]) {
            return status;
        }
        let mut code = 0;
        let r = c.call(GETPPID, [0; 6], &mut |c, _, info| {
            code = read32(&c.m, info + 8);
            None
        });
        if let Err(status) = r {
            return status;
        }
        c.exit(if code == 0x80 { 0 } else { 1 })
    });
    let status = g.wait(child, 0);
    g.show("stop", status);
    g.pt(SYSCALL, child, 0, 0);
    let status = g.wait(child, 0);
    let (_, regs) = g.regs(child);
    let line = format!(
        "entry signal={} nr={}",
        (status >> 8) & 0xff,
        g.reg(regs, ORIG_RAX) as i64
    );
    g.lines.push(line);
    g.pt(SYSCALL, child, 0, SIGUSR1);
    let status = g.wait(child, 0);
    let (_, regs) = g.regs(child);
    let line = format!(
        "exit signal={} nr={}",
        (status >> 8) & 0xff,
        g.reg(regs, ORIG_RAX) as i64
    );
    g.lines.push(line);
    let (args, infos) = (HEAP + 0x600, HEAP + 0x1000);
    g.m.write(GuestAddr(args), &[0; 16]).unwrap();
    write32(&g.m, args + 12, 2);
    let n = g.pt(PEEKSIGINFO, child, args, infos);
    g.say("thread-queue", n);
    write32(&g.m, args + 8, 1);
    let n = g.pt(PEEKSIGINFO, child, args, infos);
    let mut line = format!("process-queue={n}");
    for i in 0..n.max(0) as u64 {
        let at = infos + i * 128;
        line += &format!(
            " {}/{}",
            read32(&g.m, at),
            hex(u64::from(read32(&g.m, at + 8)))
        );
    }
    g.lines.push(line);
    g.pt(CONT, child, 0, 0);
    let status = g.wait(child, 0);
    let (_, _, code, pid) = g.siginfo(child);
    let signal = (status >> 8) & 0xff;
    g.lines.push(format!(
        "delivery signal={signal} si-code={} si-pid={pid}",
        hex(code as u64)
    ));
    g.pt(CONT, child, 0, signal as u64);
    let status = g.wait(child, 0);
    g.say("exit", Tracer::code(status));
    thread.join().unwrap();
    g.check(
        "stop: stopped=1 signal=19 event=0
entry signal=5 nr=110
exit signal=5 nr=110
thread-queue=1
process-queue=0
delivery signal=10 si-code=0x80 si-pid=0
exit=0",
    );
}

/// The three lines a stop prints as `ptrace.c` shows it, for a task other
/// than the tracer.
fn stop_lines(name: &str, status: i64) -> [String; 3] {
    let stopped = status & 0xff == 0x7f;
    [
        format!("{name}-stopped={}", i64::from(stopped)),
        format!(
            "{name}-signal={}",
            if stopped { (status >> 8) & 0xff } else { -1 }
        ),
        format!("{name}-event={}", status >> 16),
    ]
}

/// `ptrace-wait`: a tracer that is not the tracee's parent, whose second
/// thread attaches it. With `__WNOTHREAD` its first thread has nothing to
/// wait for, nor may it make requests; without, it waits for the stops by
/// the tracee's process group, as `waitid`'s CLD_TRAPPED even when it asks
/// for exits only, and for the exit as any child. The parent sees the group
/// stop, not the ptrace stop before it, nor the exit before the tracer has
/// reaped it.
#[test]
fn wait() {
    const SETPGID: u64 = 109;
    const GETPGID: u64 = 121;
    const WAITID: u64 = 247;
    const WNOTHREAD: u64 = 0x2000_0000;
    let mut g = Tracer::new();
    assert_eq!(g.call(SETPGID, [0; 6]), 0);
    let (ready_read, ready_write) = g.pipe();
    let (to_thread_read, to_thread_write) = g.pipe();
    let (from_thread_read, from_thread_write) = g.pipe();
    let (to_parent_read, to_parent_write) = g.pipe();
    let (from_parent_read, from_parent_write) = g.pipe();
    let (child, child_thread) = g.fork(move |c| {
        // PR_SET_PTRACER, PR_SET_PTRACER_ANY.
        c.sys(PRCTL, [0x5961_6d61, u64::MAX, 0, 0, 0, 0]).unwrap();
        c.sys(WRITE, [ready_write, HEAP + 0x790, 1, 0, 0, 0])
            .unwrap();
        loop {
            if let Err(status) = c.sys(PAUSE, [0; 6]) {
                return status;
            }
        }
    });
    assert_eq!(g.call(READ, [ready_read, HEAP + 0x798, 1, 0, 0, 0]), 1);
    let pgid = g.call(GETPGID, [child, 0, 0, 0, 0, 0]);
    let (lines, rx) = std::sync::mpsc::channel::<String>();
    let (tracer, tracer_thread) = g.fork(move |c| {
        c.sys(SETPGID, [0; 6]).unwrap();
        let thread_lines = lines.clone();
        let ctid = HEAP + 0xf00;
        c.thread(ctid, move |t| {
            let r = t.sys(PTRACE, [ATTACH, child, 0, 0, 0, 0]).unwrap();
            thread_lines.send(format!("attach={}", neg(r))).unwrap();
            t.sys(WRITE, [from_thread_write, HEAP + 0xf40, 1, 0, 0, 0])
                .unwrap();
            let command = HEAP + 0xf48;
            loop {
                match t.sys(READ, [to_thread_read, command, 1, 0, 0, 0]) {
                    Ok(1) => {}
                    Ok(_) => break,
                    Err(status) => return status,
                }
                let mut byte = [0];
                t.m.read(GuestAddr(command), &mut byte).unwrap();
                if byte[0] == b'q' {
                    break;
                }
                let signal = if byte[0] == b's' { SIGSTOP } else { 0 };
                let r = t.sys(PTRACE, [CONT, child, 0, signal, 0, 0]).unwrap();
                thread_lines
                    .send(format!("thread-cont={}", neg(r)))
                    .unwrap();
                t.sys(WRITE, [from_thread_write, HEAP + 0xf40, 1, 0, 0, 0])
                    .unwrap();
            }
            match t.sys(EXIT, [0; 6]) {
                Err(status) => status,
                Ok(r) => panic!("exit returned {r}"),
            }
        });
        let status_at = HEAP + 0xe00;
        // `waited_for`: 1 for the child, 0 for none, -errno, 2 for another.
        let waited_for = |c: &mut Tracee, pid: u64, flags: u64| -> (i64, i64) {
            loop {
                let r = neg(c.sys(WAIT4, [pid, status_at, flags, 0, 0, 0]).unwrap());
                if r == -4 {
                    continue;
                }
                let status = i64::from(read32(&c.m, status_at));
                let found = match r {
                    r if r < 0 => r,
                    0 => 0,
                    r if r as u64 == child => 1,
                    _ => 2,
                };
                return (found, status);
            }
        };
        // Tells the other side `what` and waits for its byte back.
        let ask = |c: &mut Tracee, to: u64, from: u64, what: u8| {
            c.m.write(GuestAddr(HEAP + 0xe40), &[what]).unwrap();
            c.sys(WRITE, [to, HEAP + 0xe40, 1, 0, 0, 0]).unwrap();
            c.sys(READ, [from, HEAP + 0xe48, 1, 0, 0, 0]).unwrap();
        };
        c.sys(READ, [from_thread_read, HEAP + 0xe48, 1, 0, 0, 0])
            .unwrap();
        let say = |name: &str, value: i64| lines.send(format!("{name}={value}")).unwrap();
        say("nothread-pid", waited_for(c, child, WNOHANG | WNOTHREAD).0);
        say(
            "nothread-any",
            waited_for(c, u64::MAX, WNOHANG | WNOTHREAD).0,
        );
        say("own-group", waited_for(c, 0, WNOHANG).0);
        let r = c.sys(PTRACE, [CONT, child, 0, 0, 0, 0]).unwrap();
        say("cont-not-tracer", neg(r));
        let (found, status) = waited_for(c, pgid.wrapping_neg(), 0);
        say("pgid", found);
        for line in stop_lines("pgid", status) {
            lines.send(line).unwrap();
        }
        ask(c, to_parent_write, from_parent_read, b'p');
        ask(c, to_thread_write, from_thread_read, b's');
        let info = HEAP + 0xe80;
        c.m.write(GuestAddr(info), &[0; 128]).unwrap();
        // P_PGID, WEXITED.
        let r = c.sys(WAITID, [2, pgid, info, 4, 0, 0]).unwrap();
        say("waitid", neg(r));
        say("waitid-code", i64::from(read32(&c.m, info + 8)));
        say("waitid-status", i64::from(read32(&c.m, info + 24)));
        say(
            "waitid-pid",
            i64::from(u64::from(read32(&c.m, info + 16)) == child),
        );
        ask(c, to_parent_write, from_parent_read, b'g');
        ask(c, to_thread_write, from_thread_read, b'c');
        c.sys(KILL, [child, SIGKILL, 0, 0, 0, 0]).unwrap();
        let (found, status) = waited_for(c, u64::MAX, 0);
        say("any", found);
        let term = if status & 0x7f != 0 && status & 0xff != 0x7f {
            status & 0x7f
        } else {
            -1
        };
        say("any-term", term);
        say("after-reap", waited_for(c, u64::MAX, WNOHANG).0);
        c.m.write(GuestAddr(HEAP + 0xe40), b"q").unwrap();
        c.sys(WRITE, [to_thread_write, HEAP + 0xe40, 1, 0, 0, 0])
            .unwrap();
        c.join(ctid);
        c.exit(0)
    });
    // The parent's waits while the tracer holds the child, printed once the
    // tracer has printed its own lines.
    let byte = HEAP + 0x7a0;
    assert_eq!(g.call(READ, [to_parent_read, byte, 1, 0, 0, 0]), 1);
    let ptrace_stop = g.wait(child, WNOHANG | WUNTRACED);
    g.call(WRITE, [from_parent_write, byte, 1, 0, 0, 0]);
    assert_eq!(g.call(READ, [to_parent_read, byte, 1, 0, 0, 0]), 1);
    let group = g.wait(child, WNOHANG | WUNTRACED);
    let again = g.wait(child, WNOHANG | WUNTRACED);
    g.call(WRITE, [from_parent_write, byte, 1, 0, 0, 0]);
    let status = g.wait(tracer, 0);
    tracer_thread.join().unwrap();
    g.lines.extend(rx.try_iter());
    g.say("tracer-exit", Tracer::code(status));
    g.say("parent-ptrace-stop", ptrace_stop);
    g.stop("parent-group", group);
    g.say("parent-again", again);
    let status = g.wait(child, 0);
    child_thread.join().unwrap();
    g.say("parent-term", status & 0x7f);
    g.check(
        "attach=0
nothread-pid=-10
nothread-any=-10
own-group=-10
cont-not-tracer=-3
pgid=1
pgid-stopped=1
pgid-signal=19
pgid-event=0
thread-cont=0
waitid=0
waitid-code=4
waitid-status=19
waitid-pid=1
thread-cont=0
any=1
any-term=9
after-reap=-10
tracer-exit=0
parent-ptrace-stop=0
parent-group-stopped=1
parent-group-signal=19
parent-group-event=0
parent-again=0
parent-term=9",
    );
}

/// `ptrace-detach`: how a tracee goes free. PTRACE_DETACH from a
/// signal-delivery-stop gives the signal it names in place of the one
/// stopped for. A tracer that exits lets a tracee in a stop go on with the
/// signal it stopped for if it did not wait for the stop (a WNOWAIT wait
/// leaves it unwaited), and without one if it did; it hands an exit it did
/// not reap to the parent, which until then does not see it; and a tracee
/// it detaches in a group stop stays stopped, a stop its parent saw while
/// it was traced.
#[test]
fn detach() {
    const WAITID: u64 = 247;
    const WCONTINUED: u64 = 8;
    const WNOWAIT: u64 = 0x100_0000;
    let mut g = Tracer::new();
    // The child's handlers record SIGUSR1 and SIGUSR2; it exits with
    // whether each came.
    let (child, thread) = g.fork(|c| {
        c.catch(SIGUSR1, 0);
        c.catch(SIGUSR2, 0);
        assert_eq!(c.sys(PTRACE, [TRACEME, 0, 0, 0, 0, 0]), Ok(0));
        let mut got = [false; 2];
        c.raise(SIGUSR1, &mut |_, signal, _| {
            got[usize::from(signal == SIGUSR2)] = true;
            None
        })
        .unwrap();
        c.exit(i32::from(got[0]) * 10 + i32::from(got[1]))
    });
    let status = g.wait(child, 0);
    g.stop("usr1", status);
    let r = g.pt(DETACH, child, 0, SIGUSR2);
    g.say("detach-usr2", r);
    let tracer = g.status_of(child).0;
    g.say("detached-tracer", tracer);
    let status = g.wait(child, 0);
    thread.join().unwrap();
    g.say("detach-exit", Tracer::code(status));
    let (ready_read, ready_write) = g.pipe();
    // A child any task may trace, which waits in pause until SIGUSR2: its
    // exit code is whether SIGUSR1 came.
    let traceable = move |c: &mut Tracee| {
        c.catch(SIGUSR1, 0);
        c.catch(SIGUSR2, 0);
        // PR_SET_PTRACER, PR_SET_PTRACER_ANY.
        c.sys(PRCTL, [0x5961_6d61, u64::MAX, 0, 0, 0, 0]).unwrap();
        c.sys(WRITE, [ready_write, HEAP + 0x790, 1, 0, 0, 0])
            .unwrap();
        let mut got = [false; 2];
        while !got[1] {
            if let Err(status) = c.call(PAUSE, [0; 6], &mut |_, signal, _| {
                got[usize::from(signal == SIGUSR2)] = true;
                None
            }) {
                return status;
            }
        }
        c.exit(i32::from(got[0]))
    };
    // What a waitid for `pid` found, as `waited` prints it.
    let waited = |c: &mut Tracee, name: &str, pid: u64, options: u64| -> [String; 2] {
        let info = HEAP + 0xe80;
        c.m.write(GuestAddr(info), &[0; 128]).unwrap();
        // P_PID.
        let r = neg(c.sys(WAITID, [1, pid, info, options, 0, 0]).unwrap());
        let code = if r < 0 {
            r
        } else {
            i64::from(read32(&c.m, info + 8))
        };
        [
            format!("{name}-code={code}"),
            format!("{name}-status={}", read32(&c.m, info + 24)),
        ]
    };
    let wait_in = |c: &mut Tracee, pid: u64| -> i64 {
        let at = HEAP + 0xe00;
        c.sys(WAIT4, [pid, at, 0, 0, 0, 0]).unwrap();
        i64::from(read32(&c.m, at))
    };
    for (keep, name) in [(false, "waited"), (true, "unwaited")] {
        let (child, thread) = g.fork(traceable);
        assert_eq!(g.call(READ, [ready_read, HEAP + 0x798, 1, 0, 0, 0]), 1);
        let (lines, rx) = std::sync::mpsc::channel::<String>();
        let (tracer, tracer_thread) = g.fork(move |c| {
            c.sys(PTRACE, [ATTACH, child, 0, 0, 0, 0]).unwrap();
            wait_in(c, child);
            c.sys(PTRACE, [CONT, child, 0, 0, 0, 0]).unwrap();
            c.sys(KILL, [child, SIGUSR1, 0, 0, 0, 0]).unwrap();
            let line = format!("{name}-usr1");
            if keep {
                for line in waited(c, &line, child, 2 | WNOWAIT) {
                    lines.send(line).unwrap();
                }
            } else {
                for line in stop_lines(&line, wait_in(c, child)) {
                    lines.send(line).unwrap();
                }
            }
            c.exit(0)
        });
        g.wait(tracer, 0);
        tracer_thread.join().unwrap();
        g.lines.extend(rx.try_iter());
        // SIGUSR2 once the child sleeps again, as the guest sends it: a
        // workaround for an emulator bug that Linux does not have, a signal
        // sent while a task comes out of a stop can be lost. Remove the wait
        // here and in the guest once the emulator keeps such a signal.
        g.until_sleeping(child);
        g.call(KILL, [child, SIGUSR2, 0, 0, 0, 0]);
        let status = g.wait(child, 0);
        thread.join().unwrap();
        g.say(&format!("{name}-got-usr1"), Tracer::code(status));
    }
    // A zombie its tracer did not reap.
    let (go_read, go_write) = g.pipe();
    let (told_read, told_write) = g.pipe();
    let (child, thread) = g.fork(move |c| {
        c.sys(PRCTL, [0x5961_6d61, u64::MAX, 0, 0, 0, 0]).unwrap();
        c.sys(WRITE, [ready_write, HEAP + 0x790, 1, 0, 0, 0])
            .unwrap();
        if let Err(status) = c.sys(READ, [go_read, HEAP + 0x798, 1, 0, 0, 0]) {
            return status;
        }
        c.exit(7)
    });
    assert_eq!(g.call(READ, [ready_read, HEAP + 0x798, 1, 0, 0, 0]), 1);
    let (lines, rx) = std::sync::mpsc::channel::<String>();
    let (tracer, tracer_thread) = g.fork(move |c| {
        c.sys(PTRACE, [ATTACH, child, 0, 0, 0, 0]).unwrap();
        wait_in(c, child);
        c.sys(PTRACE, [CONT, child, 0, 0, 0, 0]).unwrap();
        c.sys(WRITE, [go_write, HEAP + 0xe40, 1, 0, 0, 0]).unwrap();
        // WEXITED, WNOWAIT.
        for line in waited(c, "zombie", child, 4 | WNOWAIT) {
            lines.send(line).unwrap();
        }
        c.sys(WRITE, [told_write, HEAP + 0xe40, 1, 0, 0, 0])
            .unwrap();
        c.sys(READ, [go_read, HEAP + 0xe48, 1, 0, 0, 0]).unwrap();
        c.exit(0)
    });
    assert_eq!(g.call(READ, [told_read, HEAP + 0x7a0, 1, 0, 0, 0]), 1);
    let hidden = g.wait(child, WNOHANG);
    g.call(WRITE, [go_write, HEAP + 0x7a0, 1, 0, 0, 0]);
    g.wait(tracer, 0);
    tracer_thread.join().unwrap();
    g.lines.extend(rx.try_iter());
    g.say("zombie-hidden", hidden);
    let status = g.wait(child, 0);
    thread.join().unwrap();
    g.say("zombie-exit", Tracer::code(status));
    // A tracee detached in a group stop.
    let (child, thread) = g.fork(traceable);
    assert_eq!(g.call(READ, [ready_read, HEAP + 0x798, 1, 0, 0, 0]), 1);
    let (lines, rx) = std::sync::mpsc::channel::<String>();
    let (tracer, tracer_thread) = g.fork(move |c| {
        let r = c.sys(PTRACE, [SEIZE, child, 0, 0, 0, 0]).unwrap();
        lines.send(format!("seize={}", neg(r))).unwrap();
        c.sys(KILL, [child, SIGSTOP, 0, 0, 0, 0]).unwrap();
        for line in stop_lines("sigstop", wait_in(c, child)) {
            lines.send(line).unwrap();
        }
        c.sys(PTRACE, [CONT, child, 0, SIGSTOP, 0, 0]).unwrap();
        for line in stop_lines("group", wait_in(c, child)) {
            lines.send(line).unwrap();
        }
        let r = c.sys(PTRACE, [DETACH, child, 0, 0, 0, 0]).unwrap();
        lines.send(format!("detach={}", neg(r))).unwrap();
        c.exit(0)
    });
    g.wait(tracer, 0);
    tracer_thread.join().unwrap();
    g.lines.extend(rx.try_iter());
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    let mut state = g.status_of(child);
    while state != (0, b'T') && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(1));
        state = g.status_of(child);
    }
    g.say("detached-stopped", i64::from(state.1 == b'T'));
    let status = g.wait(child, WNOHANG | WUNTRACED);
    g.stop("parent", status);
    g.call(KILL, [child, SIGCONT, 0, 0, 0, 0]);
    let continued = g.wait(child, WCONTINUED) == 0xffff;
    g.say("continued", i64::from(continued));
    // SIGKILL, as the guest sends it until the emulator keeps a SIGUSR2
    // sent right after SIGCONT, as the task comes out of its stop.
    g.call(KILL, [child, SIGKILL, 0, 0, 0, 0]);
    let status = g.wait(child, 0);
    thread.join().unwrap();
    g.say("group-killed", status & 0x7f);
    g.check(
        "usr1-stopped=1
usr1-signal=10
usr1-event=0
detach-usr2=0
detached-tracer=0
detach-exit=1
waited-usr1-stopped=1
waited-usr1-signal=10
waited-usr1-event=0
waited-got-usr1=0
unwaited-usr1-code=4
unwaited-usr1-status=10
unwaited-got-usr1=1
zombie-code=1
zombie-status=7
zombie-hidden=0
zombie-exit=7
seize=0
sigstop-stopped=1
sigstop-signal=19
sigstop-event=0
group-stopped=1
group-signal=19
group-event=128
detach=0
detached-stopped=1
parent-stopped=1
parent-signal=19
parent-event=0
continued=1
group-killed=9",
    );
}

/// `ptrace-thread-exec`: a thread other than the leader execs. Its tracer
/// sees the exec event from the leader's ID, the thread's own ID as the
/// event's message, and nothing left of the thread's old ID. The program it
/// execs ends with the code `exec-child` gives.
#[test]
fn thread_exec() {
    let mut g = Tracer::new();
    let (child, thread) = g.fork(|c| {
        assert_eq!(c.sys(PTRACE, [TRACEME, 0, 0, 0, 0, 0]), Ok(0));
        c.raise(SIGSTOP, &mut |_, _, _| None).unwrap();
        let ctid = HEAP + 0xf00;
        c.thread(ctid, |t| {
            if let Err(status) = t.exec() {
                return status;
            }
            t.exit(7)
        });
        loop {
            if let Err(status) = c.sys(PAUSE, [0; 6]) {
                return status;
            }
        }
    });
    let mut s = Strace {
        named: [child, 0, 0, 0],
        first_entry: false,
    };
    s.expect(&mut g, child, "start");
    // PTRACE_O_TRACECLONE and PTRACE_O_TRACEEXEC.
    let r = g.pt(SETOPTIONS, child, 0, 8 | 0x10);
    g.say("options", r);
    g.pt(CONT, child, 0, 0);
    let status = g.wait(child, WALL);
    let at = HEAP + 0x500;
    g.pt(GETEVENTMSG, child, 0, at);
    s.named[1] = g.m.read_u64(GuestAddr(at)).unwrap();
    g.lines.push(format!("clone event={}", status >> 16));
    s.expect(&mut g, s.named[1], "thread");
    g.pt(CONT, s.named[1], 0, 0);
    g.pt(CONT, child, 0, 0);
    s.expect(&mut g, child, "exec");
    let old = g.wait(s.named[1], WNOHANG | WALL);
    g.say("old-thread", old);
    g.pt(CONT, child, 0, 0);
    s.expect(&mut g, child, "exit");
    thread.join().unwrap();
    g.check(
        "start: parent signal=19 event=0 nr=200 rax=0 message=0
options=0
clone event=3
thread: child signal=19 event=0 nr=56 rax=0 message=0
exec: parent signal=5 event=4 nr=59 rax=-38 message=child
old-thread=-10
exit: parent exited=1 code=7",
    );
}

/// `ptrace-forced-edges`: a fork stepped over leaves the child without the
/// trap flag the tracer forced; the flags a tracer writes keep it while
/// they have none, but a trap flag written in them is the tracee's own,
/// until the tracer writes the flags without it. The traps of the
/// instructions between the calls, and the one the tracee's own flag gives
/// under PTRACE_CONT, which only the CPU gives, are left out; each step
/// here is over a call, which ends at `CODE`.
#[test]
fn forced_edges() {
    let mut g = Tracer::new();
    let (child, thread) = g.fork(|c| {
        assert_eq!(c.sys(PTRACE, [TRACEME, 0, 0, 0, 0, 0]), Ok(0));
        let pid = c.sys(GETPID, [0; 6]).unwrap();
        c.sys(KILL, [pid, SIGSTOP, 0, 0, 0, 0]).unwrap();
        // The fork's child exits with whether it has the trap flag.
        let made = c.fork(|c| {
            let tf = c.t.cpu.rflags & TF != 0;
            c.exit(i32::from(tf))
        });
        let at = HEAP + 0x990;
        c.sys(WAIT4, [made, at, 0, 0, 0, 0]).unwrap();
        let code = i64::from(read32(&c.m, at) >> 8 & 0xff);
        c.sys(KILL, [pid, SIGSTOP, 0, 0, 0, 0]).unwrap();
        c.sys(GETPID, [0; 6]).unwrap();
        c.sys(GETPID, [0; 6]).unwrap();
        let tf = c.t.cpu.rflags & TF != 0;
        c.exit((code * 2) as i32 + i32::from(tf))
    });
    let step = |g: &mut Tracer, name: &str| {
        g.pt(SINGLESTEP, child, 0, 0);
        let status = g.wait(child, 0);
        let (_, _, code, _) = g.siginfo(child);
        let (_, regs) = g.regs(child);
        let line = format!(
            "{name}: signal={} code={} at={} tf-shown={}",
            (status >> 8) & 0xff,
            hex(code as u64),
            at(g.reg(regs, RIP), 0),
            i64::from(g.reg(regs, EFLAGS) & TF != 0)
        );
        g.lines.push(line);
        regs
    };
    let flags = |g: &mut Tracer| {
        let at = HEAP + 0x510;
        g.pt(PEEKUSER, child, EFLAGS, at);
        g.m.read_u64(GuestAddr(at)).unwrap()
    };
    g.wait(child, 0);
    let regs = step(&mut g, "fork-step");
    let made = g.reg(regs, RAX) as i64 > 0;
    g.say("fork-made", i64::from(made));
    // The SIGCHLD of the fork's exit stops a traced task too.
    let mut status;
    loop {
        g.pt(CONT, child, 0, 0);
        status = g.wait(child, 0);
        if status & 0xff != 0x7f || (status >> 8) & 0xff != SIGCHLD as i64 {
            break;
        }
    }
    g.say("next-stop", (status >> 8) & 0xff);
    step(&mut g, "step");
    let forced = flags(&mut g);
    g.say("peek-forced: tf", i64::from(forced & TF != 0));
    let r = g.pt(POKEUSER, child, EFLAGS, forced & !TF);
    g.say("poke-no-tf", r);
    let kept = flags(&mut g) & TF != 0;
    g.say("peek-kept: tf", i64::from(kept));
    step(&mut g, "still-stepped");
    let own = flags(&mut g) | TF;
    let r = g.pt(POKEUSER, child, EFLAGS, own);
    g.say("poke-tf", r);
    let own = flags(&mut g) & TF != 0;
    g.say("peek-own: tf", i64::from(own));
    let cleared = flags(&mut g) & !TF;
    g.pt(POKEUSER, child, EFLAGS, cleared);
    let cleared = flags(&mut g) & TF != 0;
    g.say("peek-cleared: tf", i64::from(cleared));
    g.pt(CONT, child, 0, 0);
    let status = g.wait(child, 0);
    g.say("exit", Tracer::code(status));
    thread.join().unwrap();
    g.check(
        "fork-step: signal=5 code=0x1 at=0 tf-shown=0
fork-made=1
next-stop=19
step: signal=5 code=0x1 at=0 tf-shown=0
peek-forced: tf=0
poke-no-tf=0
peek-kept: tf=0
still-stepped: signal=5 code=0x1 at=0 tf-shown=0
poke-tf=0
peek-own: tf=1
peek-cleared: tf=0
exit=0",
    );
}

/// `ptrace-held`: the tasks a tracee's clone holds for its tracer, and those
/// it does not. CLONE_PTRACE traces the child with no event asked for,
/// which starts with SIGSTOP from no one; CLONE_UNTRACED makes no event and
/// an untraced child; a clone that fails makes no event either. A held
/// child refuses PTRACE_INTERRUPT, as it was not seized, and is let go with
/// PTRACE_DETACH. A zombie may not be attached to.
#[test]
fn held() {
    const WAITID: u64 = 247;
    const CLONE_PTRACE: u64 = 0x2000;
    const CLONE_UNTRACED: u64 = 0x80_0000;
    const CLONE_THREAD: u64 = 0x1_0000;
    let mut g = Tracer::new();
    let (zombie, zombie_thread) = g.fork(|c| c.exit(0));
    let info = HEAP + 0x600;
    // P_PID, WEXITED | WNOWAIT.
    g.call(WAITID, [1, zombie, info, 4 | 0x100_0000, 0, 0]);
    let r = g.pt(ATTACH, zombie, 0, 0);
    g.say("attach-zombie", r);
    let r = g.pt(SEIZE, zombie, 0, 0);
    g.say("seize-zombie", r);
    g.wait(zombie, 0);
    zombie_thread.join().unwrap();
    let (child, thread) = g.fork(|c| {
        let chld = HEAP + 0x980;
        c.m.write_u64(GuestAddr(chld), 1 << (SIGCHLD - 1)).unwrap();
        c.sys(RT_SIGPROCMASK, [0, chld, 0, 8, 0, 0]).unwrap();
        assert_eq!(c.sys(PTRACE, [TRACEME, 0, 0, 0, 0, 0]), Ok(0));
        c.raise(SIGSTOP, &mut |_, _, _| None).unwrap();
        let at = HEAP + 0x990;
        let reaped = |c: &mut Tracee, pid: u64| {
            c.sys(WAIT4, [pid, at, 0, 0, 0, 0]).unwrap();
            read32(&c.m, at) >> 8 & 0xff
        };
        let mut code = 0;
        // A clone of its own flags, its child running `body`.
        let clone = |c: &mut Tracee, flags: u64, status: i32| {
            c.forked = Some(Box::new(move |c: &mut Tracee| c.exit(status)));
            let made = c.sys(CLONE, [flags | SIGCHLD, 0, 0, 0, 0, 0]);
            c.forked = None;
            made
        };
        let made = clone(c, CLONE_PTRACE, 3).unwrap();
        if reaped(c, made) == 3 {
            code |= 1;
        }
        c.raise(SIGSTOP, &mut |_, _, _| None).unwrap();
        let made = clone(c, CLONE_UNTRACED, 4).unwrap();
        if reaped(c, made) == 4 {
            code |= 2;
        }
        if neg(clone(c, CLONE_THREAD, 0).unwrap()) == -22 {
            code |= 4;
        }
        let made = c.fork(|c| c.exit(5));
        if reaped(c, made) == 5 {
            code |= 8;
        }
        c.exit(code)
    });
    let mut s = Strace {
        named: [child, 0, 0, 0],
        first_entry: false,
    };
    s.expect(&mut g, child, "start");
    g.pt(CONT, child, 0, 0);
    // The child CLONE_PTRACE made, which its parent waits for: no event.
    let status_at = HEAP + 0x100;
    let held = g.call(WAIT4, [u64::MAX, status_at, WALL, 0, 0, 0]);
    let status = i64::from(read32(&g.m, status_at));
    s.named[1] = held;
    g.lines.push(format!(
        "ptraced: {} signal={} event={}",
        s.who(held),
        (status >> 8) & 0xff,
        status >> 16
    ));
    let (_, _, code, pid) = g.siginfo(held);
    g.lines.push(format!("ptraced si-code={code} si-pid={pid}"));
    g.pt(CONT, held, 0, 0);
    s.expect(&mut g, held, "ptraced-gone");
    s.expect(&mut g, child, "options-stop");
    // PTRACE_O_TRACEFORK and PTRACE_O_TRACECLONE.
    let r = g.pt(SETOPTIONS, child, 0, O_TRACEFORK | 8);
    g.say("options", r);
    g.pt(CONT, child, 0, 0);
    // The untraced child and the clone that fails make no stop: the next is
    // the fork's.
    let status = g.wait(child, WALL);
    let at = HEAP + 0x500;
    g.pt(GETEVENTMSG, child, 0, at);
    s.named[2] = g.m.read_u64(GuestAddr(at)).unwrap();
    g.lines.push(format!(
        "fork signal={} event={}",
        (status >> 8) & 0xff,
        status >> 16
    ));
    let forked = s.named[2];
    s.expect(&mut g, forked, "forked");
    let r = g.pt(INTERRUPT, forked, 0, 0);
    g.say("interrupt-held", r);
    let r = g.pt(DETACH, forked, 0, 0);
    g.say("detach-held", r);
    let r = g.pt(CONT, forked, 0, 0);
    g.say("detached", r);
    g.pt(CONT, child, 0, 0);
    s.expect(&mut g, child, "exit");
    thread.join().unwrap();
    g.check(
        "attach-zombie=-1
seize-zombie=-1
start: parent signal=19 event=0 nr=200 rax=0 message=0
ptraced: child signal=19 event=0
ptraced si-code=0 si-pid=0
ptraced-gone: child exited=1 code=3
options-stop: parent signal=19 event=0 nr=200 rax=0 message=0
options=0
fork signal=5 event=1
forked: second signal=19 event=0 nr=57 rax=0 message=0
interrupt-held=-5
detach-held=0
detached=-3
exit: parent exited=1 code=15",
    );
}
