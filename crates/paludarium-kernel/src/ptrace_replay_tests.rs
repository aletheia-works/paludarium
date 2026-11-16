//! Cases of `tests/guests/processes/ptrace.c`, replayed through the kernel's
//! system calls: the tracer on the test's thread, the tracee on a thread of
//! its own, as a guest's tasks run, each system call followed by the
//! checkpoint the runtime takes before guest code runs again. The expected
//! lines are what the guest printed for its mode on native Linux 7.0
//! (x86-64, Ubuntu 26.04 runner); `diff_processes` still compares the whole
//! guests with Linux on every CI run. What only the CPU does (a signal
//! handler's body, the check a tracee makes after it resumes) is done here
//! in Rust from the state the kernel left; a line that needs an exec is left
//! out.
use super::*;

const READ: u64 = 0;
const OPEN: u64 = 2;
const CLOSE: u64 = 3;
const MMAP: u64 = 9;
const MPROTECT: u64 = 10;
const RT_SIGACTION: u64 = 13;
const RT_SIGPROCMASK: u64 = 14;
const RT_SIGRETURN: u64 = 15;
const PAUSE: u64 = 34;
const GETPID: u64 = 39;
const WAIT4: u64 = 61;
const KILL: u64 = 62;
const PTRACE: u64 = 101;
const GETPPID: u64 = 110;
const ARCH_PRCTL: u64 = 158;
const GETTID: u64 = 186;
const TKILL: u64 = 200;
const EXIT_GROUP: u64 = 231;
const TGKILL: u64 = 234;

const TRACEME: u64 = 0;
const PEEKDATA: u64 = 2;
const PEEKUSER: u64 = 3;
const POKEDATA: u64 = 5;
const POKEUSER: u64 = 6;
const CONT: u64 = 7;
const KILL_REQUEST: u64 = 8;
const GETREGS: u64 = 12;
const GETFPREGS: u64 = 14;
const SETFPREGS: u64 = 15;
const ATTACH: u64 = 16;
const DETACH: u64 = 17;
const SETOPTIONS: u64 = 0x4200;
const GETSIGINFO: u64 = 0x4202;
const SETSIGINFO: u64 = 0x4203;
const GETREGSET: u64 = 0x4204;
const SETREGSET: u64 = 0x4205;
const SEIZE: u64 = 0x4206;
const INTERRUPT: u64 = 0x4207;
const O_EXITKILL: u64 = 1 << 20;
const NT_PRSTATUS: u64 = 1;
const NT_PRFPREG: u64 = 2;

const SIGUSR1: u64 = 10;
const SIGUSR2: u64 = 12;
const SIGTERM: u64 = 15;
const SIGSTOP: u64 = 19;
const WNOHANG: u64 = 1;
const WALL: u64 = 0x4000_0000;
const SA_SIGINFO: u64 = 4;
const SA_RESTORER: u64 = 0x0400_0000;

/// `struct user_regs_struct`'s fields, by their offsets.
const R14: u64 = 8;
const R13: u64 = 16;
const R12: u64 = 24;
const RAX: u64 = 80;
const ORIG_RAX: u64 = 120;
const CS: u64 = 136;
const EFLAGS: u64 = 144;
const SS: u64 = 160;
const FS_BASE: u64 = 168;
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
}

/// A tracee on a thread of its own, as the runtime runs a guest task.
struct Tracee {
    k: Box<Kernel>,
    t: Thread,
    m: Arc<AddressSpace>,
}

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
                    Next::Resume => break,
                }
            }
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
    /// musl's `raise`: every signal blocked around a `tgkill` to itself, so
    /// that it arrives as the mask comes back, at the end of
    /// `rt_sigprocmask`.
    fn raise(&mut self, signal: u64, handler: &mut Handler<'_>) -> Result<u64, ExitStatus> {
        let (all, old) = (HEAP + 0x900, HEAP + 0x908);
        self.m.write_u64(GuestAddr(all), u64::MAX).unwrap();
        self.call(RT_SIGPROCMASK, [0, all, old, 8, 0, 0], handler)?;
        let pid = self.sys(GETPID, [0; 6])?;
        let tid = self.sys(GETTID, [0; 6])?;
        self.call(TGKILL, [pid, tid, signal, 0, 0, 0], handler)?;
        self.call(RT_SIGPROCMASK, [2, old, 0, 8, 0, 0], handler)
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
    }
}

impl Tracer {
    fn new() -> Self {
        let (k, t, m) = setup();
        m.map_shared(
            Some(GuestAddr(HEAP)),
            HEAP_PAGES * PAGE_SIZE,
            Prot::READ_WRITE,
            MappingKind::Anonymous,
        )
        .unwrap();
        m.write_u64(GuestAddr(WORD), 0x1122_3344_5566_7788).unwrap();
        Self {
            k,
            t,
            m,
            lines: Vec::new(),
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
            let mut tracee = Tracee { k, t, m };
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
    /// Waits until `pid` sleeps, as the guest does before it attaches.
    fn until_sleeping(&mut self, pid: u64) {
        let deadline = std::time::Instant::now() + PATIENCE;
        while self.status_of(pid).1 != b'S' {
            assert!(std::time::Instant::now() < deadline, "{pid} did not sleep");
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }
    fn check(&self, native: &str) {
        let native: Vec<_> = native.trim().lines().collect();
        let lines: Vec<_> = self.lines.iter().map(String::as_str).collect();
        assert_eq!(lines, native);
    }
}

/// `ptrace-traceme`, up to the exec: the stop for a signal the child sends
/// itself, its siginfo, a peek and a poke, the registers, and a cancelled
/// signal. The exec's stop is left out; the child ends with the code the
/// program it would exec gives.
#[test]
fn traceme() {
    let mut g = Tracer::new();
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
    let (child, thread) = g.fork(|c| {
        c.catch(SIGUSR1, 0);
        loop {
            if let Err(status) = c.call(PAUSE, [0; 6], &mut |_, _, _| None) {
                return status;
            }
        }
    });
    g.until_sleeping(child);
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
