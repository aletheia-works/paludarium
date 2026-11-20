/* ptrace cases, compared with native Linux on x86-64: attaching, the stops
 * a tracer sees through wait, and what it reads and changes of a stopped
 * tracee. Every line is a name and a value; no address or PID is printed,
 * only whether it is the one expected. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef PTRACE_SEIZE
#define PTRACE_SEIZE 0x4206
#endif
#ifndef PTRACE_INTERRUPT
#define PTRACE_INTERRUPT 0x4207
#endif
#ifndef PTRACE_EVENT_STOP
#define PTRACE_EVENT_STOP 128
#endif
#ifndef PTRACE_O_EXITKILL
#define PTRACE_O_EXITKILL (1 << 20)
#endif
#define NT_PRSTATUS 1
#define NT_PRFPREG 2

static void result(const char *name, long value) {
    printf("%s=%ld\n", name, value);
}

/* The raw call, so that errno is what the kernel gave and a peek's word
 * lands where it is asked to. */
static long pt(long request, pid_t pid, unsigned long addr, unsigned long data) {
    errno = 0;
    long r = syscall(SYS_ptrace, request, pid, addr, data);
    return r < 0 ? -errno : r;
}

static int wait_status(pid_t pid, int flags) {
    int status = 0;
    pid_t r;
    do {
        r = waitpid(pid, &status, flags);
    } while (r < 0 && errno == EINTR);
    if (r != pid) return r == 0 ? 0 : -errno;
    return status;
}

/* A stop, as the case prints it: the signal, and the event above it. */
static void stop(const char *name, int status) {
    char line[64];
    snprintf(line, sizeof line, "%s-stopped", name);
    result(line, WIFSTOPPED(status));
    snprintf(line, sizeof line, "%s-signal", name);
    result(line, WIFSTOPPED(status) ? WSTOPSIG(status) : -1);
    snprintf(line, sizeof line, "%s-event", name);
    result(line, status >> 16);
}

static siginfo_t siginfo_of(pid_t pid, long *error) {
    siginfo_t info;
    memset(&info, 0, sizeof info);
    *error = pt(PTRACE_GETSIGINFO, pid, 0, (unsigned long)&info);
    return info;
}

static long tracer_pid_of(pid_t pid, char *state) {
    char path[64], line[256];
    snprintf(path, sizeof path, "/proc/%d/status", pid);
    FILE *f = fopen(path, "r");
    long tracer = -1;
    if (!f) return -2;
    while (fgets(line, sizeof line, f)) {
        if (!strncmp(line, "TracerPid:", 10)) tracer = atol(line + 10);
        if (!strncmp(line, "State:", 6) && state) *state = line[7];
    }
    fclose(f);
    return tracer;
}

static volatile long shared_word = 0x1122334455667788L;
static volatile int handled;

static void on_signal(int number) { handled = handled * 100 + number; }

/* PTRACE_TRACEME, the signal-delivery-stop of a signal the child sends
 * itself, its siginfo, a peek and a poke of its memory, a cancelled
 * signal, and the SIGTRAP an exec sends a tracee attached this way. */
static int traceme(const char *self) {
    /* The child waits on `go` before it execs, so that it still runs, not
     * stopped at the exec, when the tracer peeks it after PTRACE_CONT. */
    int go[2];
    if (pipe(go)) return 80;
    pid_t child = fork();
    if (child == 0) {
        if (pt(PTRACE_TRACEME, 0, 0, 0) != 0) _exit(90);
        result("child-traceme-again", pt(PTRACE_TRACEME, 0, 0, 0));
        fflush(stdout);
        signal(SIGUSR1, on_signal);
        raise(SIGUSR1);
        /* The tracer cancelled it and changed the word. */
        if (handled != 0) _exit(91);
        if (shared_word != 0x0102030405060708L) _exit(92);
        char byte;
        if (read(go[0], &byte, 1) != 1) _exit(94);
        execl(self, self, "exec-child", self, (char *)0);
        _exit(93);
    }
    int status = wait_status(child, 0);
    stop("raise", status);
    char state = 0;
    result("tracer-pid", tracer_pid_of(child, &state) == getpid());
    result("state-tracing", state == 't');
    result("own-tracer-pid", tracer_pid_of(getpid(), NULL));
    long error;
    siginfo_t info = siginfo_of(child, &error);
    result("siginfo", error);
    result("si-signo", info.si_signo);
    result("si-code", info.si_code);
    result("si-pid", info.si_pid == child);
    long word = 0;
    result("peek", pt(PTRACE_PEEKDATA, child, (unsigned long)&shared_word, (unsigned long)&word));
    result("peeked", word == 0x1122334455667788L);
    result("poke", pt(PTRACE_POKEDATA, child, (unsigned long)&shared_word, 0x0102030405060708L));
    result("peek-unmapped", pt(PTRACE_PEEKDATA, child, 8, (unsigned long)&word));
    result("poke-unmapped", pt(PTRACE_POKEDATA, child, 8, 0));
    struct user_regs_struct regs;
    result("getregs", pt(PTRACE_GETREGS, child, 0, (unsigned long)&regs));
    result("orig-rax", regs.orig_rax);
    result("rax", regs.rax);
    result("cs", regs.cs);
    result("ss", regs.ss);
    result("if", (regs.eflags >> 9) & 1);
    result("bad-signal", pt(PTRACE_CONT, child, 0, 65));
    result("bad-request", pt(0x4299, child, 0, 0));
    result("cont", pt(PTRACE_CONT, child, 0, 0));
    result("running-peek", pt(PTRACE_PEEKDATA, child, (unsigned long)&shared_word, (unsigned long)&word));
    write(go[1], "x", 1);
    status = wait_status(child, 0);
    stop("exec", status);
    info = siginfo_of(child, &error);
    result("exec-si-code", info.si_code);
    result("exec-si-pid", info.si_pid == child);
    result("cont-exec", pt(PTRACE_CONT, child, 0, 0));
    status = wait_status(child, 0);
    result("exited", WIFEXITED(status));
    result("exit-code", WEXITSTATUS(status));
    result("no-tracee", pt(PTRACE_CONT, child, 0, 0));
    return 0;
}

static int exec_child(void) {
    return 7;
}

/* The calls a child has gone into that its parent waits for it to block
 * in, which the child counts just before it makes each: a page that the
 * fork leaves shared. /proc's 'S' alone does not tell which call a task
 * sleeps in, and under an emulator that shows a task asleep in every call
 * it is in it can be the call before, such as the write of a ready byte or
 * the rt_sigreturn of a handler. */
static int *entered;

static int share_entered(void) {
    entered = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (entered == MAP_FAILED) return -1;
    *entered = 0;
    return 0;
}

static void enter(void) { __atomic_add_fetch(entered, 1, __ATOMIC_SEQ_CST); }

/* PTRACE_ATTACH of a child waiting in pause: the stop for the attach's
 * SIGSTOP, with the restart code of the interrupted call in rax, and the
 * refusals of a second attach, of an attach to oneself, and of requests
 * to a task that is not stopped or not traced. */
static int attach(void) {
    int ready[2];
    if (pipe(ready) || share_entered()) return 80;
    pid_t child = fork();
    if (child == 0) {
        signal(SIGUSR1, on_signal);
        write(ready[1], "x", 1);
        enter();
        for (;;) pause();
    }
    /* Attaches once the child sleeps in pause, so that the stop is the
     * same each run. */
    char byte, state = 0;
    read(ready[0], &byte, 1);
    while (__atomic_load_n(entered, __ATOMIC_SEQ_CST) < 1) usleep(1000);
    while (tracer_pid_of(child, &state) >= 0 && state != 'S') usleep(1000);
    result("untraced", pt(PTRACE_CONT, child, 0, 0));
    result("self", pt(PTRACE_ATTACH, getpid(), 0, 0));
    result("attach", pt(PTRACE_ATTACH, child, 0, 0));
    result("again", pt(PTRACE_ATTACH, child, 0, 0));
    int status = wait_status(child, __WALL);
    stop("attach", status);
    long error;
    siginfo_t info = siginfo_of(child, &error);
    result("si-signo", info.si_signo);
    result("si-code", info.si_code);
    struct user_regs_struct regs;
    pt(PTRACE_GETREGS, child, 0, (unsigned long)&regs);
    result("orig-rax", regs.orig_rax);
    result("rax", (long)regs.rax);
    /* No wait reports the stop twice. */
    result("reported", wait_status(child, WNOHANG | __WALL));
    /* A signal the tracer gives runs the handler, and pause returns. */
    result("cont-usr1", pt(PTRACE_CONT, child, 0, SIGUSR1));
    kill(child, SIGUSR2);
    status = wait_status(child, 0);
    stop("usr2", status);
    result("running", pt(PTRACE_GETREGS, child, 0, (unsigned long)&regs) == 0);
    result("detach-bad", pt(PTRACE_DETACH, child, 0, 99));
    result("detach", pt(PTRACE_DETACH, child, 0, 0));
    result("detached", pt(PTRACE_CONT, child, 0, 0));
    kill(child, SIGTERM);
    status = wait_status(child, 0);
    result("signaled", WIFSIGNALED(status));
    result("term", WTERMSIG(status));
    return 0;
}

/* PTRACE_SEIZE: no stop until PTRACE_INTERRUPT, whose stop is
 * PTRACE_EVENT_STOP with SIGTRAP; a SIGSTOP's delivery stop, then the
 * group stop it starts as PTRACE_EVENT_STOP with the stop signal; and
 * PTRACE_KILL. */
static int seize(void) {
    pid_t child = fork();
    if (child == 0) {
        for (;;) pause();
    }
    result("seize-addr", pt(PTRACE_SEIZE, child, 1, 0));
    result("seize-options", pt(PTRACE_SEIZE, child, 0, 1UL << 30));
    result("seize", pt(PTRACE_SEIZE, child, 0, PTRACE_O_EXITKILL));
    result("no-stop", wait_status(child, WNOHANG));
    result("not-stopped", pt(PTRACE_GETREGS, child, 0, 0));
    result("interrupt", pt(PTRACE_INTERRUPT, child, 0, 0));
    int status = wait_status(child, 0);
    stop("interrupt", status);
    long error;
    siginfo_t info = siginfo_of(child, &error);
    result("si-signo", info.si_signo);
    result("si-code", info.si_code);
    result("si-pid", info.si_pid == child);
    result("bad-options", pt(PTRACE_SETOPTIONS, child, 0, 1UL << 30));
    result("cont", pt(PTRACE_CONT, child, 0, 0));
    kill(child, SIGSTOP);
    status = wait_status(child, 0);
    stop("sigstop", status);
    result("cont-stop", pt(PTRACE_CONT, child, 0, SIGSTOP));
    status = wait_status(child, 0);
    stop("group", status);
    info = siginfo_of(child, &error);
    result("group-si-signo", info.si_signo);
    result("group-si-code", info.si_code);
    char state = 0;
    tracer_pid_of(child, &state);
    result("group-state-tracing", state == 't');
    result("kill", pt(PTRACE_KILL, child, 0, 0));
    status = wait_status(child, 0);
    result("signaled", WIFSIGNALED(status));
    result("killed-by", WTERMSIG(status));
    return 0;
}

/* The group stop of a child attached without PTRACE_SEIZE reports the
 * stop signal alone, with no siginfo; SETSIGINFO changes a stopped
 * signal's siginfo, and a signal the tracer gives in place of another is
 * the tracer's. */
static void report_info(int number, siginfo_t *info, void *context) {
    (void)context;
    handled = handled * 100 + number;
    if (number == SIGUSR1) _exit(info->si_code == -60 && info->si_value.sival_int == 42 ? 10 : 11);
    _exit(info->si_code == SI_USER && info->si_pid == getppid() ? 20 : 21);
}

static int signals_case(void) {
    for (int round = 0; round < 2; round++) {
        pid_t child = fork();
        if (child == 0) {
            struct sigaction action = { .sa_sigaction = report_info, .sa_flags = SA_SIGINFO };
            sigaction(SIGUSR1, &action, NULL);
            sigaction(SIGUSR2, &action, NULL);
            if (pt(PTRACE_TRACEME, 0, 0, 0) != 0) _exit(90);
            raise(SIGSTOP);
            raise(SIGUSR1);
            _exit(30);
        }
        int status = wait_status(child, 0);
        stop(round ? "b-sigstop" : "a-sigstop", status);
        pt(PTRACE_CONT, child, 0, SIGSTOP);
        status = wait_status(child, 0);
        stop(round ? "b-group" : "a-group", status);
        long error;
        siginfo_of(child, &error);
        result(round ? "b-group-siginfo" : "a-group-siginfo", error);
        result("group-setsiginfo", pt(PTRACE_SETSIGINFO, child, 0, (unsigned long)&(siginfo_t){0}));
        pt(PTRACE_CONT, child, 0, 0);
        status = wait_status(child, 0);
        stop(round ? "b-usr1" : "a-usr1", status);
        if (round == 0) {
            siginfo_t info = siginfo_of(child, &error);
            info.si_code = -60;
            info.si_value.sival_int = 42;
            result("setsiginfo", pt(PTRACE_SETSIGINFO, child, 0, (unsigned long)&info));
            pt(PTRACE_CONT, child, 0, SIGUSR1);
        } else {
            pt(PTRACE_CONT, child, 0, SIGUSR2);
        }
        status = wait_status(child, 0);
        result(round ? "b-exit" : "a-exit", WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    }
    return 0;
}

/* The registers of a tracee stopped at the end of its own tkill: what
 * GETREGS, PEEKUSER and the register sets show, and what the tracer
 * changes there, which the tracee then runs with. */
static int regs_child(void) {
    if (pt(PTRACE_TRACEME, 0, 0, 0) != 0) return 90;
    static const uint64_t pattern[2] = { 0x0123456789abcdefULL, 0x5555aaaa5555aaaaULL };
    uint64_t after[2];
    register long r12 asm("r12") = 0x1111;
    register long r13 asm("r13") = 0x3333;
    long ret;
    pid_t tid = syscall(SYS_gettid);
    __asm__ volatile(
        "movdqu (%[in]), %%xmm0\n\t"
        "syscall\n\t"
        "movdqu %%xmm0, (%[out])"
        : "=a"(ret), "+r"(r12), "+r"(r13)
        : "a"((long)SYS_tkill), "D"((long)tid), "S"((long)SIGSTOP),
          [in] "r"(pattern), [out] "r"(after)
        : "rcx", "r11", "xmm0", "memory");
    int code = 0;
    if (r12 == 0x2222) code |= 1;
    if (r13 == 0x4444) code |= 2;
    if (after[0] == 0x0f0e0d0c0b0a0908ULL) code |= 4;
    if (ret == 0) code |= 8;
    return code;
}

static int regs_case(void) {
    pid_t child = fork();
    if (child == 0) _exit(regs_child());
    int status = wait_status(child, 0);
    stop("stop", status);
    struct user_regs_struct regs;
    result("getregs", pt(PTRACE_GETREGS, child, 0, (unsigned long)&regs));
    result("r12", regs.r12);
    result("r13", regs.r13);
    result("orig-rax", regs.orig_rax);
    result("rax", regs.rax);
    result("cs", regs.cs);
    result("ss", regs.ss);
    result("ds", regs.ds);
    result("fs-base", regs.fs_base != 0);
    long word = 0;
    result("peekuser", pt(PTRACE_PEEKUSER, child, offsetof(struct user_regs_struct, r12), (unsigned long)&word));
    result("peeked-r12", word);
    pt(PTRACE_PEEKUSER, child, offsetof(struct user, u_debugreg) + 6 * 8, (unsigned long)&word);
    result("dr6", word);
    pt(PTRACE_PEEKUSER, child, offsetof(struct user, u_debugreg) + 7 * 8, (unsigned long)&word);
    result("dr7", word);
    word = -1;
    pt(PTRACE_PEEKUSER, child, offsetof(struct user, u_tsize), (unsigned long)&word);
    result("tsize", word);
    result("peek-unaligned", pt(PTRACE_PEEKUSER, child, 3, (unsigned long)&word));
    result("peek-past", pt(PTRACE_PEEKUSER, child, sizeof(struct user), (unsigned long)&word));
    result("poke-r12", pt(PTRACE_POKEUSER, child, offsetof(struct user_regs_struct, r12), 0x2222));
    result("poke-cs-null", pt(PTRACE_POKEUSER, child, offsetof(struct user_regs_struct, cs), 0));
    result("poke-ds-kernel", pt(PTRACE_POKEUSER, child, offsetof(struct user_regs_struct, ds), 0x10));
    result("poke-fs-base", pt(PTRACE_POKEUSER, child, offsetof(struct user_regs_struct, fs_base), 0xffff800000000000UL));
    result("poke-tsize", pt(PTRACE_POKEUSER, child, offsetof(struct user, u_tsize), 0));
    result("poke-dr7", pt(PTRACE_POKEUSER, child, offsetof(struct user, u_debugreg) + 7 * 8, 0));
    /* IF cannot be cleared; TF and the status flags can be set. */
    unsigned long flags = regs.eflags;
    pt(PTRACE_POKEUSER, child, offsetof(struct user_regs_struct, eflags), (flags & ~0x200UL) | 0x1);
    pt(PTRACE_PEEKUSER, child, offsetof(struct user_regs_struct, eflags), (unsigned long)&word);
    result("eflags-if", (word >> 9) & 1);
    result("eflags-cf", word & 1);
    pt(PTRACE_POKEUSER, child, offsetof(struct user_regs_struct, eflags), flags);
    struct iovec iov;
    struct user_regs_struct set_regs;
    iov.iov_base = &set_regs;
    iov.iov_len = sizeof set_regs + 64;
    result("getregset", pt(PTRACE_GETREGSET, child, NT_PRSTATUS, (unsigned long)&iov));
    result("getregset-len", iov.iov_len);
    result("getregset-r12", set_regs.r12);
    set_regs.r13 = 0x4444;
    result("setregset", pt(PTRACE_SETREGSET, child, NT_PRSTATUS, (unsigned long)&iov));
    iov.iov_len = 7;
    result("regset-odd", pt(PTRACE_GETREGSET, child, NT_PRSTATUS, (unsigned long)&iov));
    iov.iov_len = 8;
    result("regset-unknown", pt(PTRACE_GETREGSET, child, 0x999, (unsigned long)&iov));
    iov.iov_len = 16;
    memset(&set_regs, 0, sizeof set_regs);
    result("regset-part", pt(PTRACE_GETREGSET, child, NT_PRSTATUS, (unsigned long)&iov));
    result("regset-part-len", iov.iov_len);
    result("regset-part-r14", set_regs.r14 == regs.r14);
    result("regset-part-r13", set_regs.r13);
    struct user_fpregs_struct fp;
    result("getfpregs", pt(PTRACE_GETFPREGS, child, 0, (unsigned long)&fp));
    result("cwd", fp.cwd);
    result("mxcsr", fp.mxcsr);
    result("xmm0-low", fp.xmm_space[0] == 0x89abcdef && fp.xmm_space[1] == 0x01234567);
    result("xmm0-high", fp.xmm_space[2] == 0x5555aaaa);
    fp.xmm_space[0] = 0x0b0a0908;
    fp.xmm_space[1] = 0x0f0e0d0c;
    result("setfpregs", pt(PTRACE_SETFPREGS, child, 0, (unsigned long)&fp));
    fp.mxcsr = 0xffffffff;
    result("setfpregs-mxcsr", pt(PTRACE_SETFPREGS, child, 0, (unsigned long)&fp));
    struct user_fpregs_struct fp2;
    iov.iov_base = &fp2;
    iov.iov_len = sizeof fp2;
    result("fpregset", pt(PTRACE_GETREGSET, child, NT_PRFPREG, (unsigned long)&iov));
    result("fpregset-len", iov.iov_len);
    result("fpregset-xmm0", fp2.xmm_space[0] == 0x0b0a0908);
    iov.iov_len = 64;
    result("fpregset-set-part", pt(PTRACE_SETREGSET, child, NT_PRFPREG, (unsigned long)&iov));
    pt(PTRACE_CONT, child, 0, 0);
    status = wait_status(child, 0);
    result("exit", WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    return 0;
}

/* Memory as a tracer reaches it: a read-only private page is written, a
 * PROT_NONE one read, and a shared read-only one refused. */
static int memory_case(void) {
    char *ro = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    char *none = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    char *shared = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (ro == MAP_FAILED || none == MAP_FAILED || shared == MAP_FAILED) return 80;
    memset(ro, 1, 4096);
    memset(none, 2, 4096);
    memset(shared, 3, 4096);
    mprotect(ro, 4096, PROT_READ);
    mprotect(none, 4096, PROT_NONE);
    mprotect(shared, 4096, PROT_READ);
    pid_t child = fork();
    if (child == 0) {
        if (pt(PTRACE_TRACEME, 0, 0, 0) != 0) _exit(90);
        raise(SIGSTOP);
        _exit(ro[8] == 9 ? 0 : 1);
    }
    int status = wait_status(child, 0);
    stop("stop", status);
    long word = 0;
    result("peek-ro", pt(PTRACE_PEEKDATA, child, (unsigned long)ro, (unsigned long)&word));
    result("peeked-ro", word & 0xff);
    result("poke-ro", pt(PTRACE_POKEDATA, child, (unsigned long)ro + 8, 9));
    result("peek-none", pt(PTRACE_PEEKDATA, child, (unsigned long)none, (unsigned long)&word));
    result("peeked-none", word & 0xff);
    result("poke-none", pt(PTRACE_POKEDATA, child, (unsigned long)none, 4));
    result("peek-shared", pt(PTRACE_PEEKDATA, child, (unsigned long)shared, (unsigned long)&word));
    result("poke-shared", pt(PTRACE_POKEDATA, child, (unsigned long)shared, 5));
    result("parent-ro", ro[8]);
    pt(PTRACE_CONT, child, 0, 0);
    status = wait_status(child, 0);
    result("exit", WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    return 0;
}

/* A thread of another process attached by its ID: waits for it with and
 * without __WALL, and its exit, which its tracer reaps. */
static int thread_pipe[2];
static void *thread_main(void *arg) {
    (void)arg;
    pid_t tid = syscall(SYS_gettid);
    write(thread_pipe[1], &tid, sizeof tid);
    char byte;
    read(thread_pipe[0] == -1 ? 0 : thread_pipe[0], &byte, 1);
    return NULL;
}

static int thread_case(void) {
    int to_thread[2];
    if (pipe(thread_pipe) || pipe(to_thread)) return 80;
    pid_t child = fork();
    if (child == 0) {
        close(thread_pipe[0]);
        thread_pipe[0] = to_thread[0];
        pthread_t thread;
        pthread_create(&thread, NULL, thread_main, NULL);
        pthread_join(thread, NULL);
        /* Stays until the tracer has reaped the thread: once the group has
         * exited, wait reports the group's exit code for the thread. */
        char byte;
        read(to_thread[0], &byte, 1);
        _exit(5);
    }
    close(to_thread[0]);
    pid_t tid;
    if (read(thread_pipe[0], &tid, sizeof tid) != sizeof tid) return 81;
    result("attach", pt(PTRACE_ATTACH, tid, 0, 0));
    int status = wait_status(tid, 0);
    stop("thread", status);
    result("process-untraced", pt(PTRACE_CONT, child, 0, 0));
    result("cont", pt(PTRACE_CONT, tid, 0, 0));
    write(to_thread[1], "x", 1);
    status = wait_status(tid, __WALL);
    result("thread-exited", WIFEXITED(status));
    result("thread-code", WEXITSTATUS(status));
    write(to_thread[1], "x", 1);
    status = wait_status(child, 0);
    result("process-exit", WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    return 0;
}

/* A tracer that is not the parent: a sibling may attach once the child
 * lets it (Yama's PR_SET_PTRACER); the child's exit is the tracer's to
 * wait for first, then its parent's. */
static int sibling_case(void) {
    int ready[2];
    if (pipe(ready)) return 80;
    pid_t child = fork();
    if (child == 0) {
        prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0);
        write(ready[1], "x", 1);
        for (;;) pause();
    }
    char byte;
    read(ready[0], &byte, 1);
    pid_t tracer = fork();
    if (tracer == 0) {
        result("attach", pt(PTRACE_ATTACH, child, 0, 0));
        int status = wait_status(child, 0);
        stop("attach", status);
        kill(child, SIGKILL);
        status = wait_status(child, 0);
        result("tracer-signaled", WIFSIGNALED(status));
        result("tracer-term", WTERMSIG(status));
        fflush(stdout);
        _exit(0);
    }
    int status = wait_status(tracer, 0);
    result("tracer-exit", WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    status = wait_status(child, 0);
    result("parent-signaled", WIFSIGNALED(status));
    result("parent-term", WTERMSIG(status));
    return 0;
}

/* PTRACE_ATTACH and PTRACE_SEIZE of a child already in a group stop:
 * the call returns once the child has stopped for its new tracer, which
 * sees the group stop at once (PTRACE_EVENT_STOP for the seize, with no
 * siginfo for the attach); the attach's own SIGSTOP then has its delivery
 * stop. */
static int attach_stopped(void) {
    for (int seize = 0; seize < 2; seize++) {
        const char *name = seize ? "seize" : "attach";
        char line[64];
        fflush(stdout);
        pid_t child = fork();
        if (child == 0) {
            for (;;) pause();
        }
        kill(child, SIGSTOP);
        int status = wait_status(child, WUNTRACED);
        snprintf(line, sizeof line, "%s-group", name);
        stop(line, status);
        result(name, pt(seize ? PTRACE_SEIZE : PTRACE_ATTACH, child, 0, 0));
        status = wait_status(child, WNOHANG | __WALL);
        snprintf(line, sizeof line, "%s-trap", name);
        stop(line, status);
        long error;
        siginfo_t info = siginfo_of(child, &error);
        snprintf(line, sizeof line, "%s-siginfo", name);
        result(line, error);
        snprintf(line, sizeof line, "%s-si-signo", name);
        result(line, info.si_signo);
        if (!seize) {
            result("cont", pt(PTRACE_CONT, child, 0, 0));
            stop("sigstop", wait_status(child, __WALL));
        }
        kill(child, SIGKILL);
        status = wait_status(child, __WALL);
        snprintf(line, sizeof line, "%s-killed", name);
        result(line, WIFSIGNALED(status) ? WTERMSIG(status) : -1);
    }
    return 0;
}

/* A tracer that exits while it still traces: the tracee it seized with
 * PTRACE_O_EXITKILL gets SIGKILL, and the other is let go and runs on. */
static int tracer_exit_case(void) {
    int ready[2];
    if (pipe(ready)) return 80;
    pid_t kids[2];
    fflush(stdout);
    for (int i = 0; i < 2; i++) {
        kids[i] = fork();
        if (kids[i] == 0) {
            prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0);
            write(ready[1], "x", 1);
            for (;;) pause();
        }
    }
    char byte;
    read(ready[0], &byte, 1);
    read(ready[0], &byte, 1);
    pid_t tracer = fork();
    if (tracer == 0) {
        result("seize-kill", pt(PTRACE_SEIZE, kids[0], 0, PTRACE_O_EXITKILL));
        result("seize-keep", pt(PTRACE_SEIZE, kids[1], 0, 0));
        fflush(stdout);
        _exit(0);
    }
    int status = wait_status(tracer, 0);
    result("tracer-exit", WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    status = wait_status(kids[0], 0);
    result("killed", WIFSIGNALED(status) ? WTERMSIG(status) : -1);
    result("kept-running", wait_status(kids[1], WNOHANG));
    kill(kids[1], SIGTERM);
    status = wait_status(kids[1], 0);
    result("kept-term", WIFSIGNALED(status) ? WTERMSIG(status) : -1);
    return 0;
}

/* The waits of a tracer that is not the tracee's parent, whose second
 * thread traces it: with __WNOTHREAD the first thread traces nor has
 * anything to wait for, nor may it make requests; without it, it waits
 * for the stops by process group, as waitid's CLD_TRAPPED even when it
 * asks for exits only, and for the exit as any child. The parent sees the
 * group stop, not the ptrace stop before it, nor the exit before the
 * tracer has reaped it. */
static int wait_pipes[4][2];
enum { TO_THREAD, FROM_THREAD, TO_PARENT, FROM_PARENT };

static void *wait_thread(void *arg) {
    pid_t child = *(pid_t *)arg;
    result("attach", pt(PTRACE_ATTACH, child, 0, 0));
    char command;
    write(wait_pipes[FROM_THREAD][1], "a", 1);
    while (read(wait_pipes[TO_THREAD][0], &command, 1) == 1 && command != 'q') {
        result("thread-cont", pt(PTRACE_CONT, child, 0, command == 's' ? SIGSTOP : 0));
        write(wait_pipes[FROM_THREAD][1], "c", 1);
    }
    return NULL;
}

/* Tells the other side `what` and waits for its byte back. */
static void ask(int to, int from, char what) {
    char byte;
    write(wait_pipes[to][1], &what, 1);
    read(wait_pipes[from][0], &byte, 1);
}

/* A wait for `pid`, which may name a group or any child: 1 for `child`,
 * 0 for none, -errno, or 2 for another task. */
static long waited_for(pid_t pid, int flags, pid_t child, int *status) {
    pid_t r;
    do r = waitpid(pid, status, flags);
    while (r < 0 && errno == EINTR);
    return r < 0 ? -errno : r == 0 ? 0 : r == child ? 1 : 2;
}

static int wait_tracer(pid_t child, pid_t pgid) {
    setpgid(0, 0);
    pthread_t thread;
    char byte;
    pthread_create(&thread, NULL, wait_thread, &child);
    read(wait_pipes[FROM_THREAD][0], &byte, 1);
    int status = 0;
    result("nothread-pid", waited_for(child, WNOHANG | __WNOTHREAD, child, &status));
    result("nothread-any", waited_for(-1, WNOHANG | __WNOTHREAD, child, &status));
    result("own-group", waited_for(0, WNOHANG, child, &status));
    result("cont-not-tracer", pt(PTRACE_CONT, child, 0, 0));
    result("pgid", waited_for(-pgid, 0, child, &status));
    stop("pgid", status);
    ask(TO_PARENT, FROM_PARENT, 'p');
    ask(TO_THREAD, FROM_THREAD, 's');
    siginfo_t info;
    memset(&info, 0, sizeof info);
    int error;
    do error = waitid(P_PGID, pgid, &info, WEXITED);
    while (error < 0 && errno == EINTR);
    result("waitid", error);
    result("waitid-code", info.si_code);
    result("waitid-status", info.si_status);
    result("waitid-pid", info.si_pid == child);
    ask(TO_PARENT, FROM_PARENT, 'g');
    ask(TO_THREAD, FROM_THREAD, 'c');
    kill(child, SIGKILL);
    result("any", waited_for(-1, 0, child, &status));
    result("any-term", WIFSIGNALED(status) ? WTERMSIG(status) : -1);
    result("after-reap", waited_for(-1, WNOHANG, child, &status));
    write(wait_pipes[TO_THREAD][1], "q", 1);
    pthread_join(thread, NULL);
    fflush(stdout);
    _exit(0);
}

static int wait_case(void) {
    int ready[2];
    if (pipe(ready)) return 80;
    for (int i = 0; i < 4; i++)
        if (pipe(wait_pipes[i])) return 80;
    /* A group of the parent's own, which the child joins, whatever group
     * the test runs in. */
    if (setpgid(0, 0)) return 81;
    fflush(stdout);
    pid_t child = fork();
    if (child == 0) {
        prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0);
        write(ready[1], "x", 1);
        for (;;) pause();
    }
    char byte;
    read(ready[0], &byte, 1);
    pid_t pgid = getpgid(child);
    pid_t tracer = fork();
    if (tracer == 0) return wait_tracer(child, pgid);
    /* The parent's waits while the tracer holds the child, printed once the
     * tracer has printed its own lines. */
    long ptrace_stop, again;
    int group;
    read(wait_pipes[TO_PARENT][0], &byte, 1);
    ptrace_stop = wait_status(child, WNOHANG | WUNTRACED);
    write(wait_pipes[FROM_PARENT][1], "x", 1);
    read(wait_pipes[TO_PARENT][0], &byte, 1);
    group = wait_status(child, WNOHANG | WUNTRACED);
    again = wait_status(child, WNOHANG | WUNTRACED);
    write(wait_pipes[FROM_PARENT][1], "x", 1);
    int status = wait_status(tracer, 0);
    result("tracer-exit", WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    result("parent-ptrace-stop", ptrace_stop);
    stop("parent-group", group);
    result("parent-again", again);
    status = wait_status(child, 0);
    result("parent-term", WIFSIGNALED(status) ? WTERMSIG(status) : -1);
    return 0;
}

/* How a tracee goes free. PTRACE_DETACH from a signal-delivery-stop gives
 * the signal it names in place of the one stopped for. A tracer that exits
 * lets a tracee in a stop go on with the signal it stopped for if it did
 * not wait for the stop (a WNOWAIT wait leaves it unwaited), and without
 * one if it did; it hands an exit it did not reap to the parent, which
 * until then does not see it; and a tracee it detaches in a group stop
 * stays stopped, a stop its parent saw while it was traced. */
static volatile int got_usr1, got_usr2;

static void on_usr(int number) {
    if (number == SIGUSR1) got_usr1 = 1;
    if (number == SIGUSR2) got_usr2 = 1;
}

static int detach_signal(void) {
    pid_t child = fork();
    if (child == 0) {
        signal(SIGUSR1, on_usr);
        signal(SIGUSR2, on_usr);
        if (pt(PTRACE_TRACEME, 0, 0, 0) != 0) _exit(90);
        raise(SIGUSR1);
        _exit(got_usr1 * 10 + got_usr2);
    }
    stop("usr1", wait_status(child, 0));
    result("detach-usr2", pt(PTRACE_DETACH, child, 0, SIGUSR2));
    result("detached-tracer", tracer_pid_of(child, NULL));
    int status = wait_status(child, 0);
    result("detach-exit", WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    return 0;
}

/* A child that lets any task trace it, then waits in pause until SIGUSR2:
 * its exit code is whether SIGUSR1 came. */
static pid_t traceable(int ready) {
    fflush(stdout);
    pid_t child = fork();
    if (child == 0) {
        signal(SIGUSR1, on_usr);
        signal(SIGUSR2, on_usr);
        prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0);
        write(ready, "x", 1);
        while (!got_usr2) pause();
        _exit(got_usr1);
    }
    return child;
}

/* Waits by waitid for `child`, and prints what it found. */
static void waited(const char *name, pid_t child, int options) {
    siginfo_t info;
    memset(&info, 0, sizeof info);
    int r;
    do r = waitid(P_PID, child, &info, options);
    while (r < 0 && errno == EINTR);
    char line[64];
    snprintf(line, sizeof line, "%s-code", name);
    result(line, r < 0 ? -errno : info.si_code);
    snprintf(line, sizeof line, "%s-status", name);
    result(line, info.si_status);
}

static int detach_exit_stopped(int ready[2]) {
    char byte;
    for (int keep = 0; keep < 2; keep++) {
        const char *name = keep ? "unwaited" : "waited";
        char line[64];
        pid_t child = traceable(ready[1]);
        read(ready[0], &byte, 1);
        pid_t tracer = fork();
        if (tracer == 0) {
            pt(PTRACE_ATTACH, child, 0, 0);
            wait_status(child, 0);
            pt(PTRACE_CONT, child, 0, 0);
            kill(child, SIGUSR1);
            snprintf(line, sizeof line, "%s-usr1", name);
            if (keep) waited(line, child, WSTOPPED | WNOWAIT);
            else stop(line, wait_status(child, 0));
            fflush(stdout);
            _exit(0);
        }
        wait_status(tracer, 0);
        /* SIGUSR2 once the child sleeps again. A workaround for an emulator
         * bug that Linux does not have: a signal sent while a task comes out
         * of a stop, here the one its tracer's exit lets go, can be lost,
         * and the child sleeps in pause for good. Remove the wait once the
         * emulator keeps such a signal. */
        char state = 0;
        for (int i = 0; i < 2000 && (tracer_pid_of(child, &state) < 0 || state != 'S'); i++)
            usleep(1000);
        kill(child, SIGUSR2);
        int status = wait_status(child, 0);
        snprintf(line, sizeof line, "%s-got-usr1", name);
        result(line, WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    }
    return 0;
}

static int detach_exit_zombie(int ready[2]) {
    char byte;
    int go[2], told[2];
    if (pipe(go) || pipe(told)) return 80;
    fflush(stdout);
    pid_t child = fork();
    if (child == 0) {
        prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0);
        write(ready[1], "x", 1);
        read(go[0], &byte, 1);
        _exit(7);
    }
    read(ready[0], &byte, 1);
    pid_t tracer = fork();
    if (tracer == 0) {
        pt(PTRACE_ATTACH, child, 0, 0);
        wait_status(child, 0);
        pt(PTRACE_CONT, child, 0, 0);
        write(go[1], "x", 1);
        waited("zombie", child, WEXITED | WNOWAIT);
        write(told[1], "x", 1);
        read(go[0], &byte, 1);
        fflush(stdout);
        _exit(0);
    }
    read(told[0], &byte, 1);
    long hidden = wait_status(child, WNOHANG);
    write(go[1], "x", 1);
    wait_status(tracer, 0);
    result("zombie-hidden", hidden);
    int status = wait_status(child, 0);
    result("zombie-exit", WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    return 0;
}

static int detach_group_stop(int ready[2]) {
    char byte;
    pid_t child = traceable(ready[1]);
    read(ready[0], &byte, 1);
    pid_t tracer = fork();
    if (tracer == 0) {
        result("seize", pt(PTRACE_SEIZE, child, 0, 0));
        kill(child, SIGSTOP);
        stop("sigstop", wait_status(child, 0));
        pt(PTRACE_CONT, child, 0, SIGSTOP);
        stop("group", wait_status(child, 0));
        result("detach", pt(PTRACE_DETACH, child, 0, 0));
        fflush(stdout);
        _exit(0);
    }
    wait_status(tracer, 0);
    char state = 0;
    for (int i = 0; i < 2000 && (tracer_pid_of(child, &state) != 0 || state != 'T'); i++)
        usleep(1000);
    result("detached-stopped", state == 'T');
    stop("parent", wait_status(child, WNOHANG | WUNTRACED));
    kill(child, SIGCONT);
    result("continued", WIFCONTINUED(wait_status(child, WCONTINUED)));
    /* SIGKILL, not the SIGUSR2 the child waits for. A workaround for the
     * emulator bug above: a SIGUSR2 sent right after SIGCONT, as the task
     * comes out of its stop, can be lost. Back to SIGUSR2, and the exit
     * code it gives, once the emulator keeps such a signal. */
    kill(child, SIGKILL);
    int status = wait_status(child, 0);
    result("group-killed", WIFSIGNALED(status) ? WTERMSIG(status) : -1);
    return 0;
}

static int detach_case(void) {
    int ready[2];
    if (pipe(ready)) return 80;
    int code = detach_signal();
    if (!code) code = detach_exit_stopped(ready);
    if (!code) code = detach_exit_zombie(ready);
    if (!code) code = detach_group_stop(ready);
    return code;
}

int main(int argc, char **argv) {
    if (argc < 3) return 99;
    const char *mode = argv[1], *self = argv[2];
    setvbuf(stdout, NULL, _IOFBF, 1 << 16);
    int code = 98;
    if (!strcmp(mode, "exec-child")) return exec_child();
    if (!strcmp(mode, "ptrace-traceme")) code = traceme(self);
    if (!strcmp(mode, "ptrace-attach")) code = attach();
    if (!strcmp(mode, "ptrace-seize")) code = seize();
    if (!strcmp(mode, "ptrace-signals")) code = signals_case();
    if (!strcmp(mode, "ptrace-regs")) code = regs_case();
    if (!strcmp(mode, "ptrace-memory")) code = memory_case();
    if (!strcmp(mode, "ptrace-thread")) code = thread_case();
    if (!strcmp(mode, "ptrace-sibling")) code = sibling_case();
    if (!strcmp(mode, "ptrace-attach-stopped")) code = attach_stopped();
    if (!strcmp(mode, "ptrace-tracer-exit")) code = tracer_exit_case();
    if (!strcmp(mode, "ptrace-wait")) code = wait_case();
    if (!strcmp(mode, "ptrace-detach")) code = detach_case();
    fflush(stdout);
    return code;
}
