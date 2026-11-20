/* ptrace's syscall stops and events, compared with native Linux on x86-64:
 * a small strace that follows a fork, PTRACE_SYSEMU, the fork, vfork,
 * exec and exit events, and the clone of a thread of a seized tracee.
 * No address or PID is printed, only which task a number names. */
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#define REQ_SYSCALL 24
#define REQ_SYSEMU 31
#define REQ_SEIZE 0x4206
#define REQ_GETEVENTMSG 0x4201
#define REQ_GET_SYSCALL_INFO 0x420e
#define REQ_SET_SYSCALL_INFO 0x4212
#define O_TRACESYSGOOD 1
#define O_TRACEFORK 2
#define O_TRACEVFORK 4
#define O_TRACECLONE 8
#define O_TRACEEXEC 0x10
#define O_TRACEVFORKDONE 0x20
#define O_TRACEEXIT 0x40
#define O_EXITKILL (1 << 20)

/* struct ptrace_syscall_info, as Linux 6.16 and later have it. */
struct syscall_info {
    uint8_t op, reserved;
    uint16_t flags;
    uint32_t arch;
    uint64_t ip, sp;
    union {
        struct {
            uint64_t nr, args[6];
        } entry;
        struct {
            int64_t rval;
            uint8_t is_error;
        } exit;
        struct {
            uint64_t nr, args[6];
            uint32_t ret_data, reserved2;
        } seccomp;
    };
};

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

/* The tasks a case names, which a value is printed as. */
static pid_t named[4];
static const char *names[4] = {"parent", "child", "second", "other"};

static void value(long v) {
    for (int i = 0; i < 4; i++) {
        if (named[i] && v == named[i]) {
            printf("%s", names[i]);
            return;
        }
    }
    printf("%ld", v);
}

static const char *who(pid_t pid) {
    for (int i = 0; i < 4; i++)
        if (named[i] == pid) return names[i];
    return "?";
}

/* --- ptrace-strace ---------------------------------------------------- */

/* The traced program: a few calls its tracer looks at or changes, then a
 * fork whose child it follows. Its exit code has a bit for each change it
 * saw as its tracer made it. */
static int strace_child(void) {
    sigset_t chld;
    sigemptyset(&chld);
    sigaddset(&chld, SIGCHLD);
    sigprocmask(SIG_BLOCK, &chld, NULL);
    if (pt(PTRACE_TRACEME, 0, 0, 0)) _exit(90);
    raise(SIGSTOP);
    long self = syscall(SYS_getpid);
    syscall(SYS_close, -1);
    long skipped = syscall(SYS_getppid);
    long changed = syscall(SYS_getuid);
    long failed = syscall(SYS_sched_yield);
    int failed_errno = errno;
    long none = syscall(1000);
    int none_errno = errno;
    pid_t child = syscall(SYS_fork);
    if (child == 0) {
        syscall(SYS_getpid);
        _exit(2);
    }
    int status;
    syscall(SYS_wait4, child, &status, 0, NULL);
    _exit((skipped == 42) | (changed == self) << 1 | (failed == -1 && failed_errno == EPERM) << 2 |
          (none == -1 && none_errno == ENOSYS) << 3 | (WEXITSTATUS(status) == 2) << 4);
}

static int first_entry = 1;

/* What the tracer does at a syscall-entry stop of `pid`: shows it, and
 * changes the calls the case changes. */
static void strace_entry(pid_t pid, struct user_regs_struct *regs) {
    long nr = (long)regs->orig_rax;
    printf("%s enter %ld rax=%lld\n", who(pid), nr, (long long)regs->rax);
    struct syscall_info info;
    memset(&info, 0, sizeof info);
    long size = pt(REQ_GET_SYSCALL_INFO, pid, sizeof info, (unsigned long)&info);
    if (first_entry) {
        first_entry = 0;
        printf("info size=%ld op=%d arch=%#x ip=%d sp=%d nr=%d\n", size, info.op, info.arch,
               info.ip == regs->rip, info.sp == regs->rsp, info.entry.nr == regs->orig_rax);
        printf("info short=%ld\n", pt(REQ_GET_SYSCALL_INFO, pid, 8, (unsigned long)&info));
        printf("info args=%d\n", info.entry.args[0] == regs->rdi && info.entry.args[3] == regs->r10);
    }
    if (nr == SYS_getppid) {
        /* Skipped, with the value the tracer leaves in rax. */
        regs->orig_rax = -1;
        regs->rax = 42;
        printf("setregs=%ld\n", pt(PTRACE_SETREGS, pid, 0, (unsigned long)regs));
    } else if (nr == SYS_getuid) {
        struct syscall_info set = info;
        printf("set-small=%ld\n", pt(REQ_SET_SYSCALL_INFO, pid, sizeof set - 1, (unsigned long)&set));
        set.flags = 1;
        printf("set-flags=%ld\n", pt(REQ_SET_SYSCALL_INFO, pid, sizeof set, (unsigned long)&set));
        set.flags = 0;
        set.op = 2;
        printf("set-op=%ld\n", pt(REQ_SET_SYSCALL_INFO, pid, sizeof set, (unsigned long)&set));
        set.op = 1;
        set.entry.nr = 1UL << 40;
        printf("set-range=%ld\n", pt(REQ_SET_SYSCALL_INFO, pid, sizeof set, (unsigned long)&set));
        set.entry.nr = SYS_getpid;
        printf("set-entry=%ld\n", pt(REQ_SET_SYSCALL_INFO, pid, sizeof set, (unsigned long)&set));
    }
}

static void strace_exit(pid_t pid, struct user_regs_struct *regs) {
    struct syscall_info info;
    memset(&info, 0, sizeof info);
    long size = pt(REQ_GET_SYSCALL_INFO, pid, sizeof info, (unsigned long)&info);
    printf("%s exit %ld = ", who(pid), (long)regs->orig_rax);
    value(info.exit.rval);
    printf(" error=%d size=%ld op=%d\n", info.exit.is_error, size, info.op);
    if ((long)regs->orig_rax == SYS_sched_yield) {
        info.exit.is_error = 1;
        info.exit.rval = -EPERM;
        printf("set-exit=%ld\n", pt(REQ_SET_SYSCALL_INFO, pid, sizeof info, (unsigned long)&info));
    }
}

/* Follows `pid` until it exits, as `strace -f` does, a child it forks
 * first, while `pid` waits at the event. */
static void strace_follow(pid_t pid) {
    for (;;) {
        int status = wait_status(pid, __WALL);
        if (status < 0 || !WIFSTOPPED(status)) {
            printf("%s exited=%d code=%d\n", who(pid), WIFEXITED(status), WEXITSTATUS(status));
            return;
        }
        int signal = WSTOPSIG(status), event = status >> 16;
        int give = 0;
        if (event) {
            unsigned long message = 0;
            pt(REQ_GETEVENTMSG, pid, 0, (unsigned long)&message);
            if (event == 1) named[1] = message;
            printf("%s event=%d message=", who(pid), event);
            value(message);
            printf("\n");
            if (event == 1) strace_follow(message);
        } else if (signal == (SIGTRAP | 0x80) || signal == SIGTRAP) {
            struct user_regs_struct regs;
            pt(PTRACE_GETREGS, pid, 0, (unsigned long)&regs);
            struct syscall_info info;
            memset(&info, 0, sizeof info);
            long size = pt(REQ_GET_SYSCALL_INFO, pid, sizeof info, (unsigned long)&info);
            if (signal == SIGTRAP) {
                /* Without PTRACE_O_TRACESYSGOOD: a plain SIGTRAP, which
                 * syscall info cannot tell from another. */
                siginfo_t si;
                pt(PTRACE_GETSIGINFO, pid, 0, (unsigned long)&si);
                printf("%s plain nr=%ld op=%d size=%ld si-code=%d\n", who(pid), (long)regs.orig_rax,
                       info.op, size, si.si_code);
                printf("options=%ld\n", pt(PTRACE_SETOPTIONS, pid, 0, O_TRACESYSGOOD | O_TRACEFORK));
            } else if (info.op == 1) {
                strace_entry(pid, &regs);
            } else {
                strace_exit(pid, &regs);
            }
        } else {
            printf("%s signal=%d\n", who(pid), signal);
            if (signal != SIGSTOP) give = signal;
        }
        pt(REQ_SYSCALL, pid, 0, give);
    }
}

static int strace_case(void) {
    fflush(stdout);
    pid_t child = fork();
    if (child == 0) strace_child();
    named[0] = child;
    strace_follow(child);
    return 0;
}

/* --- ptrace-sysemu ---------------------------------------------------- */

static int sysemu_case(void) {
    fflush(stdout);
    pid_t child = fork();
    if (child == 0) {
        if (pt(PTRACE_TRACEME, 0, 0, 0)) _exit(90);
        raise(SIGSTOP);
        long emulated = syscall(SYS_getpid);
        long skipped = syscall(SYS_getppid);
        _exit((emulated == 77) | (skipped == -1 && errno == ENOSYS) << 1);
    }
    named[0] = child;
    int status = wait_status(child, 0);
    printf("stop=%d\n", WIFSTOPPED(status) ? WSTOPSIG(status) : -1);
    pt(PTRACE_SETOPTIONS, child, 0, O_TRACESYSGOOD);
    /* Each call stops at its entry only, and does not run. */
    for (int round = 0;; round++) {
        printf("sysemu=%ld\n", pt(REQ_SYSEMU, child, 0, 0));
        status = wait_status(child, 0);
        struct user_regs_struct regs;
        pt(PTRACE_GETREGS, child, 0, (unsigned long)&regs);
        printf("entry signal=%d nr=%ld rax=%lld\n", WSTOPSIG(status), (long)regs.orig_rax,
               (long long)regs.rax);
        if ((long)regs.orig_rax == SYS_getpid) {
            regs.rax = 77;
            pt(PTRACE_SETREGS, child, 0, (unsigned long)&regs);
        }
        if ((long)regs.orig_rax == SYS_getppid || round > 8) break;
    }
    /* Skipped under PTRACE_SYSEMU, which it entered with, though the
     * tracer asks for its exit now. */
    pt(REQ_SYSCALL, child, 0, 0);
    status = wait_status(child, 0);
    struct user_regs_struct regs;
    pt(PTRACE_GETREGS, child, 0, (unsigned long)&regs);
    printf("exit signal=%d nr=%ld rax=%lld\n", WSTOPSIG(status), (long)regs.orig_rax,
           (long long)regs.rax);
    pt(PTRACE_CONT, child, 0, 0);
    status = wait_status(child, 0);
    printf("exit=%d\n", WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    return 0;
}

/* --- ptrace-events ---------------------------------------------------- */

/* The next stop of `pid`, which is to be `event` (0 for a signal stop),
 * and the event's message. */
static void expect(pid_t pid, const char *name) {
    int status = wait_status(pid, __WALL);
    if (status < 0 || !WIFSTOPPED(status)) {
        printf("%s: %s exited=%d code=%d\n", name, who(pid), WIFEXITED(status), WEXITSTATUS(status));
        return;
    }
    unsigned long message = 0;
    pt(REQ_GETEVENTMSG, pid, 0, (unsigned long)&message);
    struct user_regs_struct regs;
    pt(PTRACE_GETREGS, pid, 0, (unsigned long)&regs);
    printf("%s: %s signal=%d event=%d nr=%ld rax=", name, who(pid), WSTOPSIG(status), status >> 16,
           (long)regs.orig_rax);
    value(regs.rax);
    printf(" message=");
    value(message);
    printf("\n");
}

static int events_case(const char *self) {
    fflush(stdout);
    pid_t child = fork();
    if (child == 0) {
        sigset_t chld;
        sigemptyset(&chld);
        sigaddset(&chld, SIGCHLD);
        sigprocmask(SIG_BLOCK, &chld, NULL);
        if (pt(PTRACE_TRACEME, 0, 0, 0)) _exit(90);
        raise(SIGSTOP);
        pid_t forked = syscall(SYS_fork);
        if (forked == 0) _exit(3);
        int status;
        waitpid(forked, &status, 0);
        if (vfork() == 0) _exit(4);
        execl(self, self, "exec-child", self, (char *)NULL);
        _exit(91);
    }
    named[0] = child;
    expect(child, "start");
    printf("options=%ld\n", pt(PTRACE_SETOPTIONS, child, 0,
                               O_TRACEFORK | O_TRACEVFORK | O_TRACEEXEC | O_TRACEVFORKDONE |
                                   O_TRACEEXIT));
    pt(PTRACE_CONT, child, 0, 0);
    /* fork: the parent stops at the event, the child starts stopped. */
    int status = wait_status(child, __WALL);
    unsigned long message = 0;
    pt(REQ_GETEVENTMSG, child, 0, (unsigned long)&message);
    named[1] = message;
    printf("fork event=%d\n", status >> 16);
    siginfo_t si;
    pt(PTRACE_GETSIGINFO, child, 0, (unsigned long)&si);
    printf("fork si-signo=%d si-code=%#x\n", si.si_signo, si.si_code);
    expect(named[1], "forked");
    pt(PTRACE_GETSIGINFO, named[1], 0, (unsigned long)&si);
    printf("forked si-code=%d si-pid=%d\n", si.si_code, si.si_pid);
    pt(PTRACE_CONT, named[1], 0, 0);
    expect(named[1], "forked-exit");
    pt(PTRACE_CONT, named[1], 0, 0);
    expect(named[1], "forked-gone");
    pt(PTRACE_CONT, child, 0, 0);
    /* vfork: the parent stops at the event, then once its child has
     * exited, at PTRACE_EVENT_VFORK_DONE. */
    status = wait_status(child, __WALL);
    pt(REQ_GETEVENTMSG, child, 0, (unsigned long)&message);
    named[2] = message;
    printf("vfork event=%d\n", status >> 16);
    expect(named[2], "vforked");
    pt(PTRACE_CONT, named[2], 0, 0);
    expect(named[2], "vforked-exit");
    pt(PTRACE_CONT, named[2], 0, 0);
    expect(named[2], "vforked-gone");
    pt(PTRACE_CONT, child, 0, 0);
    expect(child, "vfork-done");
    pt(PTRACE_CONT, child, 0, 0);
    /* execve, then the new program's exit. */
    expect(child, "exec");
    pt(PTRACE_CONT, child, 0, 0);
    expect(child, "exit");
    pt(PTRACE_CONT, child, 0, 0);
    expect(child, "gone");
    return 0;
}

/* --- ptrace-clone ----------------------------------------------------- */

static void *clone_thread(void *arg) {
    (void)arg;
    return NULL;
}

static int clone_case(void) {
    int go[2], done[2];
    if (pipe(go) || pipe(done)) return 80;
    fflush(stdout);
    pid_t child = fork();
    if (child == 0) {
        char byte;
        read(go[0], &byte, 1);
        pthread_t thread;
        pthread_create(&thread, NULL, clone_thread, NULL);
        pthread_join(thread, NULL);
        /* Stays until its tracer has reaped the thread. */
        read(done[0], &byte, 1);
        _exit(0);
    }
    named[0] = child;
    printf("seize=%ld\n", pt(REQ_SEIZE, child, 0, O_TRACECLONE | O_EXITKILL));
    write(go[1], "x", 1);
    int status = wait_status(child, __WALL);
    unsigned long message = 0;
    pt(REQ_GETEVENTMSG, child, 0, (unsigned long)&message);
    named[2] = message;
    struct user_regs_struct regs;
    pt(PTRACE_GETREGS, child, 0, (unsigned long)&regs);
    struct syscall_info info;
    memset(&info, 0, sizeof info);
    long size = pt(REQ_GET_SYSCALL_INFO, child, sizeof info, (unsigned long)&info);
    printf("clone signal=%d event=%d nr=%ld rax=%lld info-op=%d size=%ld\n", WSTOPSIG(status),
           status >> 16, (long)regs.orig_rax, (long long)regs.rax, info.op, size);
    /* The new thread, seized as its maker, starts in PTRACE_EVENT_STOP. */
    expect(named[2], "thread");
    pt(PTRACE_CONT, named[2], 0, 0);
    pt(PTRACE_CONT, child, 0, 0);
    expect(named[2], "thread-gone");
    write(done[1], "x", 1);
    expect(child, "gone");
    return 0;
}

/* --- ptrace-held ------------------------------------------------------ */

/* The tasks a tracee's clone holds for its tracer, and those it does not:
 * CLONE_PTRACE traces the child with no event asked for, which starts
 * with SIGSTOP from no one; CLONE_UNTRACED makes no event and an untraced
 * child; a clone that fails makes no event either. A held child refuses
 * PTRACE_INTERRUPT, as it was not seized, and is let go with
 * PTRACE_DETACH. A zombie may not be attached to. */
#define CLONE_PTRACE_FLAG 0x2000
#define CLONE_UNTRACED_FLAG 0x800000
#define CLONE_THREAD_FLAG 0x10000

static int reaped(pid_t pid) {
    int status = 0;
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {
    }
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

static int held_child(void) {
    sigset_t chld;
    sigemptyset(&chld);
    sigaddset(&chld, SIGCHLD);
    sigprocmask(SIG_BLOCK, &chld, NULL);
    if (pt(PTRACE_TRACEME, 0, 0, 0)) return 90;
    raise(SIGSTOP);
    int code = 0;
    pid_t made = syscall(SYS_clone, CLONE_PTRACE_FLAG | SIGCHLD, 0, 0, 0, 0);
    if (made == 0) _exit(3);
    if (reaped(made) == 3) code |= 1;
    raise(SIGSTOP);
    made = syscall(SYS_clone, CLONE_UNTRACED_FLAG | SIGCHLD, 0, 0, 0, 0);
    if (made == 0) _exit(4);
    if (reaped(made) == 4) code |= 2;
    if (syscall(SYS_clone, CLONE_THREAD_FLAG | SIGCHLD, 0, 0, 0, 0) == -1 && errno == EINVAL)
        code |= 4;
    made = syscall(SYS_fork);
    if (made == 0) _exit(5);
    if (reaped(made) == 5) code |= 8;
    return code;
}

static int held_case(void) {
    fflush(stdout);
    pid_t zombie = fork();
    if (zombie == 0) _exit(0);
    siginfo_t si;
    memset(&si, 0, sizeof si);
    waitid(P_PID, zombie, &si, WEXITED | WNOWAIT);
    printf("attach-zombie=%ld\n", pt(PTRACE_ATTACH, zombie, 0, 0));
    printf("seize-zombie=%ld\n", pt(REQ_SEIZE, zombie, 0, 0));
    wait_status(zombie, 0);
    fflush(stdout);
    pid_t child = fork();
    if (child == 0) _exit(held_child());
    named[0] = child;
    expect(child, "start");
    pt(PTRACE_CONT, child, 0, 0);
    /* The child CLONE_PTRACE made, which its parent waits for: no event. */
    int status = 0;
    pid_t held = waitpid(-1, &status, __WALL);
    named[1] = held;
    printf("ptraced: %s signal=%d event=%d\n", who(held), WSTOPSIG(status), status >> 16);
    memset(&si, 0, sizeof si);
    pt(PTRACE_GETSIGINFO, held, 0, (unsigned long)&si);
    printf("ptraced si-code=%d si-pid=%d\n", si.si_code, si.si_pid);
    pt(PTRACE_CONT, held, 0, 0);
    expect(held, "ptraced-gone");
    expect(child, "options-stop");
    printf("options=%ld\n", pt(PTRACE_SETOPTIONS, child, 0, O_TRACEFORK | O_TRACECLONE));
    pt(PTRACE_CONT, child, 0, 0);
    /* The untraced child and the clone that fails make no stop: the next
     * is the fork's. */
    status = wait_status(child, __WALL);
    unsigned long message = 0;
    pt(REQ_GETEVENTMSG, child, 0, (unsigned long)&message);
    named[2] = message;
    printf("fork signal=%d event=%d\n", WSTOPSIG(status), status >> 16);
    expect(named[2], "forked");
    printf("interrupt-held=%ld\n", pt(0x4207, named[2], 0, 0));
    printf("detach-held=%ld\n", pt(PTRACE_DETACH, named[2], 0, 0));
    printf("detached=%ld\n", pt(PTRACE_CONT, named[2], 0, 0));
    pt(PTRACE_CONT, child, 0, 0);
    expect(child, "exit");
    return 0;
}

/* --- ptrace-thread-exec ----------------------------------------------- */

/* A thread other than the leader execs: its tracer sees the exec event
 * from the leader's ID, the thread's own ID as the event's message, and
 * nothing left of the thread's old ID. */
static const char *exec_self;

static void *exec_thread(void *arg) {
    (void)arg;
    execl(exec_self, exec_self, "exec-child", exec_self, (char *)NULL);
    return NULL;
}

static int thread_exec_case(const char *self) {
    exec_self = self;
    fflush(stdout);
    pid_t child = fork();
    if (child == 0) {
        if (pt(PTRACE_TRACEME, 0, 0, 0)) _exit(90);
        raise(SIGSTOP);
        pthread_t thread;
        pthread_create(&thread, NULL, exec_thread, NULL);
        for (;;) pause();
    }
    named[0] = child;
    expect(child, "start");
    printf("options=%ld\n", pt(PTRACE_SETOPTIONS, child, 0, O_TRACECLONE | O_TRACEEXEC));
    pt(PTRACE_CONT, child, 0, 0);
    int status = wait_status(child, __WALL);
    unsigned long message = 0;
    pt(REQ_GETEVENTMSG, child, 0, (unsigned long)&message);
    named[1] = message;
    printf("clone event=%d\n", status >> 16);
    expect(named[1], "thread");
    pt(PTRACE_CONT, named[1], 0, 0);
    pt(PTRACE_CONT, child, 0, 0);
    expect(child, "exec");
    printf("old-thread=%d\n", wait_status(named[1], WNOHANG | __WALL));
    pt(PTRACE_CONT, child, 0, 0);
    expect(child, "exit");
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 3) return 99;
    const char *mode = argv[1], *self = argv[2];
    setvbuf(stdout, NULL, _IOFBF, 1 << 16);
    int code = 98;
    if (!strcmp(mode, "exec-child")) return 7;
    if (!strcmp(mode, "ptrace-strace")) code = strace_case();
    if (!strcmp(mode, "ptrace-sysemu")) code = sysemu_case();
    if (!strcmp(mode, "ptrace-events")) code = events_case(self);
    if (!strcmp(mode, "ptrace-clone")) code = clone_case();
    if (!strcmp(mode, "ptrace-held")) code = held_case();
    if (!strcmp(mode, "ptrace-thread-exec")) code = thread_exec_case(self);
    fflush(stdout);
    return code;
}
