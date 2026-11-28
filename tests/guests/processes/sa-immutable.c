/* sigaction's flags and SA_IMMUTABLE.
 *
 * rt_sigaction keeps and shows only the flags of Linux's UAPI_SA_FLAGS, and
 * writes the old action only after the change. A kill by seccomp forces
 * SIGSYS as HANDLER_EXIT (`force_sig_seccomp`): the action is left at its
 * default and SA_IMMUTABLE, in the sighand_struct that a CLONE_SIGHAND
 * process shares. That process then may neither change nor read SIGSYS's
 * action (EINVAL), a process it forks copies it, a tracer sees no
 * signal-delivery stop for it, and execve clears it. (Linux master's signal
 * files also leave such a signal out, which v7.0 does not, so it is not
 * compared here.)
 *
 * The vsyscall-immutable case: a tracer that changes the number of a
 * vsyscall entry's call at its seccomp stop, or moves the thread from the
 * entry, makes `emulate_vsyscall` end the caller with SIGSYS
 * (`force_exit_sig`), which leaves the action at its default and
 * SA_IMMUTABLE as well: the tracer sees no signal-delivery stop, and the
 * process that shares the actions finds SIGSYS's immutable. Each change is
 * made in a forked process of its own, whose actions are not yet so. */
#define _GNU_SOURCE
#include <errno.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

/* The classic BPF and seccomp ABI, which musl's headers do not have. */
struct sock_filter {
    uint16_t code;
    uint8_t jt, jf;
    uint32_t k;
};
struct sock_fprog {
    unsigned short len;
    struct sock_filter *filter;
};
#define BPF_STMT(code, k) {(uint16_t)(code), 0, 0, (k)}
#define BPF_JUMP(code, k, jt, jf) {(uint16_t)(code), (jt), (jf), (k)}
#define LOAD_NR 0x20     /* BPF_LD | BPF_W | BPF_ABS, of seccomp_data's nr */
#define JUMP_EQ 0x15     /* BPF_JMP | BPF_JEQ | BPF_K */
#define RETURN 0x06      /* BPF_RET | BPF_K */
#define SECCOMP_SET_MODE_FILTER 1
#define SECCOMP_RET_KILL_PROCESS 0x80000000U
#define SECCOMP_RET_ALLOW 0x7fff0000U
#define SECCOMP_RET_TRACE 0x7ff00000U
#define VSYSCALL_TIME 0xffffffffff600400UL

#define SA_RESTORER_FLAG 0x04000000UL
#define SA_UNSUPPORTED_FLAG 0x00000400UL
#define SA_IMMUTABLE_FLAG 0x00800000UL

/* The kernel's struct sigaction on x86-64. */
struct kact {
    unsigned long handler, flags, restorer, mask;
};

static long act(int sig, const struct kact *new, struct kact *old) {
    long r = syscall(SYS_rt_sigaction, sig, new, old, 8);
    return r < 0 ? -errno : r;
}

static void handler(int sig) { (void)sig; }

static char *self;

/* The CLONE_SIGHAND process: a filter that kills it at getppid. */
static int sharer(void *unused) {
    (void)unused;
    struct sock_filter code[] = {
        BPF_STMT(LOAD_NR, 0),
        BPF_JUMP(JUMP_EQ, SYS_getppid, 0, 1),
        BPF_STMT(RETURN, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(RETURN, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog program = {sizeof code / sizeof code[0], code};
    if (syscall(SYS_prctl, PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) return 1;
    if (syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &program)) return 2;
    syscall(SYS_getppid);
    return 3;
}

/* The traced CLONE_SIGHAND process: its tracer sees time from the
 * vsyscall page at a seccomp stop. */
static int traced_sharer(void *unused) {
    (void)unused;
    struct sock_filter code[] = {
        BPF_STMT(LOAD_NR, 0),
        BPF_JUMP(JUMP_EQ, SYS_time, 0, 1),
        BPF_STMT(RETURN, SECCOMP_RET_TRACE),
        BPF_STMT(RETURN, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog program = {sizeof code / sizeof code[0], code};
    if (syscall(SYS_ptrace, PTRACE_TRACEME, 0, 0, 0)) return 1;
    syscall(SYS_kill, syscall(SYS_getpid), SIGSTOP);
    if (syscall(SYS_prctl, PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) return 2;
    if (syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &program)) return 3;
    ((long (*)(long *))VSYSCALL_TIME)(NULL);
    return 4;
}

static void status_line(const char *who, int status) {
    if (WIFSIGNALED(status))
        printf("%s: signaled %d\n", who, WTERMSIG(status));
    else if (WIFSTOPPED(status))
        printf("%s: stopped %d\n", who, WSTOPSIG(status));
    else
        printf("%s: exited %d\n", who, WEXITSTATUS(status));
    fflush(stdout);
}

/* What SIGSYS's action shows, from `who`. */
static void show_sigsys(const char *who) {
    struct kact old = {0x77, 0x77, 0x77, 0x77};
    long r = act(SIGSYS, NULL, &old);
    printf("%s: query %ld handler %#lx flags %#lx\n", who, r, old.handler, old.flags);
    fflush(stdout);
}

/* One change of the vsyscall-immutable case: the number, or `rip`. */
static int vsyscall_immutable(int move) {
    struct kact sys = {(unsigned long)handler, SA_RESTORER_FLAG, 0, 0};
    printf("handler: %ld\n", act(SIGSYS, &sys, NULL));
    static char stack[64 * 1024] __attribute__((aligned(16)));
    int pid = clone(traced_sharer, stack + sizeof stack, CLONE_VM | CLONE_SIGHAND | SIGCHLD, NULL);
    if (pid < 0) {
        perror("clone");
        return 1;
    }
    int status;
    waitpid(pid, &status, __WALL);
    status_line("sharer", status);
    if (!WIFSTOPPED(status)) return 1;
    ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESECCOMP | PTRACE_O_EXITKILL);
    ptrace(PTRACE_CONT, pid, 0, 0);
    waitpid(pid, &status, __WALL);
    status_line("sharer", status);
    if (!WIFSTOPPED(status)) return 1;
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, pid, 0, &regs);
    printf("seccomp: event %d nr %lld at entry %d\n", status >> 16, (long long)regs.orig_rax,
           regs.rip == VSYSCALL_TIME);
    if (move)
        regs.rip = VSYSCALL_TIME - 0x400;
    else
        regs.orig_rax = SYS_getpid;
    printf("changed %s: %ld\n", move ? "rip" : "nr", ptrace(PTRACE_SETREGS, pid, 0, &regs));
    fflush(stdout);
    ptrace(PTRACE_CONT, pid, 0, 0);
    waitpid(pid, &status, __WALL);
    status_line("sharer then", status);
    if (WIFSTOPPED(status)) {
        kill(pid, SIGKILL);
        waitpid(pid, &status, __WALL);
    }
    show_sigsys("after");
    printf("set: %ld\n", act(SIGSYS, &sys, NULL));
    return 0;
}

int main(int argc, char **argv) {
    /* The harness gives the program's own path after the case's name. */
    self = argc > 2 ? argv[2] : argv[0];
    if (argc > 1 && strcmp(argv[1], "after-exec") == 0) {
        show_sigsys("after exec");
        return 0;
    }
    setvbuf(stdout, NULL, _IOLBF, 0);
    struct rlimit none = {0, 0};
    setrlimit(RLIMIT_CORE, &none);
    if (argc > 1 && strcmp(argv[1], "vsyscall-immutable") == 0) {
        for (int move = 0; move < 2; move++) {
            int pid = fork();
            if (pid == 0) _exit(vsyscall_immutable(move));
            int status;
            waitpid(pid, &status, 0);
            status_line("case", status);
        }
        return 0;
    }

    /* Only the known flags stay, and show. */
    struct kact usr1 = {(unsigned long)handler,
                        SA_SIGINFO | SA_RESTORER_FLAG | SA_UNSUPPORTED_FLAG | SA_IMMUTABLE_FLAG |
                            1UL << 40,
                        0, 0};
    long r = act(SIGUSR1, &usr1, NULL);
    struct kact old = {0};
    act(SIGUSR1, NULL, &old);
    printf("flags: set %ld shows %#lx\n", r, old.flags);

    /* An old action it cannot write is EFAULT after the change; a new one
     * it cannot read is EFAULT before the signal's checks. */
    struct kact ignore = {(unsigned long)SIG_IGN, SA_RESTORER_FLAG, 0, 0};
    r = act(SIGUSR2, &ignore, (struct kact *)8);
    act(SIGUSR2, NULL, &old);
    printf("order: bad old %ld ignored %d\n", r, old.handler == (unsigned long)SIG_IGN);
    printf("order: SIGKILL with a bad new %ld\n", act(SIGKILL, (struct kact *)8, NULL));

    /* The sharer's seccomp kill leaves SIGSYS at its default, immutable. */
    struct kact sys = {(unsigned long)handler, SA_RESTORER_FLAG, 0, 1UL << 1};
    printf("handler: %ld\n", act(SIGSYS, &sys, NULL));
    show_sigsys("before");
    static char stack[64 * 1024] __attribute__((aligned(16)));
    int pid = clone(sharer, stack + sizeof stack, CLONE_VM | CLONE_SIGHAND | SIGCHLD, NULL);
    if (pid < 0) {
        perror("clone");
        return 1;
    }
    int status;
    waitpid(pid, &status, 0);
    status_line("sharer", status);
    show_sigsys("after");
    printf("set: %ld\n", act(SIGSYS, &sys, NULL));
    fflush(stdout);

    /* A forked process copies it: SIGSYS ends it, as the handler is gone. */
    pid = fork();
    if (pid == 0) {
        show_sigsys("forked");
        kill(getpid(), SIGSYS);
        _exit(4);
    }
    waitpid(pid, &status, 0);
    status_line("forked", status);

    /* A tracer sees no signal-delivery stop for it. */
    pid = fork();
    if (pid == 0) {
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        kill(getpid(), SIGSYS);
        _exit(5);
    }
    waitpid(pid, &status, 0);
    status_line("traced", status);
    if (WIFSTOPPED(status)) {
        ptrace(PTRACE_CONT, pid, 0, WSTOPSIG(status));
        waitpid(pid, &status, 0);
        status_line("traced then", status);
        if (WIFSTOPPED(status)) {
            kill(pid, SIGKILL);
            waitpid(pid, &status, 0);
        }
    }

    /* execve clears it, as `flush_signal_handlers` clears the flags. */
    pid = fork();
    if (pid == 0) {
        char *args[] = {self, "after-exec", NULL};
        char *env[] = {NULL};
        execve(self, args, env);
        _exit(6);
    }
    waitpid(pid, &status, 0);
    status_line("exec", status);
    return 0;
}
