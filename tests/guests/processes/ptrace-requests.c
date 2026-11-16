/* More ptrace requests, compared with native Linux on x86-64: the pending
 * signals and the mask of a stopped tracee, PTRACE_LISTEN, the stops
 * SECCOMP_RET_TRACE makes, and PTRACE_ARCH_PRCTL and the rseq
 * registration. No address or PID is printed, only whether it is the one
 * expected. */
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stddef.h>
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

#define REQ_SEIZE 0x4206
#define REQ_INTERRUPT 0x4207
#define REQ_LISTEN 0x4208
#define REQ_PEEKSIGINFO 0x4209
#define REQ_GETSIGMASK 0x420a
#define REQ_SETSIGMASK 0x420b
#define REQ_GET_RSEQ_CONFIGURATION 0x420f
#define REQ_GET_SYSCALL_INFO 0x420e
#define REQ_GETEVENTMSG 0x4201
#define REQ_ARCH_PRCTL 30
#define O_TRACESECCOMP 0x80
#define EVENT_STOP 128

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
#define BPF_LD 0x00
#define BPF_W 0x00
#define BPF_ABS 0x20
#define BPF_JMP 0x05
#define BPF_JEQ 0x10
#define BPF_K 0x00
#define BPF_RET 0x06
#define BPF_STMT(code, k) {(uint16_t)(code), 0, 0, (k)}
#define BPF_JUMP(code, k, jt, jf) {(uint16_t)(code), (jt), (jf), (k)}
#define SECCOMP_SET_MODE_FILTER 1
#define SECCOMP_RET_TRACE 0x7ff00000U
#define SECCOMP_RET_ALLOW 0x7fff0000U
/* seccomp_data begins with the call's number. */
#define SECCOMP_DATA_NR 0

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

static void show(const char *name, int status) {
    printf("%s: stopped=%d signal=%d event=%d\n", name, WIFSTOPPED(status),
           WIFSTOPPED(status) ? WSTOPSIG(status) : -1, status >> 16);
}

/* --- ptrace-sigmask --------------------------------------------------- */

struct peek_args {
    uint64_t off;
    uint32_t flags;
    int32_t nr;
};

static volatile int handled;
static void on_signal(int number) { handled = handled * 100 + number; }

static int sigmask_case(void) {
    fflush(stdout);
    pid_t child = fork();
    if (child == 0) {
        signal(SIGUSR1, on_signal);
        signal(SIGRTMIN, on_signal);
        sigset_t set;
        sigemptyset(&set);
        sigaddset(&set, SIGUSR1);
        sigaddset(&set, SIGRTMIN);
        sigprocmask(SIG_BLOCK, &set, NULL);
        if (pt(PTRACE_TRACEME, 0, 0, 0)) _exit(90);
        /* One for the thread, two for the process. */
        syscall(SYS_tgkill, getpid(), syscall(SYS_gettid), SIGUSR1);
        sigqueue(getpid(), SIGRTMIN, (union sigval){.sival_int = 1});
        sigqueue(getpid(), SIGRTMIN, (union sigval){.sival_int = 2});
        /* Not raise, which blocks every signal around the tkill and puts
         * its mask back after. */
        syscall(SYS_tkill, syscall(SYS_gettid), SIGSTOP);
        _exit(handled % 1000000);
    }
    int status = wait_status(child, 0);
    show("stop", status);
    uint64_t mask = 0;
    printf("getmask-size=%ld\n", pt(REQ_GETSIGMASK, child, 4, (unsigned long)&mask));
    printf("getmask=%ld\n", pt(REQ_GETSIGMASK, child, 8, (unsigned long)&mask));
    printf("mask-usr1=%d mask-rtmin=%d\n", (int)(mask >> (SIGUSR1 - 1) & 1),
           (int)(mask >> (SIGRTMIN - 1) & 1));
    siginfo_t infos[4];
    struct peek_args args = {0, 0, 4};
    long n = pt(REQ_PEEKSIGINFO, child, (unsigned long)&args, (unsigned long)infos);
    printf("thread-queue=%ld", n);
    for (long i = 0; i < n; i++) printf(" %d/%d", infos[i].si_signo, infos[i].si_code);
    printf("\n");
    args.flags = 1;
    n = pt(REQ_PEEKSIGINFO, child, (unsigned long)&args, (unsigned long)infos);
    printf("process-queue=%ld", n);
    for (long i = 0; i < n; i++)
        printf(" %d/%d/%d", infos[i].si_signo == SIGRTMIN, infos[i].si_code, infos[i].si_value.sival_int);
    printf("\n");
    args.off = 1;
    printf("offset=%ld\n", pt(REQ_PEEKSIGINFO, child, (unsigned long)&args, (unsigned long)infos));
    args.off = 9;
    printf("beyond=%ld\n", pt(REQ_PEEKSIGINFO, child, (unsigned long)&args, (unsigned long)infos));
    args.off = 0;
    args.flags = 2;
    printf("bad-flags=%ld\n", pt(REQ_PEEKSIGINFO, child, (unsigned long)&args, (unsigned long)infos));
    args.flags = 1;
    args.nr = -1;
    printf("bad-nr=%ld\n", pt(REQ_PEEKSIGINFO, child, (unsigned long)&args, (unsigned long)infos));
    args.nr = 1;
    printf("bad-buffer=%ld\n", pt(REQ_PEEKSIGINFO, child, (unsigned long)&args, 8));
    /* Nothing blocked now, but SIGKILL and SIGSTOP never are. */
    uint64_t none = ~0ULL & ~(1ULL << (SIGUSR1 - 1)) & ~(1ULL << (SIGRTMIN - 1));
    printf("setmask=%ld\n", pt(REQ_SETSIGMASK, child, 8, (unsigned long)&none));
    pt(REQ_GETSIGMASK, child, 8, (unsigned long)&mask);
    printf("kill-blocked=%d stop-blocked=%d usr2-blocked=%d\n", (int)(mask >> (SIGKILL - 1) & 1),
           (int)(mask >> (SIGSTOP - 1) & 1), (int)(mask >> (SIGUSR2 - 1) & 1));
    none = 0;
    printf("setmask-size=%ld\n", pt(REQ_SETSIGMASK, child, 16, (unsigned long)&none));
    pt(REQ_SETSIGMASK, child, 8, (unsigned long)&none);
    /* The pending signals come once it goes on: the thread's first. */
    pt(PTRACE_CONT, child, 0, 0);
    for (;;) {
        status = wait_status(child, 0);
        if (!WIFSTOPPED(status)) break;
        printf("delivery=%d\n", WSTOPSIG(status));
        pt(PTRACE_CONT, child, 0, WSTOPSIG(status));
    }
    printf("exit=%d\n", WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    return 0;
}

/* --- ptrace-listen ---------------------------------------------------- */

static long state_of(pid_t pid) {
    char path[64], line[256];
    snprintf(path, sizeof path, "/proc/%d/status", pid);
    FILE *f = fopen(path, "r");
    long state = 0;
    if (!f) return -1;
    while (fgets(line, sizeof line, f))
        if (!strncmp(line, "State:", 6)) state = line[7];
    fclose(f);
    return state;
}

static int listen_case(void) {
    int ready[2];
    if (pipe(ready)) return 80;
    fflush(stdout);
    pid_t child = fork();
    if (child == 0) {
        write(ready[1], "x", 1);
        for (;;) pause();
    }
    char byte;
    read(ready[0], &byte, 1);
    do usleep(10000);
    while (state_of(child) != 'S');
    printf("seize=%ld\n", pt(REQ_SEIZE, child, 0, 0));
    kill(child, SIGSTOP);
    int status = wait_status(child, 0);
    show("sigstop", status);
    printf("listen-signal=%ld\n", pt(REQ_LISTEN, child, 0, 0));
    pt(PTRACE_CONT, child, 0, SIGSTOP);
    status = wait_status(child, 0);
    show("group", status);
    printf("listen=%ld\n", pt(REQ_LISTEN, child, 0, 0));
    /* Listening: neither a wait nor a request sees it stopped. */
    printf("wait=%d\n", wait_status(child, WNOHANG));
    struct user_regs_struct regs;
    printf("getregs=%ld\n", pt(PTRACE_GETREGS, child, 0, (unsigned long)&regs));
    printf("listen-again=%ld\n", pt(REQ_LISTEN, child, 0, 0));
    printf("state=%c\n", (char)state_of(child));
    /* The group stop ends: it traps again. */
    kill(child, SIGCONT);
    status = wait_status(child, 0);
    show("continued", status);
    pt(PTRACE_CONT, child, 0, 0);
    status = wait_status(child, 0);
    show("sigcont", status);
    pt(PTRACE_CONT, child, 0, 0);
    /* Stopped and listening again, then an interrupt. */
    kill(child, SIGSTOP);
    status = wait_status(child, 0);
    show("sigstop-2", status);
    pt(PTRACE_CONT, child, 0, SIGSTOP);
    status = wait_status(child, 0);
    show("group-2", status);
    printf("listen-2=%ld\n", pt(REQ_LISTEN, child, 0, 0));
    printf("interrupt=%ld\n", pt(REQ_INTERRUPT, child, 0, 0));
    status = wait_status(child, 0);
    show("interrupted", status);
    kill(child, SIGKILL);
    status = wait_status(child, 0);
    printf("killed=%d\n", WIFSIGNALED(status) ? WTERMSIG(status) : -1);
    return 0;
}

/* --- ptrace-seccomp --------------------------------------------------- */

static int install_filter(void) {
    struct sock_filter code[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_NR),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_getppid, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRACE | 0x42),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_getuid, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRACE | 7),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog program = {sizeof code / sizeof code[0], code};
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) return -1;
    return syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &program);
}

struct syscall_info {
    uint8_t op, reserved;
    uint16_t flags;
    uint32_t arch;
    uint64_t ip, sp;
    struct {
        uint64_t nr, args[6];
        uint32_t ret_data, reserved2;
    } seccomp;
};

static int seccomp_case(void) {
    fflush(stdout);
    pid_t child = fork();
    if (child == 0) {
        if (install_filter()) _exit(91);
        if (pt(PTRACE_TRACEME, 0, 0, 0)) _exit(90);
        /* No tracer has asked for the event yet. */
        long untraced = syscall(SYS_getppid);
        int untraced_errno = errno;
        raise(SIGSTOP);
        long skipped = syscall(SYS_getppid);
        long changed = syscall(SYS_getuid);
        long rechecked = syscall(SYS_getppid);
        _exit((untraced == -1 && untraced_errno == ENOSYS) | (skipped == 99) << 1 |
              (changed == getpid()) << 2 | (rechecked > 0) << 3);
    }
    int status = wait_status(child, 0);
    show("stop", status);
    printf("options=%ld\n", pt(PTRACE_SETOPTIONS, child, 0, O_TRACESECCOMP));
    for (int round = 0; round < 3; round++) {
        pt(PTRACE_CONT, child, 0, 0);
        status = wait_status(child, 0);
        show("seccomp", status);
        unsigned long message = 0;
        pt(REQ_GETEVENTMSG, child, 0, (unsigned long)&message);
        struct user_regs_struct regs;
        pt(PTRACE_GETREGS, child, 0, (unsigned long)&regs);
        struct syscall_info info;
        memset(&info, 0, sizeof info);
        long size = pt(REQ_GET_SYSCALL_INFO, child, sizeof info, (unsigned long)&info);
        printf("message=%#lx nr=%ld rax=%lld info-size=%ld op=%d info-nr=%ld ret-data=%#x\n", message,
               (long)regs.orig_rax, (long long)regs.rax, size, info.op, (long)info.seccomp.nr,
               info.seccomp.ret_data);
        if (round == 0) {
            regs.orig_rax = -1;
            regs.rax = 99;
            pt(PTRACE_SETREGS, child, 0, (unsigned long)&regs);
        } else if (round == 1) {
            regs.orig_rax = SYS_getpid;
            pt(PTRACE_SETREGS, child, 0, (unsigned long)&regs);
        }
    }
    pt(PTRACE_CONT, child, 0, 0);
    status = wait_status(child, 0);
    printf("exit=%d\n", WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    return 0;
}

/* --- ptrace-arch-rseq ------------------------------------------------- */

#define ARCH_SET_GS 0x1001
#define ARCH_SET_FS 0x1002
#define ARCH_GET_FS 0x1003
#define ARCH_GET_GS 0x1004
#define RSEQ_SIG 0x53053053

static struct {
    uint32_t cpu_id_start, cpu_id;
    uint64_t rseq_cs;
    uint32_t flags, node_id, mm_cid, padding;
} __attribute__((aligned(32))) area;

struct rseq_configuration {
    uint64_t pointer;
    uint32_t size, signature, flags, pad;
};

static int arch_rseq_case(void) {
    fflush(stdout);
    pid_t child = fork();
    if (child == 0) {
        long registered = syscall(SYS_rseq, &area, 32, 0, RSEQ_SIG);
        if (pt(PTRACE_TRACEME, 0, 0, 0)) _exit(90);
        raise(SIGSTOP);
        unsigned long gs = 0;
        syscall(SYS_arch_prctl, ARCH_GET_GS, &gs);
        _exit((registered == 0) | (gs == 0x1234) << 1);
    }
    int status = wait_status(child, 0);
    show("stop", status);
    struct user_regs_struct regs;
    pt(PTRACE_GETREGS, child, 0, (unsigned long)&regs);
    unsigned long fs = 0;
    printf("get-fs=%ld same=%d\n", pt(REQ_ARCH_PRCTL, child, (unsigned long)&fs, ARCH_GET_FS),
           fs == regs.fs_base);
    printf("set-gs=%ld\n", pt(REQ_ARCH_PRCTL, child, 0x1234, ARCH_SET_GS));
    pt(PTRACE_GETREGS, child, 0, (unsigned long)&regs);
    printf("gs-base=%#llx\n", (unsigned long long)regs.gs_base);
    unsigned long gs = 0;
    printf("get-gs=%ld gs=%#lx\n", pt(REQ_ARCH_PRCTL, child, (unsigned long)&gs, ARCH_GET_GS), gs);
    printf("set-fs-high=%ld\n", pt(REQ_ARCH_PRCTL, child, 1UL << 63, ARCH_SET_FS));
    printf("get-fs-fault=%ld\n", pt(REQ_ARCH_PRCTL, child, 8, ARCH_GET_FS));
    printf("other=%ld\n", pt(REQ_ARCH_PRCTL, child, 0, 0x1fff));
    struct rseq_configuration conf;
    memset(&conf, 0, sizeof conf);
    long size = pt(REQ_GET_RSEQ_CONFIGURATION, child, sizeof conf, (unsigned long)&conf);
    printf("rseq size=%ld pointer=%d length=%u signature=%#x flags=%u\n", size,
           conf.pointer == (uint64_t)(uintptr_t)&area, conf.size, conf.signature, conf.flags);
    memset(&conf, 0, sizeof conf);
    size = pt(REQ_GET_RSEQ_CONFIGURATION, child, 8, (unsigned long)&conf);
    printf("rseq-short size=%ld pointer=%d length=%u\n", size,
           conf.pointer == (uint64_t)(uintptr_t)&area, conf.size);
    /* A detach keeps what the tracer set: the child reads its gs base. */
    printf("detach=%ld\n", pt(PTRACE_DETACH, child, 0, 0));
    status = wait_status(child, 0);
    printf("exit=%d\n", WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    return 0;
}

/* --- ptrace-syscall-signal ------------------------------------------- */

#define REQ_SYSCALL 24
#define O_TRACEEXIT 0x40

static volatile int signal_code = -1;
static void record_code(int number, siginfo_t *info, void *context) {
    (void)number;
    (void)context;
    signal_code = info->si_code;
}

/* A signal the tracer gives at a syscall stop is sent to the process from
 * the kernel: it waits in the process's queue, not the thread's. */
static int syscall_signal_case(void) {
    fflush(stdout);
    pid_t child = fork();
    if (child == 0) {
        struct sigaction action = {.sa_sigaction = record_code, .sa_flags = SA_SIGINFO};
        sigaction(SIGUSR1, &action, NULL);
        if (pt(PTRACE_TRACEME, 0, 0, 0)) _exit(90);
        syscall(SYS_tkill, syscall(SYS_gettid), SIGSTOP);
        syscall(SYS_getppid);
        _exit(signal_code == 0x80 ? 0 : 1);
    }
    int status = wait_status(child, 0);
    show("stop", status);
    pt(REQ_SYSCALL, child, 0, 0);
    status = wait_status(child, 0);
    struct user_regs_struct regs;
    pt(PTRACE_GETREGS, child, 0, (unsigned long)&regs);
    printf("entry signal=%d nr=%ld\n", WSTOPSIG(status), (long)regs.orig_rax);
    pt(REQ_SYSCALL, child, 0, SIGUSR1);
    status = wait_status(child, 0);
    pt(PTRACE_GETREGS, child, 0, (unsigned long)&regs);
    printf("exit signal=%d nr=%ld\n", WSTOPSIG(status), (long)regs.orig_rax);
    siginfo_t infos[2];
    struct peek_args args = {0, 0, 2};
    printf("thread-queue=%ld\n", pt(REQ_PEEKSIGINFO, child, (unsigned long)&args, (unsigned long)infos));
    args.flags = 1;
    long n = pt(REQ_PEEKSIGINFO, child, (unsigned long)&args, (unsigned long)infos);
    printf("process-queue=%ld", n);
    for (long i = 0; i < n; i++) printf(" %d/%#x", infos[i].si_signo, infos[i].si_code);
    printf("\n");
    pt(PTRACE_CONT, child, 0, 0);
    status = wait_status(child, 0);
    siginfo_t info;
    memset(&info, 0, sizeof info);
    pt(PTRACE_GETSIGINFO, child, 0, (unsigned long)&info);
    printf("delivery signal=%d si-code=%#x si-pid=%d\n", WSTOPSIG(status), info.si_code, info.si_pid);
    pt(PTRACE_CONT, child, 0, WSTOPSIG(status));
    status = wait_status(child, 0);
    printf("exit=%d\n", WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    return 0;
}

/* --- ptrace-exit-core ------------------------------------------------- */

/* PTRACE_EVENT_EXIT of a process a fatal signal ends, with a core and
 * without: the event's status has 0x80 only when it dumps one. */
static void exit_core_round(const char *name, rlim_t limit) {
    unlink("core");
    fflush(stdout);
    pid_t child = fork();
    if (child == 0) {
        struct rlimit r;
        getrlimit(RLIMIT_CORE, &r);
        r.rlim_cur = limit < r.rlim_max ? limit : r.rlim_max;
        setrlimit(RLIMIT_CORE, &r);
        if (pt(PTRACE_TRACEME, 0, 0, 0)) _exit(90);
        syscall(SYS_tkill, syscall(SYS_gettid), SIGSTOP);
        syscall(SYS_tkill, syscall(SYS_gettid), SIGQUIT);
        _exit(91);
    }
    int status = wait_status(child, 0);
    pt(PTRACE_SETOPTIONS, child, 0, O_TRACEEXIT);
    pt(PTRACE_CONT, child, 0, 0);
    status = wait_status(child, 0);
    printf("%s: delivery=%d\n", name, WSTOPSIG(status));
    pt(PTRACE_CONT, child, 0, SIGQUIT);
    status = wait_status(child, 0);
    unsigned long message = 0;
    pt(REQ_GETEVENTMSG, child, 0, (unsigned long)&message);
    printf("%s: event=%d message=%#lx\n", name, status >> 16, message);
    pt(PTRACE_CONT, child, 0, 0);
    status = wait_status(child, 0);
    printf("%s: signal=%d core=%d\n", name, WIFSIGNALED(status) ? WTERMSIG(status) : -1,
           WCOREDUMP(status) ? 1 : 0);
    unlink("core");
}

static int exit_core_case(void) {
    exit_core_round("core", RLIM_INFINITY);
    exit_core_round("no-core", 0);
    return 0;
}

/* --- ptrace-restart-codes --------------------------------------------- */

/* The restart code a tracer leaves in rax at the stop for the signal that
 * interrupted a read decides whether it runs again. */
static int restart_pipe[2];
static void restart_handler(int number) { (void)number; }

static long blocked_read(void) {
    char byte;
    long r = syscall(SYS_read, restart_pipe[0], &byte, 1);
    return r < 0 ? -errno : r;
}

/* Waits until the child sleeps, then sends it `number`, and stops it there;
 * shows rax, and leaves `rax` and `orig_rax` as asked (`keep` for none). */
static void interrupt(pid_t child, int number, long rax, long orig, int resume) {
    do usleep(10000);
    while (state_of(child) != 'S');
    kill(child, number);
    int status = wait_status(child, 0);
    struct user_regs_struct regs;
    pt(PTRACE_GETREGS, child, 0, (unsigned long)&regs);
    printf("stop=%d rax=%lld\n", WIFSTOPPED(status) ? WSTOPSIG(status) : -1,
           (long long)regs.rax);
    regs.rax = rax;
    if (orig) regs.orig_rax = orig;
    pt(PTRACE_SETREGS, child, 0, (unsigned long)&regs);
    pt(PTRACE_CONT, child, 0, resume);
}

static int restart_codes_case(void) {
    if (pipe(restart_pipe)) return 80;
    fflush(stdout);
    pid_t child = fork();
    if (child == 0) {
        struct sigaction plain = {.sa_handler = restart_handler};
        struct sigaction restarting = {.sa_handler = restart_handler, .sa_flags = SA_RESTART};
        sigaction(SIGUSR1, &plain, NULL);
        sigaction(SIGUSR2, &restarting, NULL);
        if (pt(PTRACE_TRACEME, 0, 0, 0)) _exit(90);
        syscall(SYS_tkill, syscall(SYS_gettid), SIGSTOP);
        long nointr = blocked_read();
        long nohand = blocked_read();
        long literal = blocked_read();
        long block = blocked_read();
        printf("nointr=%ld nohand=%ld literal=%ld block=%ld\n", nointr, nohand, literal, block);
        fflush(stdout);
        _exit(0);
    }
    wait_status(child, 0);
    pt(PTRACE_CONT, child, 0, 0);
    /* -ERESTARTSYS made -ERESTARTNOINTR: it runs again after the handler,
     * and reads the byte written meanwhile. */
    interrupt(child, SIGUSR1, -513, 0, SIGUSR1);
    write(restart_pipe[1], "x", 1);
    /* -ERESTARTNOHAND: EINTR after a handler, even an SA_RESTART one. */
    interrupt(child, SIGUSR2, -514, 0, SIGUSR2);
    /* orig_rax -1: no call to restart, and rax is what the read returns. */
    interrupt(child, SIGUSR1, -512, -1, SIGUSR1);
    /* -ERESTART_RESTARTBLOCK, the signal taken back so no handler runs:
     * restart_syscall, with nothing to resume, gives EINTR. */
    interrupt(child, SIGUSR1, -516, 0, 0);
    int status = wait_status(child, 0);
    printf("exit=%d\n", WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    return 0;
}

/* --- ptrace-selectors -------------------------------------------------- */

static int selectors_case(void) {
    fflush(stdout);
    pid_t child = fork();
    if (child == 0) {
        if (pt(PTRACE_TRACEME, 0, 0, 0)) _exit(90);
        syscall(SYS_tkill, syscall(SYS_gettid), SIGSTOP);
        _exit(0);
    }
    wait_status(child, 0);
    struct user_regs_struct regs;
    pt(PTRACE_GETREGS, child, 0, (unsigned long)&regs);
    printf("ds=%#llx es=%#llx fs=%#llx gs=%#llx cs=%#llx ss=%#llx\n", regs.ds, regs.es, regs.fs,
           regs.gs, regs.cs, regs.ss);
    long ds = offsetof(struct user_regs_struct, ds), cs = offsetof(struct user_regs_struct, cs);
    printf("poke-ds=%ld\n", pt(PTRACE_POKEUSER, child, ds, 0x2b));
    unsigned long word = 0;
    long peeked = pt(PTRACE_PEEKUSER, child, ds, (unsigned long)&word);
    printf("peek-ds=%ld word=%#lx\n", peeked, word);
    printf("poke-ds-kernel=%ld\n", pt(PTRACE_POKEUSER, child, ds, 0x10));
    printf("poke-cs-null=%ld\n", pt(PTRACE_POKEUSER, child, cs, 0));
    pt(PTRACE_GETREGS, child, 0, (unsigned long)&regs);
    regs.es = 0x1002b;
    printf("setregs=%ld\n", pt(PTRACE_SETREGS, child, 0, (unsigned long)&regs));
    pt(PTRACE_GETREGS, child, 0, (unsigned long)&regs);
    printf("ds=%#llx es=%#llx\n", regs.ds, regs.es);
    pt(PTRACE_CONT, child, 0, 0);
    int status = wait_status(child, 0);
    printf("exit=%d\n", WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    return 0;
}

/* --- ptrace-suspend-seccomp -------------------------------------------- */

/* A tracer under seccomp may not suspend its tracee's (EPERM), whatever
 * its capabilities. */
static int suspend_seccomp_case(void) {
    fflush(stdout);
    pid_t child = fork();
    if (child == 0) {
        if (pt(PTRACE_TRACEME, 0, 0, 0)) _exit(90);
        syscall(SYS_tkill, syscall(SYS_gettid), SIGSTOP);
        _exit(0);
    }
    wait_status(child, 0);
    struct sock_filter code[] = {BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)};
    struct sock_fprog program = {1, code};
    printf("no-new-privs=%d\n", prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0));
    printf("filter=%ld\n", syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &program));
    printf("setoptions=%ld\n", pt(PTRACE_SETOPTIONS, child, 0, 1 << 21));
    pt(PTRACE_CONT, child, 0, 0);
    int status = wait_status(child, 0);
    printf("exit=%d\n", WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 3) return 99;
    const char *mode = argv[1];
    setvbuf(stdout, NULL, _IOFBF, 1 << 16);
    int code = 98;
    if (!strcmp(mode, "ptrace-sigmask")) code = sigmask_case();
    if (!strcmp(mode, "ptrace-listen")) code = listen_case();
    if (!strcmp(mode, "ptrace-seccomp")) code = seccomp_case();
    if (!strcmp(mode, "ptrace-arch-rseq")) code = arch_rseq_case();
    if (!strcmp(mode, "ptrace-syscall-signal")) code = syscall_signal_case();
    if (!strcmp(mode, "ptrace-exit-core")) code = exit_core_case();
    if (!strcmp(mode, "ptrace-restart-codes")) code = restart_codes_case();
    if (!strcmp(mode, "ptrace-selectors")) code = selectors_case();
    if (!strcmp(mode, "ptrace-suspend-seccomp")) code = suspend_seccomp_case();
    fflush(stdout);
    return code;
}
