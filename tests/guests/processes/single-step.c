/* The trap flag and int3, compared with native Linux on x86-64: the
 * single-step traps a guest gets after it sets TF itself with popf, across
 * a syscall and a signal handler, the SIGTRAP of int3, and a tracer's
 * PTRACE_SINGLESTEP and PTRACE_SYSEMU_SINGLESTEP. The instruction
 * sequences are written in assembly, so that each trap's address is known:
 * an address is printed only as its offset into its sequence. */
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <ucontext.h>
#include <unistd.h>

#define TF 0x100

/* Each sequence turns TF on with popf, runs a few instructions, and turns
 * it off again; `seq_*_end` is its last instruction. */
__asm__(".text\n"
        /* popf sets TF: no trap after it; one after each instruction
         * after, the popf that clears TF included. */
        ".globl seq_flag, seq_flag_end\n"
        "seq_flag:\n"
        "  pushfq\n"
        "  orq $0x100, (%rsp)\n"
        "  popfq\n"
        "  nop\n"
        "  movl $1, %eax\n"
        "  pushfq\n"
        "  andq $~0x100, (%rsp)\n"
        "  popfq\n"
        "seq_flag_end:\n"
        "  ret\n"
        /* A syscall with TF set. */
        ".globl seq_syscall, seq_syscall_end\n"
        "seq_syscall:\n"
        "  pushfq\n"
        "  orq $0x100, (%rsp)\n"
        "  popfq\n"
        "  movl $39, %eax\n"
        "  syscall\n"
        "  nop\n"
        "  pushfq\n"
        "  andq $~0x100, (%rsp)\n"
        "  popfq\n"
        "seq_syscall_end:\n"
        "  ret\n"
        /* kill(rdi, SIGUSR1), whose handler runs without TF, then int3. */
        ".globl seq_signal, seq_signal_end\n"
        "seq_signal:\n"
        "  pushfq\n"
        "  orq $0x100, (%rsp)\n"
        "  popfq\n"
        "  movl $10, %esi\n"
        "  movl $62, %eax\n"
        "  syscall\n"
        "  int3\n"
        "  nop\n"
        "  pushfq\n"
        "  andq $~0x100, (%rsp)\n"
        "  popfq\n"
        "seq_signal_end:\n"
        "  ret\n"
        /* int3 alone. */
        ".globl seq_int3, seq_int3_end\n"
        "seq_int3:\n"
        "  nop\n"
        "  int3\n"
        "seq_int3_end:\n"
        "  ret\n"
        /* kill(rdi, SIGSTOP) for a tracer to step from: it stops at
         * seq_trace_from. */
        ".globl seq_trace, seq_trace_from, seq_trace_end\n"
        "seq_trace:\n"
        "  movl $19, %esi\n"
        "  movl $62, %eax\n"
        "  syscall\n"
        "seq_trace_from:\n"
        "  nop\n"
        "  movl $1, %ecx\n"
        "  movl $39, %eax\n"
        "  syscall\n"
        "  nop\n"
        "  nop\n"
        "seq_trace_end:\n"
        "  ret\n");

void seq_flag(void), seq_syscall(void), seq_signal(int), seq_int3(void), seq_trace(int);
extern char seq_flag_end[], seq_syscall_end[], seq_signal_end[], seq_int3_end[], seq_trace_from[],
    seq_trace_end[];

/* What each SIGTRAP showed: where, why, and the flags. */
struct trap {
    uint64_t rip;
    int code, trapno, saved_tf, handler_tf, addr_is_rip;
};
static struct trap traps[32];
static volatile int trap_count;
static volatile int usr1_tf = -1;

static uint64_t flags_now(void) {
    uint64_t flags;
    __asm__ volatile("pushfq\n popq %0" : "=r"(flags));
    return flags;
}

static void on_trap(int number, siginfo_t *info, void *context) {
    (void)number;
    ucontext_t *uc = context;
    if (trap_count < 32) {
        struct trap *t = &traps[trap_count];
        t->rip = uc->uc_mcontext.gregs[REG_RIP];
        t->code = info->si_code;
        t->trapno = uc->uc_mcontext.gregs[REG_TRAPNO];
        t->saved_tf = (uc->uc_mcontext.gregs[REG_EFL] & TF) != 0;
        t->handler_tf = (flags_now() & TF) != 0;
        t->addr_is_rip = (uint64_t)(uintptr_t)info->si_addr == t->rip;
    }
    trap_count++;
}

static void on_usr1(int number) {
    (void)number;
    usr1_tf = (flags_now() & TF) != 0;
}

static void report(const char *name, void *start, void *end) {
    printf("%s: traps=%d\n", name, trap_count);
    for (int i = 0; i < trap_count && i < 32; i++) {
        struct trap *t = &traps[i];
        uint64_t s = (uint64_t)(uintptr_t)start, e = (uint64_t)(uintptr_t)end;
        if (t->rip >= s && t->rip <= e)
            printf("  at=%llu", (unsigned long long)(t->rip - s));
        else
            printf("  at=outside");
        printf(" code=%#x trapno=%d saved-tf=%d handler-tf=%d addr-is-rip=%d\n", t->code,
               t->trapno, t->saved_tf, t->handler_tf, t->addr_is_rip);
    }
    printf("%s: tf-after=%d\n", name, (flags_now() & TF) != 0);
    trap_count = 0;
}

static void install(void) {
    struct sigaction action = {.sa_sigaction = on_trap, .sa_flags = SA_SIGINFO};
    sigaction(SIGTRAP, &action, NULL);
    signal(SIGUSR1, on_usr1);
}

static int flag_case(void) {
    install();
    seq_flag();
    report("popf", (void *)seq_flag, seq_flag_end);
    return 0;
}

static int syscall_case(void) {
    install();
    seq_syscall();
    report("syscall", (void *)seq_syscall, seq_syscall_end);
    return 0;
}

static int signal_case(void) {
    install();
    seq_signal(getpid());
    report("signal", (void *)seq_signal, seq_signal_end);
    printf("usr1-handler-tf=%d\n", usr1_tf);
    return 0;
}

static int int3_case(void) {
    install();
    seq_int3();
    report("int3", (void *)seq_int3, seq_int3_end);
    return 0;
}

/* --- the tracer's single steps ------------------------------------------ */

static long pt(long request, pid_t pid, unsigned long addr, unsigned long data) {
    errno = 0;
    long r = syscall(SYS_ptrace, request, pid, addr, data);
    return r < 0 ? -errno : r;
}

static int wait_status(pid_t pid) {
    int status = 0;
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {
    }
    return status;
}

/* Steps `child` with `request` from seq_trace_from to seq_trace_end,
 * showing each stop. */
static void step_round(pid_t child, long request, const char *name) {
    uint64_t start = (uint64_t)(uintptr_t)seq_trace, end = (uint64_t)(uintptr_t)seq_trace_end;
    struct user_regs_struct regs;
    pt(PTRACE_GETREGS, child, 0, (unsigned long)&regs);
    printf("%s: stopped at=%llu\n", name, (unsigned long long)(regs.rip - start));
    for (int i = 0; i < 20 && regs.rip != end; i++) {
        long r = pt(request, child, 0, 0);
        int status = wait_status(child);
        if (r || !WIFSTOPPED(status)) {
            printf("%s: request=%ld status=%#x\n", name, r, status);
            return;
        }
        siginfo_t info;
        memset(&info, 0, sizeof info);
        pt(PTRACE_GETSIGINFO, child, 0, (unsigned long)&info);
        pt(PTRACE_GETREGS, child, 0, (unsigned long)&regs);
        printf("%s: signal=%#x code=%#x at=", name, WSTOPSIG(status), info.si_code);
        if (regs.rip >= start && regs.rip <= end)
            printf("%llu", (unsigned long long)(regs.rip - start));
        else
            printf("outside");
        /* rax only at a syscall-entry stop: elsewhere it may be a PID. */
        printf(" nr=%ld tf-shown=%d", (long)regs.orig_rax, (regs.eflags & TF) != 0);
        if (WSTOPSIG(status) == (SIGTRAP | 0x80)) printf(" rax=%lld", (long long)regs.rax);
        printf("\n");
    }
}

static int ptrace_case(void) {
    fflush(stdout);
    pid_t child = fork();
    if (child == 0) {
        if (pt(PTRACE_TRACEME, 0, 0, 0)) _exit(90);
        seq_trace(getpid());
        seq_trace(getpid());
        /* The trap flag the tracer set is gone. */
        _exit((flags_now() & TF) ? 1 : 0);
    }
    wait_status(child);
    step_round(child, PTRACE_SINGLESTEP, "singlestep");
    pt(PTRACE_CONT, child, 0, 0);
    wait_status(child);
    pt(PTRACE_SETOPTIONS, child, 0, PTRACE_O_TRACESYSGOOD);
    step_round(child, 32 /* PTRACE_SYSEMU_SINGLESTEP */, "sysemu-singlestep");
    pt(PTRACE_CONT, child, 0, 0);
    int status = wait_status(child);
    printf("exit=%d\n", WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) return 99;
    const char *mode = argv[1];
    setvbuf(stdout, NULL, _IOFBF, 1 << 16);
    int code = 98;
    if (!strcmp(mode, "trap-flag")) code = flag_case();
    if (!strcmp(mode, "trap-flag-syscall")) code = syscall_case();
    if (!strcmp(mode, "trap-flag-signal")) code = signal_case();
    if (!strcmp(mode, "int3")) code = int3_case();
    if (!strcmp(mode, "ptrace-singlestep")) code = ptrace_case();
    fflush(stdout);
    return code;
}
