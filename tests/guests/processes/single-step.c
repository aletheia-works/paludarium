/* The trap flag and int3, compared with native Linux on x86-64: the
 * single-step traps a guest gets after it sets TF itself with popf, across
 * a syscall and a signal handler, the SIGTRAP of int3, and a tracer's
 * PTRACE_SINGLESTEP and PTRACE_SYSEMU_SINGLESTEP. The instruction
 * sequences are written in assembly, so that each trap's address is known:
 * an address is printed only as its offset into its sequence. */
#define _GNU_SOURCE
#include <errno.h>
#include <stddef.h>
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
        /* rep stosb of 3 bytes at rdi with TF set: a trap after each
         * iteration. */
        ".globl seq_rep, seq_rep_end\n"
        "seq_rep:\n"
        "  pushfq\n"
        "  orq $0x100, (%rsp)\n"
        "  popfq\n"
        "  movl $3, %ecx\n"
        "  rep stosb\n"
        "  pushfq\n"
        "  andq $~0x100, (%rsp)\n"
        "  popfq\n"
        "seq_rep_end:\n"
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
        "  ret\n"
        /* kill(rdi, SIGSTOP), then kill(rdi, SIGUSR1) for a tracer to step
         * into the handler, and the rest stepped by the flag the frame
         * gives back. */
        ".globl seq_frame, seq_frame_end\n"
        "seq_frame:\n"
        "  movl $19, %esi\n"
        "  movl $62, %eax\n"
        "  syscall\n"
        "  movl $10, %esi\n"
        "  movl $62, %eax\n"
        "  syscall\n"
        "  nop\n"
        "  pushfq\n"
        "  andq $~0x100, (%rsp)\n"
        "  popfq\n"
        "seq_frame_end:\n"
        "  ret\n"
        /* kill(rdi, SIGSTOP), then an instruction an execute breakpoint
         * watches, a write and a read of `watched`. */
        ".globl seq_hw, seq_hw_exec, seq_hw_end\n"
        "seq_hw:\n"
        "  movl $19, %esi\n"
        "  movl $62, %eax\n"
        "  syscall\n"
        "  nop\n"
        "seq_hw_exec:\n"
        "  movl $1, %ecx\n"
        "  movq %rcx, watched(%rip)\n"
        "  movq watched(%rip), %rdx\n"
        "seq_hw_end:\n"
        "  ret\n"
        /* kill(rdi, SIGSTOP), then an fxsave, an xlat and a leave whose
         * memory breakpoints watch; the callee-saved registers are kept. */
        ".globl seq_hw2, seq_hw2_end\n"
        "seq_hw2:\n"
        "  pushq %rbx\n"
        "  pushq %rbp\n"
        "  pushq %r12\n"
        "  movl $19, %esi\n"
        "  movl $62, %eax\n"
        "  syscall\n"
        "  leaq fxarea(%rip), %rax\n"
        "  fxsave (%rax)\n"
        "  leaq table(%rip), %rbx\n"
        "  movl $8, %eax\n"
        "  xlat\n"
        "  movq %rsp, %r12\n"
        "  leaq leaveslot(%rip), %rbp\n"
        "  leave\n"
        "  movq %r12, %rsp\n"
        "seq_hw2_end:\n"
        "  popq %r12\n"
        "  popq %rbp\n"
        "  popq %rbx\n"
        "  ret\n"
        ".data\n"
        ".balign 8\n"
        ".globl watched\n"
        "watched: .quad 0\n"
        ".balign 16\n"
        ".globl fxarea, table, leaveslot\n"
        "fxarea: .zero 512\n"
        "table: .zero 16\n"
        "leaveslot: .quad 0\n"
        ".text\n");

void seq_rep(char *);
extern char seq_rep_end[];
void seq_flag(void), seq_syscall(void), seq_signal(int), seq_int3(void), seq_trace(int),
    seq_frame(int), seq_hw(int);
extern char seq_hw_exec[], seq_hw_end[], seq_hw2_end[], fxarea[], table[], leaveslot[];
void seq_hw2(int);
extern uint64_t watched;
extern char seq_flag_end[], seq_syscall_end[], seq_signal_end[], seq_int3_end[], seq_trace_from[],
    seq_trace_end[], seq_frame_end[];

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

static int rep_case(void) {
    static char buffer[8];
    install();
    seq_rep(buffer);
    report("rep", (void *)seq_rep, seq_rep_end);
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

/* A tracee stepped into a handler: stepping ends there, so the handler's
 * frame keeps no trap flag the tracer set, and nothing traps once the
 * tracer lets it run. */
static void frame_handler(int number) { (void)number; }

static int forced_frame_case(void) {
    fflush(stdout);
    pid_t child = fork();
    if (child == 0) {
        signal(SIGUSR1, frame_handler);
        if (pt(PTRACE_TRACEME, 0, 0, 0)) _exit(90);
        seq_frame(getpid());
        _exit((flags_now() & TF) ? 1 : 0);
    }
    uint64_t start = (uint64_t)(uintptr_t)seq_frame, end = (uint64_t)(uintptr_t)seq_frame_end;
    wait_status(child);
    int status = 0;
    struct user_regs_struct regs;
    siginfo_t info;
    /* Step to the stop for SIGUSR1. */
    for (int i = 0; i < 20; i++) {
        pt(PTRACE_SINGLESTEP, child, 0, 0);
        status = wait_status(child);
        if (!WIFSTOPPED(status) || WSTOPSIG(status) == SIGUSR1) break;
        memset(&info, 0, sizeof info);
        pt(PTRACE_GETSIGINFO, child, 0, (unsigned long)&info);
        pt(PTRACE_GETREGS, child, 0, (unsigned long)&regs);
        printf("step: signal=%d code=%#x at=%lld\n", WSTOPSIG(status), info.si_code,
               (long long)(regs.rip - start));
    }
    printf("delivery: signal=%d\n", WIFSTOPPED(status) ? WSTOPSIG(status) : -1);
    /* Into the handler: the stop before it. */
    pt(PTRACE_SINGLESTEP, child, 0, SIGUSR1);
    status = wait_status(child);
    memset(&info, 0, sizeof info);
    pt(PTRACE_GETSIGINFO, child, 0, (unsigned long)&info);
    pt(PTRACE_GETREGS, child, 0, (unsigned long)&regs);
    printf("handler: signal=%d code=%#x in-handler=%d tf-shown=%d\n", WSTOPSIG(status),
           info.si_code, regs.rip == (uint64_t)(uintptr_t)frame_handler, (regs.eflags & TF) != 0);
    /* Let run: rt_sigreturn gives back no flag. */
    for (int i = 0; i < 10; i++) {
        pt(PTRACE_CONT, child, 0, 0);
        status = wait_status(child);
        if (!WIFSTOPPED(status)) break;
        memset(&info, 0, sizeof info);
        pt(PTRACE_GETSIGINFO, child, 0, (unsigned long)&info);
        pt(PTRACE_GETREGS, child, 0, (unsigned long)&regs);
        printf("after: signal=%d code=%#x at=", WSTOPSIG(status), info.si_code);
        if (regs.rip >= start && regs.rip <= end)
            printf("%llu", (unsigned long long)(regs.rip - start));
        else
            printf("outside");
        printf(" tf-shown=%d\n", (regs.eflags & TF) != 0);
    }
    printf("exit=%d\n", WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    return 0;
}

/* --- hardware breakpoints ------------------------------------------------ */

#define DEBUGREG(n) (offsetof(struct user, u_debugreg) + (n) * 8)

static long peek_debug(pid_t child, int n) {
    unsigned long word = 0;
    long r = pt(PTRACE_PEEKUSER, child, DEBUGREG(n), (unsigned long)&word);
    return r ? r : (long)word;
}

/* One stop of the breakpoint case: why, where in seq_hw, and DR6. */
static void hw_stop(pid_t child, const char *name) {
    int status = wait_status(child);
    if (!WIFSTOPPED(status)) {
        printf("%s: exited=%d\n", name, WIFEXITED(status) ? WEXITSTATUS(status) : -1);
        return;
    }
    siginfo_t info;
    memset(&info, 0, sizeof info);
    pt(PTRACE_GETSIGINFO, child, 0, (unsigned long)&info);
    struct user_regs_struct regs;
    pt(PTRACE_GETREGS, child, 0, (unsigned long)&regs);
    uint64_t start = (uint64_t)(uintptr_t)seq_hw;
    printf("%s: signal=%d code=%d at=%lld addr-is-rip=%d rf=%d dr6=%#lx\n", name, WSTOPSIG(status),
           info.si_code, (long long)(regs.rip - start),
           (uint64_t)(uintptr_t)info.si_addr == regs.rip, (int)(regs.eflags >> 16 & 1),
           (unsigned long)peek_debug(child, 6));
}

static int hw_breakpoint_case(void) {
    fflush(stdout);
    pid_t child = fork();
    if (child == 0) {
        if (pt(PTRACE_TRACEME, 0, 0, 0)) _exit(90);
        seq_hw(getpid());
        _exit(watched == 1 ? 0 : 1);
    }
    wait_status(child);
    printf("dr0=%ld dr6=%#lx dr7=%ld\n", peek_debug(child, 0), (unsigned long)peek_debug(child, 6),
           peek_debug(child, 7));
    /* One step first: DR6 then has the step. */
    pt(PTRACE_SINGLESTEP, child, 0, 0);
    hw_stop(child, "step");
    unsigned long exec = (unsigned long)seq_hw_exec, data = (unsigned long)&watched;
    printf("poke-dr0=%ld\n", pt(PTRACE_POKEUSER, child, DEBUGREG(0), exec));
    printf("poke-dr1=%ld\n", pt(PTRACE_POKEUSER, child, DEBUGREG(1), data));
    printf("poke-dr4=%ld\n", pt(PTRACE_POKEUSER, child, DEBUGREG(4), 0));
    printf("poke-kernel=%ld\n", pt(PTRACE_POKEUSER, child, DEBUGREG(2), 1UL << 63));
    /* DR0 executes; DR1 is an 8-byte write; an I/O one and a long
     * execute one are refused, and leave DR7 as it was. */
    unsigned long dr7 = 1 | 1 << 2 | 0x9UL << 20;
    printf("poke-dr7-io=%ld\n", pt(PTRACE_POKEUSER, child, DEBUGREG(7), 1 | 0x2UL << 16));
    printf("poke-dr7-long=%ld\n", pt(PTRACE_POKEUSER, child, DEBUGREG(7), 1 | 0x4UL << 16));
    printf("poke-dr7=%ld\n", pt(PTRACE_POKEUSER, child, DEBUGREG(7), dr7));
    printf("dr7=%#lx misaligned=%ld\n", (unsigned long)peek_debug(child, 7),
           pt(PTRACE_POKEUSER, child, DEBUGREG(1), data + 4));
    pt(PTRACE_CONT, child, 0, 0);
    hw_stop(child, "execute");
    pt(PTRACE_CONT, child, 0, 0);
    hw_stop(child, "write");
    /* DR1 now reads or writes, DR0 off: the read hits. */
    pt(PTRACE_POKEUSER, child, DEBUGREG(7), 1 << 2 | 0xbUL << 20);
    pt(PTRACE_CONT, child, 0, 0);
    hw_stop(child, "read");
    pt(PTRACE_POKEUSER, child, DEBUGREG(7), 0);
    pt(PTRACE_CONT, child, 0, 0);
    hw_stop(child, "end");
    return 0;
}

/* Data breakpoints on an fxsave's area, an xlat's table entry and the
 * word a leave pops. */
static void hw2_stop(pid_t child, const char *name) {
    int status = wait_status(child);
    if (!WIFSTOPPED(status)) {
        printf("%s: exited=%d\n", name, WIFEXITED(status) ? WEXITSTATUS(status) : -1);
        return;
    }
    siginfo_t info;
    memset(&info, 0, sizeof info);
    pt(PTRACE_GETSIGINFO, child, 0, (unsigned long)&info);
    struct user_regs_struct regs;
    pt(PTRACE_GETREGS, child, 0, (unsigned long)&regs);
    printf("%s: signal=%d code=%d at=%lld dr6=%#lx\n", name, WSTOPSIG(status), info.si_code,
           (long long)(regs.rip - (uint64_t)(uintptr_t)seq_hw2), (unsigned long)peek_debug(child, 6));
}

static int hw_implicit_case(void) {
    fflush(stdout);
    pid_t child = fork();
    if (child == 0) {
        if (pt(PTRACE_TRACEME, 0, 0, 0)) _exit(90);
        seq_hw2(getpid());
        _exit(0);
    }
    wait_status(child);
    /* DR0: XMM0 in the fxsave area, which it writes; DR3: its last bytes,
     * which it leaves to software and never writes. */
    pt(PTRACE_POKEUSER, child, DEBUGREG(0), (unsigned long)(fxarea + 160));
    pt(PTRACE_POKEUSER, child, DEBUGREG(1), (unsigned long)(table + 8));
    pt(PTRACE_POKEUSER, child, DEBUGREG(2), (unsigned long)leaveslot);
    pt(PTRACE_POKEUSER, child, DEBUGREG(3), (unsigned long)(fxarea + 504));
    /* DR0 and DR3: 8-byte writes; DR1: a 1-byte read or write; DR2: an
     * 8-byte read or write. */
    unsigned long dr7 = 1 | 1 << 2 | 1 << 4 | 1 << 6 | 0x9UL << 16 | 0x3UL << 20 | 0xbUL << 24 |
                        0x9UL << 28;
    printf("dr7=%ld\n", pt(PTRACE_POKEUSER, child, DEBUGREG(7), dr7));
    pt(PTRACE_CONT, child, 0, 0);
    hw2_stop(child, "fxsave");
    pt(PTRACE_CONT, child, 0, 0);
    hw2_stop(child, "xlat");
    pt(PTRACE_CONT, child, 0, 0);
    hw2_stop(child, "leave");
    pt(PTRACE_POKEUSER, child, DEBUGREG(7), 0);
    pt(PTRACE_CONT, child, 0, 0);
    hw2_stop(child, "end");
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
    if (!strcmp(mode, "trap-flag-rep")) code = rep_case();
    if (!strcmp(mode, "ptrace-singlestep")) code = ptrace_case();
    if (!strcmp(mode, "ptrace-forced-frame")) code = forced_frame_case();
    if (!strcmp(mode, "ptrace-hw-breakpoint")) code = hw_breakpoint_case();
    if (!strcmp(mode, "ptrace-hw-implicit")) code = hw_implicit_case();
    fflush(stdout);
    return code;
}
