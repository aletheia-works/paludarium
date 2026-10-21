/* Data movement and control transfer: mov (all core forms), movabs, movsx,
 * movsxd, movzx, cdqe, lea, xchg, push/pop, call/jmp (direct, register,
 * memory), ret, and the nop forms (multi-byte, cs-prefixed, xchg ax,ax,
 * endbr64). None of these change flags; flags are printed to prove it. */
#include "insn.h"

static u64 target_value;
static void target(void) { target_value += 1; }
static void (*volatile target_ptr)(void) = target;

int test_main(void) {
    for (u64 i = 0; i < NVEC; i++) {
        u64 v = vectors[i], r, m;
        u32 m32;
        u16 m16;
        u8 m8;

        r = 0xcccccccccccccccc;
        __asm__ volatile("mov %k[v], %k[r]" : [r] "+r"(r) : [v] "r"(v));
        report_value("mov32rr", r);
        __asm__ volatile("mov %[v], %[r]" : [r] "=r"(r) : [v] "r"(v));
        report_value("mov64rr", r);
        m = 0xcccccccccccccccc;
        __asm__ volatile("movq %[v], %[m]" : [m] "=m"(m) : [v] "r"(v));
        report_value("mov64mr", m);
        m = 0xcccccccccccccccc;
        __asm__ volatile("movl %k[v], %k[m]" : [m] "+m"(m) : [v] "r"(v));
        report_value("mov32mr", m);
        m = 0xcccccccccccccccc;
        __asm__ volatile("movw %w[v], %[m]" : [m] "+m"(m) : [v] "r"(v));
        report_value("mov16mr", m);
        m = 0xcccccccccccccccc;
        __asm__ volatile("movb %b[v], %[m]" : [m] "+m"(m) : [v] "r"(v));
        report_value("mov8mr", m);
        r = 0xcccccccccccccccc;
        m = v;
        __asm__ volatile("movl %[m], %k[r]" : [r] "+r"(r) : [m] "m"(m));
        report_value("mov32rm", r);
        __asm__ volatile("movq %[m], %[r]" : [r] "=r"(r) : [m] "m"(m));
        report_value("mov64rm", r);

        m32 = (u32)v;
        m16 = (u16)v;
        m8 = (u8)v;
        __asm__ volatile("movsbl %[m], %k[r]" : [r] "=r"(r) : [m] "m"(m8));
        report_value("movsx32m8", r);
        __asm__ volatile("movslq %[m], %[r]" : [r] "=r"(r) : [m] "m"(m32));
        report_value("movsxd64m32", r);
        __asm__ volatile("movslq %k[v], %[r]" : [r] "=r"(r) : [v] "r"(v));
        report_value("movsxd64r32", r);
        r = 0xcccccccccccccccc;
        __asm__ volatile("movzbl %[m], %k[r]" : [r] "+r"(r) : [m] "m"(m8));
        report_value("movzx32m8", r);
        __asm__ volatile("movzwl %[m], %k[r]" : [r] "+r"(r) : [m] "m"(m16));
        report_value("movzx32m16", r);
        __asm__ volatile("movzbl %b[v], %k[r]" : [r] "+r"(r) : [v] "r"(v));
        report_value("movzx32r8", r);
        r = v;
        __asm__ volatile("cltq" : "+a"(r));
        report_value("cdqe", r);

        __asm__ volatile("lea 0x10(%[v],%[v],4), %[r]" : [r] "=r"(r) : [v] "r"(v));
        report_value("lea64", r);
        __asm__ volatile("lea -1(%[v]), %k[r]" : [r] "=r"(r) : [v] "r"(v));
        report_value("lea32", r);

        u64 x = v, y = 0x5a5a5a5a5a5a5a5a;
        m = 0x0123456789abcdef;
        __asm__ volatile("xchg %k[x], %k[m]" : [x] "+r"(x), [m] "+m"(m));
        report("xchg32m", v, 0, 0, x, m, ~0UL);
        __asm__ volatile("xchg %[x], %[y]" : [x] "+r"(x), [y] "+r"(y));
        report("xchg64rr", v, 0, 0, x, y, ~0UL);

        __asm__ volatile("push %[v]\n\tpop %[r]" : [r] "=r"(r) : [v] "r"(v) : "memory");
        report_value("pushpop", r);
    }

    u64 r, f;
    __asm__ volatile("movabs $0x123456789abcdef0, %[r]" : [r] "=r"(r));
    report_value("movabs", r);
    __asm__ volatile("mov $-5, %[r]" : [r] "=r"(r));
    report_value("mov64i", r);
    __asm__ volatile("mov $0xfffffff0, %k[r]" : [r] "=r"(r));
    report_value("mov32i", r);
    u64 m = 0;
    __asm__ volatile("movq $-2, %[m]" : [m] "+m"(m));
    report_value("mov64mi", m);
    m = 0xcccccccccccccccc;
    __asm__ volatile("movl $0x12345678, %[m]" : [m] "+m"(m));
    report_value("mov32mi", m);
    m = 0xcccccccccccccccc;
    __asm__ volatile("movb $0x7f, %[m]" : [m] "+m"(m));
    report_value("mov8mi", m);
    __asm__ volatile("push $-3\n\tpop %[r]" : [r] "=r"(r) : : "memory");
    report_value("pushimm8", r);
    __asm__ volatile("push $0x12345678\n\tpop %[r]" : [r] "=r"(r) : : "memory");
    report_value("pushimm32", r);

    /* Control transfer: direct, register and memory indirect calls, jmp. */
    target_value = 0;
    target();
    void (*fp)(void) = target_ptr;
    __asm__ volatile("call *%[f]" : : [f] "r"(fp) : "rax", "rcx", "rdx", "rsi", "rdi",
                     "r8", "r9", "r10", "r11", "memory", "cc");
    __asm__ volatile("call *%[f]" : : [f] "m"(target_ptr) : "rax", "rcx", "rdx", "rsi",
                     "rdi", "r8", "r9", "r10", "r11", "memory", "cc");
    report_value("calls", target_value);
    __asm__ volatile("lea 1f(%%rip), %[r]\n\tjmp *%[r]\n\tmov $0, %[r]\n1:\n\t"
                     "mov $7, %[r]"
                     : [r] "=&r"(r));
    report_value("jmpreg", r);
    static void *const jump_slot = &&after_jump;
    __asm__ goto("jmp *%0" : : "m"(jump_slot) : : after_jump);
    report_value("jmpmem", 0);
after_jump:
    report_value("jmpmem", 1);

    /* nop forms keep every register and flag. */
    r = 0x77;
    __asm__ volatile("push %[fi]\n\tpopfq\n\t"
                     "nopl 0x0(%%rax,%%rax,1)\n\t"
                     "nopw 0x0(%%rax,%%rax,1)\n\t"
                     "nopl 0x0(%%rax)\n\t"
                     ".byte 0x2e, 0x66, 0x0f, 0x1f, 0x84, 0x00, 0, 0, 0, 0\n\t"
                     ".byte 0x66, 0x90\n\t"
                     ".byte 0xf3, 0x0f, 0x1e, 0xfa\n\t"
                     "nop\n\t"
                     "pushfq\n\tpop %[f]"
                     : [f] "=&r"(f), [r] "+r"(r)
                     : [fi] "r"(F_ARITH)
                     : "cc", "memory");
    report("nops", 0, 0, F_ARITH, r, f, F_ARITH);
    flush_out();
    return 0;
}
