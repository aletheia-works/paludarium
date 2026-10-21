/*
 * Common helpers for the per-instruction differential-test guests.
 *
 * Each guest is built with -nostdlib (no libc): it provides its own _start,
 * runs one instruction family on fixed inputs and prints the resulting
 * registers, flags and memory as text. The same binary runs natively on
 * x86-64 Linux and under paludarium, and the harness compares the output
 * bytes, so the expected values always come from native execution
 * (team.md Testing Posture, Q6).
 *
 * Flags that x86 leaves undefined for an instruction are masked out before
 * printing; UNDEFINED.md lists what is not compared.
 */
#ifndef PALUDARIUM_INSN_H
#define PALUDARIUM_INSN_H

typedef unsigned long u64;
typedef unsigned int u32;
typedef unsigned short u16;
typedef unsigned char u8;

#define F_CF 0x0001UL
#define F_PF 0x0004UL
#define F_AF 0x0010UL
#define F_ZF 0x0040UL
#define F_SF 0x0080UL
#define F_DF 0x0400UL
#define F_OF 0x0800UL
#define F_ARITH (F_CF | F_PF | F_AF | F_ZF | F_SF | F_OF)
#define F_LOGIC (F_ARITH & ~F_AF) /* AF undefined for logical ops */

static long sys_write(int fd, const void *buf, u64 len) {
    long ret;
    __asm__ volatile("syscall"
                     : "=a"(ret)
                     : "a"(1L), "D"((long)fd), "S"(buf), "d"(len)
                     : "rcx", "r11", "memory");
    return ret;
}

static char out_buf[4096];
static u64 out_len;

static void flush_out(void) {
    if (out_len > 0) {
        sys_write(1, out_buf, out_len);
        out_len = 0;
    }
}

static void put_char(char c) {
    if (out_len == sizeof out_buf) {
        flush_out();
    }
    out_buf[out_len++] = c;
}

static void put_str(const char *s) {
    while (*s) {
        put_char(*s++);
    }
}

static void put_hex(u64 v) {
    static const char digits[] = "0123456789abcdef";
    put_char('0');
    put_char('x');
    for (int shift = 60; shift >= 0; shift -= 4) {
        put_char(digits[(v >> shift) & 0xf]);
    }
}

/* Prints "<name> <a> <b> fi=<in flags> -> <r> f=<flags & mask>\n". */
static void report(const char *name, u64 a, u64 b, u64 fin, u64 r, u64 flags, u64 mask) {
    put_str(name);
    put_char(' ');
    put_hex(a);
    put_char(' ');
    put_hex(b);
    put_str(" fi=");
    put_hex(fin);
    put_str(" -> ");
    put_hex(r);
    put_str(" f=");
    put_hex(flags & mask);
    put_char('\n');
}

/* Prints "<name> <value>\n". */
static void report_value(const char *name, u64 v) {
    put_str(name);
    put_char(' ');
    put_hex(v);
    put_char('\n');
}

static const u64 vectors[] = {
    0x0000000000000000UL, 0x0000000000000001UL, 0x000000000000007fUL,
    0x0000000000000080UL, 0x00000000000000ffUL, 0x0000000000008000UL,
    0x000000007fffffffUL, 0x0000000080000000UL, 0x00000000ffffffffUL,
    0x7fffffffffffffffUL, 0x8000000000000000UL, 0xffffffffffffffffUL,
    0x0123456789abcdefUL, 0xfedcba9876543210UL,
};
#define NVEC (sizeof vectors / sizeof vectors[0])

/* Input flag states: all clear, and all arithmetic flags set. */
static const u64 flag_inputs[] = {0x0UL, F_ARITH};
#define NFIN 2

/* Two-operand register form: dst = a, src = b, "op %src, %dst". */
#define BIN_RR(label, op, sz, mask)                                           \
    for (u64 i = 0; i < NVEC; i++)                                            \
        for (u64 j = 0; j < NVEC; j++)                                        \
            for (u64 k = 0; k < NFIN; k++) {                                  \
                u64 a = vectors[i], b = vectors[j], f, fi = flag_inputs[k];   \
                __asm__ volatile("push %[fi]\n\tpopfq\n\t" op " %" sz         \
                                 "[b], %" sz "[a]\n\tpushfq\n\tpop %[f]"      \
                                 : [a] "+r"(a), [f] "=&r"(f)                  \
                                 : [b] "r"(b), [fi] "r"(fi)                   \
                                 : "cc", "memory");                          \
                report(label, vectors[i], b, fi, a, f, mask);                 \
            }

/* Register destination, immediate source. */
#define BIN_RI(label, op, sz, imm, mask)                                      \
    for (u64 i = 0; i < NVEC; i++)                                            \
        for (u64 k = 0; k < NFIN; k++) {                                      \
            u64 a = vectors[i], f, fi = flag_inputs[k];                       \
            __asm__ volatile("push %[fi]\n\tpopfq\n\t" op " $" imm ", %" sz   \
                             "[a]\n\tpushfq\n\tpop %[f]"                      \
                             : [a] "+r"(a), [f] "=&r"(f)                      \
                             : [fi] "r"(fi)                                   \
                             : "cc", "memory");                              \
            report(label, vectors[i], 0, fi, a, f, mask);                     \
        }

/* Memory destination, register source ("op %src, mem"). */
#define BIN_MR(label, op, sz, mask)                                           \
    for (u64 i = 0; i < NVEC; i++)                                            \
        for (u64 j = 0; j < NVEC; j += 3) {                                   \
            u64 m = vectors[i], b = vectors[j], f, fi = 0;                    \
            __asm__ volatile("push %[fi]\n\tpopfq\n\t" op " %" sz             \
                             "[b], %[m]\n\tpushfq\n\tpop %[f]"                \
                             : [m] "+m"(m), [f] "=&r"(f)                      \
                             : [b] "r"(b), [fi] "r"(fi)                       \
                             : "cc", "memory");                              \
            report(label, vectors[i], b, fi, m, f, mask);                     \
        }

/* Register destination, memory source ("op mem, %dst"). */
#define BIN_RM(label, op, sz, mask)                                           \
    for (u64 i = 0; i < NVEC; i++)                                            \
        for (u64 j = 0; j < NVEC; j += 3) {                                   \
            u64 a = vectors[i], m = vectors[j], f, fi = 0;                    \
            __asm__ volatile("push %[fi]\n\tpopfq\n\t" op " %[m], %" sz       \
                             "[a]\n\tpushfq\n\tpop %[f]"                      \
                             : [a] "+r"(a), [f] "=&r"(f)                      \
                             : [m] "m"(m), [fi] "r"(fi)                       \
                             : "cc", "memory");                              \
            report(label, vectors[i], m, fi, a, f, mask);                     \
        }

/* Memory destination, immediate source. */
#define BIN_MI(label, op, imm, mask)                                          \
    for (u64 i = 0; i < NVEC; i++) {                                          \
        u64 m = vectors[i], f, fi = 0;                                        \
        __asm__ volatile("push %[fi]\n\tpopfq\n\t" op " $" imm                \
                         ", %[m]\n\tpushfq\n\tpop %[f]"                       \
                         : [m] "+m"(m), [f] "=&r"(f)                          \
                         : [fi] "r"(fi)                                       \
                         : "cc", "memory");                                  \
        report(label, vectors[i], 0, fi, m, f, mask);                         \
    }

/* One-operand register form ("op %dst"). */
#define UN_R(label, op, sz, mask)                                             \
    for (u64 i = 0; i < NVEC; i++)                                            \
        for (u64 k = 0; k < NFIN; k++) {                                      \
            u64 a = vectors[i], f, fi = flag_inputs[k];                       \
            __asm__ volatile("push %[fi]\n\tpopfq\n\t" op " %" sz             \
                             "[a]\n\tpushfq\n\tpop %[f]"                      \
                             : [a] "+r"(a), [f] "=&r"(f)                      \
                             : [fi] "r"(fi)                                   \
                             : "cc", "memory");                              \
            report(label, vectors[i], 0, fi, a, f, mask);                     \
        }

/* One-operand memory form ("op mem"). */
#define UN_M(label, op, mask)                                                 \
    for (u64 i = 0; i < NVEC; i++)                                            \
        for (u64 k = 0; k < NFIN; k++) {                                      \
            u64 m = vectors[i], f, fi = flag_inputs[k];                       \
            __asm__ volatile("push %[fi]\n\tpopfq\n\t" op                     \
                             " %[m]\n\tpushfq\n\tpop %[f]"                    \
                             : [m] "+m"(m), [f] "=&r"(f)                      \
                             : [fi] "r"(fi)                                   \
                             : "cc", "memory");                              \
            report(label, vectors[i], 0, fi, m, f, mask);                     \
        }

int test_main(void);

__asm__(".text\n"
        ".global _start\n"
        "_start:\n"
        "  xor %ebp, %ebp\n"
        "  and $-16, %rsp\n"
        "  call test_main\n"
        "  mov %eax, %edi\n"
        "  mov $231, %eax\n"
        "  syscall\n"
        "  hlt\n");

#endif
