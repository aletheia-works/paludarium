/* The x87 unit, compared with Linux: what process.c's x87 cases leave out.

   x87-transcendental: fsin, fcos, fsincos, fptan, fpatan, f2xm1, fyl2x and
   fyl2xp1. Intel's and AMD's CPUs agree on what is no number, on infinities
   and zeros, on values out of each instruction's range and on the stack,
   and there every bit is compared. A value they work out may differ between
   them in its last bit, and in C1, which goes by what they worked out: such a
   result must be within one unit in the last place of the correctly rounded
   one in x87_transcendental.h, and its exceptions the same. The emulator
   gives that one, which its unit tests check. The long double functions of
   musl, which use these instructions, are compared rounded to double with
   the double ones, which use none.

   x87-decimal: fbstp in each rounding, of each kind of value, and fbld, of
   digits and of nibbles above 9.

   x87-state: the 16-bit fnstenv and fldenv (with 0x66), fnstenv with 0x66
   and REX.W both, fnsave and frstor of both sizes, and ffreep. Where the
   last instruction and operand were is left out: CPUs differ, and the
   emulator keeps none.

   x87-exceptions: what each instruction leaves where its exception is not
   masked, which SIGFPE then comes at the next instruction that waits, with
   its si_code, and the process it ends without a handler. */
#define _GNU_SOURCE
#include <math.h>
#include <signal.h>
#include <sys/wait.h>
#include <ucontext.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

struct x87_value {
    uint64_t mantissa;
    uint16_t high;
};
#include "x87_transcendental.h"

static const char *const ones[] = {"fsin", "fcos", "fsincos", "fptan", "f2xm1"};
static const char *const twos[] = {"fpatan", "fyl2x", "fyl2xp1"};
#define COUNT(array) ((int)(sizeof array / sizeof array[0]))

static void control(uint16_t word) {
    __asm__ volatile("fninit\n fldcw %0" : : "m"(word));
}
/* One instruction on st(0), or on st(1) and st(0), from a clean state with
   the given control word: its results, top first, and the status word. With
   `unordered`, C0, C2 and C3 are set before it, to see which it keeps. */
static uint16_t run(const char *op, uint16_t word, const struct x87_value *a, const struct x87_value *b,
                    unsigned char out[2][10], int unordered) {
    static const struct x87_value nan = {0xc000000000000000ULL, 0x7fff};
    uint16_t sw;
    control(word);
    if (unordered) __asm__ volatile("fldt %0\n fldz\n fucompp" : : "m"(nan));
    __asm__ volatile("fldt %0" : : "m"(*a));
    if (b) __asm__ volatile("fldt %0" : : "m"(*b));
    __asm__ volatile("fnclex");
#define RUN(name) else if (!strcmp(op, #name)) __asm__ volatile(#name "\n fnstsw %0" : "=m"(sw))
    if (0) {
    }
    RUN(fsin);
    RUN(fcos);
    RUN(fsincos);
    RUN(fptan);
    RUN(f2xm1);
    RUN(fpatan);
    RUN(fyl2x);
    RUN(fyl2xp1);
    __asm__ volatile("fstpt %0\n fstpt %1" : "=m"(out[0]), "=m"(out[1]));
    control(0x37f);
    return sw;
}
static void put(const unsigned char *bytes) {
    for (int i = 9; i >= 0; i--) printf("%02x", bytes[i]);
}
/* C1 says only which way the CPU's own result went, where it noted PE. */
static uint16_t shown(uint16_t sw) {
    return sw & 0x20 ? sw & ~0x200 : sw;
}
static struct x87_value parse(const char *hex) {
    struct x87_value v = {0, 0};
    for (int i = 0; hex[i]; i++) {
        unsigned digit = hex[i] <= '9' ? (unsigned)(hex[i] - '0') : (unsigned)(hex[i] - 'a' + 10);
        v.high = (uint16_t)(v.high << 4 | v.mantissa >> 60);
        v.mantissa = v.mantissa << 4 | digit;
    }
    return v;
}
/* Where a value stands among those of its sign, so that neighbours are one
   apart, the largest denormal and the smallest normal too. */
static __int128 place(struct x87_value v) {
    unsigned exponent = v.high & 0x7fff;
    __int128 p = exponent ? ((__int128)(exponent - 1) << 63) + v.mantissa : (__int128)v.mantissa;
    return v.high & 0x8000 ? -p : p;
}
static struct x87_value bytes_value(const unsigned char *bytes) {
    struct x87_value v;
    memcpy(&v.mantissa, bytes, 8);
    memcpy(&v.high, bytes + 8, 2);
    return v;
}
static int results_of(const char *op) {
    return !strcmp(op, "fsincos") || !strcmp(op, "fptan") ? 2 : 1;
}
static int two_of(const char *op) {
    return !strcmp(op, "fpatan") || !strncmp(op, "fyl2x", 5);
}

/* The values each instruction is given where the CPUs agree on every bit. */
static const struct x87_value special[] = {
    {0, 0}, {0, 0x8000},                                         /* zeros */
    {1ULL << 63, 0x7fff}, {1ULL << 63, 0xffff},                  /* infinities */
    {3ULL << 62, 0x7fff}, {0xc000000000000123ULL, 0xffff},        /* quiet NaNs */
    {0xa000000000000000ULL, 0x7fff},                             /* a signaling NaN */
    {1ULL << 62, 0x3fff}, {1ULL << 61, 0x7fff}, {0, 0x7fff},     /* unsupported */
    {1ULL << 63, 0x403e}, {1ULL << 63, 0xc03e}, {~0ULL, 0x7ffe}, /* 2^63, -2^63, the largest */
    {1ULL << 63, 0x403f}, {1ULL << 63, 0x4000}, {1ULL << 63, 0xc000}, /* 2^64, 2, -2 */
    {(1ULL << 63) | 1, 0x3fff}, {3ULL << 62, 0xbfff},            /* just above 1, -1.5 */
};
/* For the instructions of two, finite values too: those with a result the
   CPUs do not work out. */
static const struct x87_value partners[] = {
    {0, 0}, {0, 0x8000}, {1ULL << 63, 0x7fff}, {1ULL << 63, 0xffff}, {3ULL << 62, 0x7fff},
    {0xc000000000000123ULL, 0xffff}, {0xa000000000000000ULL, 0x7fff}, {1ULL << 62, 0x3fff},
    {1ULL << 63, 0x3fff}, {1ULL << 63, 0xbfff}, {1ULL << 63, 0x4000}, {1ULL << 63, 0x3ffe},
    {1, 0}, {0x7fffffffffffffffULL, 0x8000}, {1ULL << 63, 0x0001}, {1ULL << 63, 0xc03e},
};
static int is_finite(const struct x87_value *v) {
    unsigned exponent = v->high & 0x7fff;
    return exponent != 0x7fff && (exponent == 0 || v->mantissa >> 63);
}
static int zero(const struct x87_value *v) {
    return (v->high & 0x7fff) == 0 && v->mantissa == 0;
}
/* Whether the CPUs work out a result for these, which x87_transcendental.h
   then has. */
static int worked_out(const char *op, const struct x87_value *y, const struct x87_value *x) {
    if (!is_finite(y) || !is_finite(x) || zero(y) || zero(x)) return 0;
    int negative = x->high & 0x8000;
    int one = (x->high & 0x7fff) == 0x3fff && x->mantissa == 1ULL << 63;
    if (!strcmp(op, "fyl2x")) return !negative && !one;
    if (!strcmp(op, "fyl2xp1")) return !(negative && (x->high & 0x7fff) >= 0x3fff);
    return 1;
}

static void exact_cases(void) {
    unsigned char out[2][10];
    /* The values the instructions of one take as they are, or leave. */
    for (int k = 0; k < COUNT(ones); k++)
        for (int i = 0; i < COUNT(special); i++)
            for (int mode = 0; mode < 4; mode++) {
                const struct x87_value *a = &special[i];
                int trigonometric = ones[k][1] != '2';
                unsigned exponent = a->high & 0x7fff;
                /* Within range, a finite value that is not zero is worked out. */
                if (is_finite(a) && !zero(a) && (trigonometric ? exponent < 0x403e : exponent < 0x3fff ||
                                                   (exponent == 0x3fff && a->mantissa == 1ULL << 63)))
                    continue;
                uint16_t sw = run(ones[k], (uint16_t)(0x37f | mode << 10), a, NULL, out, mode == 3);
                printf("%s %d %d:", ones[k], i, mode);
                for (int r = 0; r < results_of(ones[k]); r++) {
                    printf(" ");
                    put(out[r]);
                }
                printf(" sw=%04x\n", shown(sw));
            }
    for (int k = 0; k < COUNT(twos); k++)
        for (int i = 0; i < COUNT(partners); i++)
            for (int j = 0; j < COUNT(partners); j++) {
                if (worked_out(twos[k], &partners[i], &partners[j])) continue;
                uint16_t sw = run(twos[k], 0x37f, &partners[i], &partners[j], out, (i + j) % 3 == 0);
                printf("%s %d %d: ", twos[k], i, j);
                put(out[0]);
                printf(" sw=%04x\n", shown(sw));
            }
    /* The stack: empty, with one register for the instructions of two, and
       full for the two that push. */
    static const struct x87_value values[] = {{0, 0}, {1ULL << 63, 0x403e}, {3ULL << 62, 0x7fff}, {1, 0}};
    for (int k = 0; k < COUNT(ones) + COUNT(twos); k++) {
        const char *op = k < COUNT(ones) ? ones[k] : twos[k - COUNT(ones)];
        unsigned char stack[3][10];
        uint16_t sw;
#define STACK(label, setup, form) do { \
            __asm__ volatile("fninit\n " setup "\n " form "\n fnstsw %0" : "=m"(sw)); \
            __asm__ volatile("fstpt %0\n fstpt %1\n fstpt %2" : "=m"(stack[0]), "=m"(stack[1]), "=m"(stack[2])); \
            printf("%s %s: ", label, op); \
            put(stack[0]); printf(" "); put(stack[1]); printf(" "); put(stack[2]); \
            printf(" sw=%04x\n", sw); \
        } while (0)
#define STACKS(name) else if (!strcmp(op, #name)) { \
            STACK("empty", "", #name); \
            STACK("one", "fldz", #name); \
            STACK("below", "fldz\n fld1\n ffree %%st(0)", #name); \
        }
        if (0) {
        }
        STACKS(fsin) STACKS(fcos) STACKS(fsincos) STACKS(fptan) STACKS(f2xm1) STACKS(fpatan) STACKS(fyl2x) STACKS(fyl2xp1)
        if (results_of(op) == 1) continue;
        for (int i = 0; i < COUNT(values); i++) {
#define FULL(name) \
            __asm__ volatile("fninit\n fldz\n fldz\n fldz\n fldz\n fldz\n fldz\n fld1\n fldt %1\n " #name "\n fnstsw %0" \
                             : "=m"(sw) : "m"(values[i])); \
            __asm__ volatile("fstpt %0\n fstpt %1\n fstpt %2" : "=m"(stack[0]), "=m"(stack[1]), "=m"(stack[2])); \
            printf("full %s %d: ", #name, i); \
            put(stack[0]); printf(" "); put(stack[1]); printf(" "); put(stack[2]); \
            printf(" sw=%04x\n", sw);
            if (!strcmp(op, "fsincos")) {
                FULL(fsincos)
            } else {
                FULL(fptan)
            }
        }
    }
}

/* Each result of the table within one unit in the last place, and the same
   exceptions; again with the precision at 24 bits, which these do not
   follow. */
static void bounded_cases(void) {
    static const char *const ops[] = {"fsin", "fcos", "fsincos", "fptan", "f2xm1", "fpatan", "fyl2x", "fyl2xp1"};
    int count[8] = {0}, within[8] = {0}, same[8] = {0};
    for (int n = 0; n < COUNT(x87_expected); n++) {
        const struct x87_expected *e = &x87_expected[n];
        int k = 0;
        while (strcmp(ops[k], e->op)) k++;
        struct x87_value a = parse(e->a), b = parse(e->b);
        for (int precision = 0; precision < (n % 7 == 0 ? 2 : 1); precision++) {
            unsigned char out[2][10];
            uint16_t word = (uint16_t)((precision ? 0x07f : 0x37f) | e->mode << 10);
            uint16_t sw = run(e->op, word, &a, two_of(e->op) ? &b : NULL, out, 0);
            int close = 1;
            const char *expected[2] = {e->first, e->second};
            for (int r = 0; r < results_of(e->op); r++) {
                /* st(0) is the one pushed. */
                __int128 got = place(bytes_value(out[results_of(e->op) - 1 - r]));
                __int128 want = place(parse(expected[r]));
                if (got - want > 1 || want - got > 1) close = 0;
            }
            int exceptions = (sw & 0x3f) == (e->flags & 0x3f);
            count[k]++;
            within[k] += close;
            same[k] += exceptions;
            if (!close || !exceptions) {
                printf("%s %d %s %s:", e->op, e->mode, e->a, e->b);
                for (int r = results_of(e->op); r-- > 0;) {
                    printf(" ");
                    put(out[r]);
                }
                printf(" sw=%04x, not %s %s %03x\n", sw, e->first, e->second, e->flags);
            }
        }
    }
    for (int k = 0; k < 8; k++)
        printf("%s: %d of %d within one unit, %d with the same exceptions\n", ops[k], within[k], count[k], same[k]);
}

/* musl's long double functions, rounded to double, against the double ones:
   at most one unit apart. */
static void functions(void) {
    static const double inputs[] = {0.5, -0.75, 1.25, 3.0, -7.5, 0.001, 22.25, -0.3, 100.0, 1e-5, 0.999, 2.5e3};
    int count = 0, close = 0;
#define NEAR(a, b) do { \
        double a_ = (double)(a), b_ = (b); \
        int64_t x_, y_; \
        memcpy(&x_, &a_, 8); \
        memcpy(&y_, &b_, 8); \
        count++; \
        if (x_ - y_ <= 1 && y_ - x_ <= 1) close++; \
        else printf("far: %s(%a) %a %a\n", #b, x, a_, b_); \
    } while (0)
    for (int i = 0; i < COUNT(inputs); i++) {
        double x = inputs[i], ax = fabs(x), t = ax > 1 ? 1 / x : x;
        long double lx = x, lax = ax, lt = t;
        NEAR(expl(lx / 8), exp(x / 8));
        NEAR(exp2l(lx / 8), exp2(x / 8));
        NEAR(expm1l(lx / 8), expm1(x / 8));
        NEAR(logl(lax), log(ax));
        NEAR(log2l(lax), log2(ax));
        NEAR(log10l(lax), log10(ax));
        NEAR(log1pl(lax), log1p(ax));
        NEAR(atanl(lx), atan(x));
        NEAR(atan2l(lx, 3.0L), atan2(x, 3.0));
        NEAR(asinl(lt), asin(t));
        NEAR(acosl(lt), acos(t));
        NEAR(powl(lax, 1.5L), pow(ax, 1.5));
        NEAR(sinl(lx), sin(x));
        NEAR(cosl(lx), cos(x));
        NEAR(tanl(lx), tan(x));
    }
    printf("functions: %d of %d within one unit\n", close, count);
    printf("special: %La %La %La %La %La\n", expl(0.0L), logl(1.0L), atan2l(0.0L, -1.0L), log2l(8.0L), expl(-INFINITY));
}

static void hex(const unsigned char *bytes, int size) {
    for (int i = size; i-- > 0;) printf("%02x", bytes[i]);
}

static void decimal_cases(void) {
    static const struct x87_value values[] = {
        {0, 0}, {0, 0x8000}, {1ULL << 63, 0x3fff}, {1ULL << 63, 0xbfff}, {1ULL << 63, 0x3ffe}, {3ULL << 62, 0x3ffe},
        {3ULL << 62, 0x3fff}, {5ULL << 61, 0x4000}, {5ULL << 61, 0xc000}, {7ULL << 61, 0x4000},
        {0xde0b6b3a763fffffULL, 0x403a}, {0xde0b6b3a76400000ULL, 0x403a}, {0xde0b6b3a76400000ULL, 0xc03a},
        {0xde0b6b3a763ffff8ULL, 0x403a}, {0xde0b6b3a763ffff0ULL, 0xc03a}, {0xde0b6b3a763ffffcULL, 0x403a},
        {1ULL << 63, 0x403e}, {1ULL << 63, 0x7fff}, {1ULL << 63, 0xffff}, {3ULL << 62, 0x7fff},
        {0xa000000000000000ULL, 0x7fff}, {1ULL << 62, 0x3fff}, {1, 0}, {1ULL << 63, 0}, {1ULL << 63, 0x3fbf},
        {1ULL << 63, 0xbfbf}, {0xb3c4e1e8b6d3c4e0ULL, 0x4037}, {~0ULL, 0x403e},
    };
    for (int i = 0; i < COUNT(values); i++)
        for (int mode = 0; mode < 4; mode++) {
            uint16_t word = (uint16_t)(0x37f | mode << 10), sw;
            unsigned char out[12];
            memset(out, 0x55, sizeof out);
            __asm__ volatile("fninit\n fldcw %3\n fld1\n fldt %2\n fnclex\n fbstp %0\n fnstsw %1"
                             : "=m"(*(unsigned char(*)[10])out), "=m"(sw) : "m"(values[i]), "m"(word));
            printf("fbstp %d %d: ", i, mode);
            hex(out, 12);
            printf(" sw=%04x\n", sw);
        }
    {
        uint16_t sw;
        unsigned char out[10];
        __asm__ volatile("fninit\n fbstp %0\n fnstsw %1" : "=m"(out), "=m"(sw));
        printf("fbstp empty: ");
        hex(out, 10);
        printf(" sw=%04x\n", sw);
    }
    static const unsigned char packed[][10] = {
        {0x21, 0x43, 0x65, 0x87, 0x09, 0, 0, 0, 0, 0}, {0x21, 0x43, 0x65, 0x87, 0x09, 0, 0, 0, 0, 0x80},
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0x80}, {0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0},
        {0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0xff}, {0x0a, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        {0xa0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
        {0, 0, 0, 0, 0, 0, 0, 0, 0xc0, 0xff}, {0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0x7f}, {0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0x01},
        {0x0f, 0, 0, 0, 0, 0, 0, 0, 0, 0}, {0x1b, 0, 0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0, 0, 0, 0, 0, 0xf0, 0},
        {0, 0, 0, 0, 0, 0, 0, 0, 0x10, 0}, {0x45, 0x23, 0x01, 0, 0, 0, 0, 0, 0, 0},
    };
    for (int i = 0; i < COUNT(packed); i++) {
        unsigned char out[10];
        uint16_t sw;
        __asm__ volatile("fninit\n fnclex\n fbld %2\n fnstsw %1\n fstpt %0" : "=m"(out), "=m"(sw) : "m"(packed[i]));
        printf("fbld %d: ", i);
        hex(out, 10);
        printf(" sw=%04x", sw);
        __asm__ volatile("fninit\n fld1\n fld1\n fld1\n fld1\n fld1\n fld1\n fld1\n fld1\n fnclex\n fbld %2\n fnstsw %1\n fstpt %0"
                         : "=m"(out), "=m"(sw) : "m"(packed[i]));
        printf(" full ");
        hex(out, 10);
        printf(" sw=%04x\n", sw);
    }
}

/* The words of an image, without where the last instruction and operand
   were: 16 bits from byte 6 to 14 of the 16-bit one, and from 12 to 26 of the
   other. */
static void words(const char *label, const unsigned char *image, int wide) {
    printf("%s: ", label);
    if (wide) {
        hex(image, 12);
        printf(" ");
        hex(image + 26, 2);
    } else {
        hex(image, 6);
    }
}

/* ffreep st(i) frees st(i) and pops, with no exception: the tags and the
   top it leaves, from st(1) of three values and from an empty st(0). C0 to
   C3 are left out, as the manuals leave them undefined after it. */
static void ffreep_cases(void) {
    static unsigned char area[512] __attribute__((aligned(16)));
    uint16_t status;
    __asm__ volatile("fninit\n fld1\n fldz\n fldpi\n ffreep %%st(1)\n fnstsw %0\n fxsave %1"
                     : "=m"(status), "=m"(area));
    printf("ffreep st(1): sw=%04x tags=%02x\n", status & ~0x4700, area[4]);
    __asm__ volatile("fninit\n ffreep %%st(0)\n fnstsw %0\n fxsave %1" : "=m"(status), "=m"(area));
    printf("ffreep empty: sw=%04x tags=%02x\n", status & ~0x4700, area[4]);
}

static void state_cases(void) {
    static const struct x87_value nan = {3ULL << 62, 0x7fff};
    {
        /* With REX.W as well, 0x66 does not give the 14-byte layout. A
           static image, which is addressed from rip, so that no other REX
           comes after this one. */
        static unsigned char env[32];
        memset(env, 0x55, sizeof env);
        __asm__ volatile("fninit\n fld1\n .byte 0x66, 0x48\n fnstenv %0" : "=m"(env));
        words("fnstenv 66 rex.w", env, 1);
        printf(" after it ");
        hex(env + 28, 4);
        printf("\n");
    }
    ffreep_cases();
    for (int k = 0; k < 2; k++) {
        unsigned char env[32];
        uint16_t after, word = k ? 0x0260 : 0x037f;
        memset(env, 0x55, sizeof env);
        __asm__ volatile("fninit\n fld1\n fldz\n fldt %2\n fldcw %3\n fadd %%st(0)\n .byte 0x66\n fnstenv %0\n fnstcw %1"
                         : "=m"(env), "=m"(after) : "m"(nan), "m"(word));
        words("fnstenv 16", env, 0);
        printf(" then cw=%04x, after it ", after);
        hex(env + 14, 18);
        printf("\n");
        memset(env + 14, 0xaa, 18);
        uint16_t control, status;
        unsigned char top[10];
        __asm__ volatile("fninit\n .byte 0x66\n fldenv %3\n fnstcw %0\n fnstsw %1\n fstpt %2"
                         : "=m"(control), "=m"(status), "=m"(top) : "m"(env));
        printf("fldenv 16: cw=%04x sw=%04x st0=", control, status);
        hex(top, 10);
        printf("\n");
    }
    {
        unsigned char env[14] = {0x7f, 0x03, 0x00, 0x30, 0xf3, 0xff, 1, 2, 3, 4, 5, 6, 7, 8};
        uint16_t control, status;
        static unsigned char area[512] __attribute__((aligned(16)));
        __asm__ volatile("fninit\n .byte 0x66\n fldenv %3\n fnstcw %0\n fnstsw %1\n fxsave %2"
                         : "=m"(control), "=m"(status), "=m"(area) : "m"(env));
        printf("fldenv 16 made up: cw=%04x sw=%04x tags=%02x\n", control, status, area[4]);
    }
    for (int k = 0; k < 2; k++) {
        unsigned char area[128];
        uint16_t word = 0x0262, control, status;
        memset(area, 0x55, sizeof area);
        if (k)
            __asm__ volatile("fninit\n fld1\n fldz\n fldpi\n fldcw %1\n fadd %%st(0)\n .byte 0x66\n fnsave %0" : "=m"(area) : "m"(word));
        else
            __asm__ volatile("fninit\n fld1\n fldz\n fldpi\n fldcw %1\n fadd %%st(0)\n fnsave %0" : "=m"(area) : "m"(word));
        __asm__ volatile("fnstcw %0\n fnstsw %1" : "=m"(control), "=m"(status));
        int environment = k ? 14 : 28;
        words(k ? "fnsave 16" : "fnsave", area, !k);
        printf(" then cw=%04x sw=%04x\n", control, status);
        for (int r = 0; r < 8; r++) {
            printf("  st%d ", r);
            hex(area + environment + r * 10, 10);
            printf("\n");
        }
        printf("  after it ");
        hex(area + environment + 80, 128 - environment - 80);
        printf("\n");
        unsigned char st[3][10];
        if (k)
            __asm__ volatile(".byte 0x66\n frstor %5\n fnstcw %3\n fnstsw %4\n fstpt %0\n fstpt %1\n fstpt %2"
                             : "=m"(st[0]), "=m"(st[1]), "=m"(st[2]), "=m"(control), "=m"(status) : "m"(area));
        else
            __asm__ volatile("frstor %5\n fnstcw %3\n fnstsw %4\n fstpt %0\n fstpt %1\n fstpt %2"
                             : "=m"(st[0]), "=m"(st[1]), "=m"(st[2]), "=m"(control), "=m"(status) : "m"(area));
        printf("frstor%s: cw=%04x sw=%04x ", k ? " 16" : "", control, status);
        for (int r = 0; r < 3; r++) {
            hex(st[r], 10);
            printf(" ");
        }
        printf("\n");
    }
}

/* x87-exceptions: what an instruction leaves where its exception is not
   masked, read by fnsave, which does not wait; then where SIGFPE comes, and
   its si_code. */
static unsigned char saved[108];
static unsigned char target[16];
static const long double huge = 1e4000L, minus_one = -1.0L, two = 2.0L;
static const uint32_t float_snan = 0x7f800001, float_denormal = 1;
static const struct x87_value smallest = {1ULL << 63, 0x0001}, largest = {~0ULL, 0x7ffe}, denormal = {1, 0},
                              snan = {0xa000000000000000ULL, 0x7fff}, infinity = {1ULL << 63, 0x7fff};
static void saved_show(const char *label, uint16_t word) {
    printf("%s cw=%04x: ", label, word);
    hex(saved, 2);
    printf(" ");
    hex(saved + 4, 2);
    printf(" ");
    hex(saved + 8, 2);
    for (int r = 0; r < 3; r++) {
        printf(" ");
        hex(saved + 28 + r * 10, 10);
    }
    printf(" memory ");
    hex(target, 10);
    printf("\n");
}
/* With only `flags` unmasked. %3 to %12 are the values above. */
#define UNMASKED(label, setup, op, flags) do { \
        uint16_t word_ = (uint16_t)(0x37f & ~(flags)); \
        memset(target, 0x55, sizeof target); \
        __asm__ volatile("fninit\n fldcw %2\n " setup "\n " op "\n fnsave %0" \
                         : "=m"(saved), "+m"(target) \
                         : "m"(word_), "m"(infinity), "m"(minus_one), "m"(float_snan), "m"(snan), "m"(huge), \
                           "m"(denormal), "m"(float_denormal), "m"(largest), "m"(smallest), "m"(two) \
                         : "memory"); \
        saved_show(label, word_); \
    } while (0)
static volatile int faulted;
static volatile uintptr_t faulted_at;
static void fpe(int number, siginfo_t *info, void *context) {
    ucontext_t *uc = context;
    unsigned char *fp = (unsigned char *)uc->uc_mcontext.fpregs;
    uint16_t status, word, now_word, now_status;
    uint32_t mxcsr;
    memcpy(&word, fp, 2);
    memcpy(&status, fp + 2, 2);
    memcpy(&mxcsr, fp + 24, 4);
    faulted++;
    faulted_at = (uintptr_t)uc->uc_mcontext.gregs[REG_RIP];
    __asm__ volatile("fnstcw %0\n fnstsw %1" : "=m"(now_word), "=m"(now_status));
    printf("  SIGFPE %d code=%d at rip=%d trap=%lld error=%lld frame sw=%04x cw=%04x mxcsr=%04x, handler cw=%04x sw=%04x\n",
           number, info->si_code, info->si_addr == (void *)faulted_at, (long long)uc->uc_mcontext.gregs[REG_TRAPNO],
           (long long)uc->uc_mcontext.gregs[REG_ERR], status, word, mxcsr & 0xffc0, now_word, now_status);
    /* Cleared, so that the instruction runs when it returns. */
    status &= (uint16_t)~0x80ff;
    memcpy(fp + 2, &status, 2);
}
/* A division by zero pending, unmasked, and then `next`. */
#define NEXT(label, next) do { \
        uintptr_t at_; \
        uint16_t word_ = 0x37b, status_; \
        faulted = 0; \
        faulted_at = 0; \
        __asm__ volatile("fninit\n fldcw %2\n fldz\n fld1\n fdiv %%st(1), %%st\n lea 1f(%%rip), %0\n 1: " next "\n fnstsw %1\n fninit" \
                         : "=&r"(at_), "=m"(status_) : "m"(word_), "m"(saved) : "memory", "xmm0"); \
        printf("after %s: %d faults, %s, sw=%04x\n", label, faulted, \
               faulted_at == 0 ? "none" : faulted_at == at_ ? "there" : "elsewhere", status_); \
    } while (0)
static void exception_cases(void) {
    UNMASKED("ie fadd inf-inf", "fldt %3\n fldt %3\n fchs", "fadd %%st(1), %%st", 1);
    UNMASKED("ie faddp inf-inf", "fldt %3\n fldt %3\n fchs", "faddp", 1);
    UNMASKED("ie fsqrt -1", "fldt %4", "fsqrt", 1);
    UNMASKED("ie flds snan", "fld1", "flds %5", 1);
    UNMASKED("ie fstps snan", "fldt %6", "fstps %1", 1);
    UNMASKED("ie fistp nan", "fldt %3\n fldt %3\n fchs\n fadd %%st(1), %%st\n fnclex", "fistpl %1", 1);
    UNMASKED("ie fistp huge", "fldt %7", "fistpl %1", 1);
    UNMASKED("ie fcom snan", "fldt %6\n fld1", "fcom %%st(1)", 1);
    UNMASKED("ie fsin inf", "fldt %3", "fsin", 1);
    UNMASKED("ie fptan inf", "fldt %3", "fptan", 1);
    UNMASKED("ie fbstp huge", "fldt %7", "fbstp %1", 1);
    UNMASKED("is fadd empty", "fld1\n ffree %%st(0)\n fld1", "fadd %%st(1), %%st", 1);
    UNMASKED("is fld full", "fld1\n fld1\n fld1\n fld1\n fld1\n fld1\n fld1\n fld1", "fldz", 1);
    UNMASKED("is fstp empty", "", "fstpt %1", 1);
    UNMASKED("is fxch empty", "fld1", "fxch %%st(1)", 1);
    UNMASKED("de fadd", "fldt %8\n fld1", "fadd %%st(1), %%st", 2);
    UNMASKED("de flds", "fld1", "flds %9", 2);
    UNMASKED("de fsin", "fldt %8", "fsin", 2);
    UNMASKED("de fcom", "fldt %8\n fld1", "fcom %%st(1)", 2);
    UNMASKED("ze fdiv", "fldz\n fld1", "fdiv %%st(1), %%st", 4);
    UNMASKED("ze fdivp", "fldz\n fld1", "fdivp", 4);
    UNMASKED("ze fyl2x", "fld1\n fldz", "fyl2x", 4);
    UNMASKED("ze fxtract", "fldz", "fxtract", 4);
    UNMASKED("oe fmul", "fldt %10\n fldt %10", "fmul %%st(1), %%st", 8);
    UNMASKED("oe fmulp", "fldt %10\n fldt %10", "fmulp", 8);
    UNMASKED("oe fstps", "fldt %7", "fstps %1", 8);
    UNMASKED("oe fstpl", "fldt %7", "fstpl %1", 8);
    UNMASKED("oe fscale", "fld1\n fld1\n fscale\n fstp %%st(1)\n fldt %10\n fxch\n fadd %%st(0)\n fxch", "fscale", 8);
    UNMASKED("ue fmul", "fldt %11\n fldt %11", "fmul %%st(1), %%st", 0x10);
    UNMASKED("ue fstps", "fldt %11", "fstps %1", 0x10);
    UNMASKED("ue fstpl", "fldt %11", "fstpl %1", 0x10);
    UNMASKED("ue f2xm1", "fldt %11", "f2xm1", 0x10);
    UNMASKED("ue exact fmul", "fld1\n fldt %11\n fmul %%st(1), %%st\n fstp %%st(1)\n fld1\n fchs\n fld1\n fscale\n fstp %%st(1)",
             "fmul %%st(1), %%st", 0x10);
    UNMASKED("pe fadd", "fldt %11\n fld1", "fadd %%st(1), %%st", 0x20);
    UNMASKED("pe fsqrt", "fldt %12", "fsqrt", 0x20);
    UNMASKED("pe fstps", "fldpi", "fstps %1", 0x20);
    UNMASKED("pe fistp", "fldpi", "fistpl %1", 0x20);
    UNMASKED("pe fsin", "fld1", "fsin", 0x20);
    UNMASKED("pe fldpi", "", "fldpi", 0x20);
    UNMASKED("all fdiv", "fldz\n fld1", "fdiv %%st(1), %%st", 0x3f);
    UNMASKED("ie+pe fistp", "fldt %7", "fistpl %1", 0x21);
    struct sigaction action = {0};
    action.sa_sigaction = fpe;
    action.sa_flags = SA_SIGINFO;
    sigaction(SIGFPE, &action, NULL);
    NEXT("fwait", "fwait");
    NEXT("fnop", "fnop");
    NEXT("fld1", "fld1");
    NEXT("fxch", "fxch");
    NEXT("fstp st0", "fstp %%st(0)");
    NEXT("ffree", "ffree %%st(0)");
    NEXT("fincstp", "fincstp");
    NEXT("fldcw", "fldcw %2");
    NEXT("fnstcw", "fnstcw %3");
    NEXT("fnstsw", "fnstsw %%ax");
    NEXT("fnclex", "fnclex");
    NEXT("fninit", "fninit");
    NEXT("fnstenv", "fnstenv %3");
    NEXT("fldenv", "fnstenv %3\n fldenv %3");
    NEXT("fnsave", "fnsave %3");
    NEXT("frstor", "frstor %3");
    NEXT("fxsave", "fxsave64 %3");
    NEXT("fucomi", "fucomi %%st(0), %%st");
    NEXT("fcmov", "fcmovb %%st(0), %%st");
    NEXT("fstsw", "fstsw %%ax");
    NEXT("addsd", "addsd %%xmm0, %%xmm0");
    NEXT("nop", "nop");
    /* Each exception's si_code. */
    static const uint16_t words[] = {0x37e, 0x37d, 0x37b, 0x377, 0x36f, 0x35f, 0x37e};
    for (int k = 0; k < 7; k++) {
        uint16_t word = words[k];
        printf("code %d:\n", k);
        switch (k) {
        case 0: __asm__ volatile("fninit\n fldcw %0\n fld1\n fchs\n fsqrt\n fwait\n fninit" : : "m"(word)); break;
        case 1: __asm__ volatile("fninit\n fldcw %0\n fldt %1\n fld1\n fadd %%st(1), %%st\n fwait\n fninit" : : "m"(word), "m"(denormal)); break;
        case 2: __asm__ volatile("fninit\n fldcw %0\n fldz\n fld1\n fdiv %%st(1), %%st\n fwait\n fninit" : : "m"(word)); break;
        case 3: __asm__ volatile("fninit\n fldcw %0\n fldt %1\n fld %%st(0)\n fmul %%st(1), %%st\n fwait\n fninit" : : "m"(word), "m"(largest)); break;
        case 4: __asm__ volatile("fninit\n fldcw %0\n fldt %1\n fld %%st(0)\n fmul %%st(1), %%st\n fwait\n fninit" : : "m"(word), "m"(smallest)); break;
        case 5: __asm__ volatile("fninit\n fldcw %0\n fldpi\n fsqrt\n fwait\n fninit" : : "m"(word)); break;
        default: __asm__ volatile("fninit\n fldcw %0\n fadd %%st(1), %%st\n fwait\n fninit" : : "m"(word)); break;
        }
    }
    {
        /* Several at once: the division by zero comes first. */
        uint16_t word = 0x340;
        printf("code several:\n");
        __asm__ volatile("fninit\n fldt %1\n fld1\n fadd %%st(1), %%st\n fldz\n fld1\n fdiv %%st(1), %%st\n fldcw %0\n fwait\n fninit"
                         : : "m"(word), "m"(denormal));
    }
    {
        /* Unmasked by fldcw after it was set: the next that waits faults. */
        uint16_t word = 0x37b, status;
        faulted = 0;
        printf("unmasked later:\n");
        __asm__ volatile("fninit\n fldz\n fld1\n fdiv %%st(1), %%st\n fldcw %1\n fnstsw %0\n fwait\n fninit" : "=m"(status) : "m"(word));
        printf("  before fwait sw=%04x, %d faults\n", status, faulted);
    }
    /* With no handler, the process ends by SIGFPE. */
    signal(SIGFPE, SIG_DFL);
    fflush(stdout);
    pid_t child = fork();
    if (child == 0) {
        uint16_t word = 0x37b;
        __asm__ volatile("fninit\n fldcw %0\n fldz\n fld1\n fdiv %%st(1), %%st\n fwait" : : "m"(word));
        _exit(0);
    }
    int status;
    waitpid(child, &status, 0);
    printf("child: signaled=%d signal=%d\n", WIFSIGNALED(status), WIFSIGNALED(status) ? WTERMSIG(status) : 0);
}

int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "";
    setvbuf(stdout, NULL, _IOFBF, 1 << 16);
    alarm(60);
    if (!strcmp(mode, "x87-transcendental")) {
        exact_cases();
        bounded_cases();
        functions();
        return 0;
    }
    if (!strcmp(mode, "x87-decimal")) {
        decimal_cases();
        return 0;
    }
    if (!strcmp(mode, "x87-state")) {
        state_cases();
        return 0;
    }
    if (!strcmp(mode, "x87-exceptions")) {
        exception_cases();
        return 0;
    }
    printf("unknown mode %s\n", mode);
    return 2;
}
