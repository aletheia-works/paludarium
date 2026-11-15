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
   the double ones, which use none. */
#define _GNU_SOURCE
#include <math.h>
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
    printf("unknown mode %s\n", mode);
    return 2;
}
