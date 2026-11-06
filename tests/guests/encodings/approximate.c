/* What x86 leaves to the CPU, as the same output on every CPU. */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <emmintrin.h>
#include <xmmintrin.h>

static uint32_t bits(float f) {
    uint32_t u;
    memcpy(&u, &f, 4);
    return u;
}
static float value(uint32_t u) {
    float f;
    memcpy(&f, &u, 4);
    return f;
}
/* Intel and AMD both promise a relative error of at most 1.5 * 2^-12. */
static int close_enough(double got, double want) {
    double error = (got - want) / want;
    if (error < 0) error = -error;
    return error <= 1.5 / 4096;
}
static double root_of(double x) {
    double r;
    __asm__("sqrtsd %1, %0" : "=x"(r) : "x"(x));
    return r;
}

int main(void) {
    static const float finite[] = {1.0f, 2.0f, 0.5f, 3.0f, 7.0f, 1.5f, 1e-30f, 1e30f, 1.1754944e-38f,
                                   16.0f, 0.1f, 123456.789f, 1e10f, 1e-10f, 65536.0f, 1.9999999f};
    int rcp = 0, rsqrt = 0, count = 0;
    for (unsigned i = 0; i < sizeof finite / sizeof finite[0]; i++)
        for (int sign = 0; sign < 2; sign++) {
            float x = sign ? -finite[i] : finite[i];
            float out[4];
            _mm_storeu_ps(out, _mm_rcp_ps(_mm_set1_ps(x)));
            for (int lane = 0; lane < 4; lane++) rcp += close_enough(out[lane], 1.0 / x);
            count += 4;
            if (!sign) {
                _mm_storeu_ps(out, _mm_rsqrt_ps(_mm_set1_ps(x)));
                for (int lane = 0; lane < 4; lane++) rsqrt += close_enough(out[lane], 1.0 / root_of(x));
            }
        }
    printf("rcp %d of %d, rsqrt %d of %d\n", rcp, count, rsqrt, count / 2);

    static const uint32_t special[] = {
        0, 0x80000000u, 0x7f800000u, 0xff800000u, /* zeros, infinities */
        1, 0x80000001u, 0x007fffffu, 0x807fffffu, /* denormals */
        0x7fc00042u, 0xffc00042u, 0x7f800042u, 0xff800042u, /* NaNs */
    };
    unsigned before = _mm_getcsr();
    for (unsigned i = 0; i < sizeof special / sizeof special[0]; i++) {
        __m128 x = _mm_set1_ps(value(special[i]));
        printf("%08x rcp %08x rsqrt %08x\n", special[i], bits(_mm_cvtss_f32(_mm_rcp_ps(x))),
               bits(_mm_cvtss_f32(_mm_rsqrt_ps(x))));
    }
    /* Where only one of the two is defined: the other is an ordinary value. */
    float largest = value(0x7f7fffffu), other[4];
    _mm_storeu_ps(other, _mm_rsqrt_ps(_mm_set1_ps(largest)));
    printf("largest rcp %08x -largest rcp %08x rsqrt in bound %d\n",
           bits(_mm_cvtss_f32(_mm_rcp_ps(_mm_set1_ps(largest)))),
           bits(_mm_cvtss_f32(_mm_rcp_ps(_mm_set1_ps(-largest)))),
           close_enough(other[0], 1.0 / root_of(largest)));
    printf("-largest rsqrt %08x -1 rsqrt %08x\n", bits(_mm_cvtss_f32(_mm_rsqrt_ps(_mm_set1_ps(-largest)))),
           bits(_mm_cvtss_f32(_mm_rsqrt_ps(_mm_set1_ps(-1.0f)))));
    printf("mxcsr unchanged %d\n", _mm_getcsr() == before);

    /* The scalar forms keep the upper lanes, from registers and from memory. */
    __m128 upper = _mm_set_ps(4, 3, 2, 1);
    float s = 0;
    float out[4];
    _mm_storeu_ps(out, _mm_rcp_ss(upper));
    printf("rcpss %08x %08x %08x\n", bits(out[1]), bits(out[2]), bits(out[3]));
    _mm_storeu_ps(out, _mm_rsqrt_ss(upper));
    printf("rsqrtss %08x %08x %08x\n", bits(out[1]), bits(out[2]), bits(out[3]));
    __m128 kept = upper;
    __asm__("rcpss %1, %0" : "+x"(kept) : "m"(s));
    _mm_storeu_ps(out, kept);
    printf("rcpss memory %08x %08x %08x %08x\n", bits(out[0]), bits(out[1]), bits(out[2]), bits(out[3]));

    /* MASKMOVDQU writes the selected bytes, and with no mask none. Whether no
       mask can still fault on memory it cannot reach is each CPU's choice: this
       AMD's does. */
    unsigned char target[32];
    memset(target, 0xee, sizeof target);
    __m128i data = _mm_set_epi8(16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1);
    __m128i mask = _mm_set_epi8(-1, 0, 127, -128, 0, 0, -1, 1, 0, -1, 0, -1, 0, 0, 0, -1);
    _mm_maskmoveu_si128(data, mask, (char *)target + 5);
    for (unsigned i = 0; i < sizeof target; i++) printf("%02x", target[i]);
    putchar('\n');
    _mm_maskmoveu_si128(data, _mm_setzero_si128(), (char *)target);
    for (unsigned i = 0; i < sizeof target; i++) printf("%02x", target[i]);
    putchar('\n');
    return 0;
}
