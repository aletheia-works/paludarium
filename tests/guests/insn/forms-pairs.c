#include "insn.h"
typedef struct {u64 low,high;} __attribute__((aligned(16))) pair;
int test_main(void) {
    for(u64 i=0;i<NVEC;i++)for(u64 equal=0;equal<2;equal++) {
        pair m={vectors[i],vectors[NVEC-1-i]};
        u64 a=m.low^(equal?0:1),d=m.high,b=0x123456789abcdef0UL,c=0xfedcba9876543210UL;
        u64 flags,initial=F_ARITH|2;
        __asm__ volatile("pushq %[fi]; popfq; lock cmpxchg16b %[m]; pushfq; popq %[f]"
            :[m] "+m"(m),"+a"(a),"+d"(d),[f] "=&r"(flags)
            :"b"(b),"c"(c),[fi] "r"(initial):"cc","memory");
        report("cmpxchg16b",vectors[i],equal,initial,a,flags,F_ARITH);
        report_value("rdx",d);report_value("low",m.low);report_value("high",m.high);
        u64 memory=vectors[i];
        a=0x1234567800000000UL|(memory&0xffffffffUL);d=0xabcdef1200000000UL|(memory>>32);
        if(!equal)a^=1;
        __asm__ volatile("pushq %[fi]; popfq; lock cmpxchg8b %[m]; pushfq; popq %[f]"
            :[m] "+m"(memory),"+a"(a),"+d"(d),[f] "=&r"(flags)
            :"b"(b),"c"(c),[fi] "r"(initial):"cc","memory");
        report("cmpxchg8b",vectors[i],equal,initial,a,flags,F_ARITH);
        report_value("rdx",d);report_value("memory",memory);
    }
    flush_out();return 0;
}
