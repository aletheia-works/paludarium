/* Cases precede U2 CPU rotate/scan/bit/atomic implementation. */
#include "insn.h"
static const u64 counts[] = {0,1,2,8,9,16,17,31,32,63,64,65};
#define ROTATE(OP,SUFFIX,SIZE,REG) do { \
    for (u64 j=0;j<sizeof(counts)/sizeof(counts[0]);j++) { \
        u64 r=vectors[i],f,fi=F_ARITH|2,c=counts[j]; \
        __asm__ volatile("pushq %[fi]; popfq; " OP SUFFIX " %%cl," REG "[r]; pushfq; popq %[f]" \
            : [r] "+r"(r), [f] "=&r"(f) : "c"(c), [fi] "r"(fi) : "cc"); \
        u64 masked=c & ((SIZE)==8 ? 63 : 31); \
        u64 mask=F_ARITH; if(masked>1) mask &= ~F_OF; \
        report(OP SUFFIX,vectors[i],c,fi,r,f,mask); \
    } \
} while(0)
#define ALL_ROTATE(OP) ROTATE(OP,"b",1,"%b"); ROTATE(OP,"w",2,"%w"); ROTATE(OP,"l",4,"%k"); ROTATE(OP,"q",8,"%")
#define SCAN(OP,SUFFIX,REG) do { \
    u64 r=0x1122334455667788UL,f; \
    __asm__ volatile(OP SUFFIX " " REG "[a]," REG "[r]; pushfq; popq %[f]" \
        : [r] "+r"(r), [f] "=&r"(f) : [a] "r"(vectors[i]) : "cc"); \
    report(OP SUFFIX,vectors[i],0,0,vectors[i] ? r : 0,f,F_ZF); \
}while(0)
#define BIT(OP) do { u64 r=vectors[i],f,bit=63; \
    __asm__ volatile(OP "q %[bit],%[r]; pushfq; popq %[f]" \
        : [r] "+r"(r),[f] "=&r"(f) : [bit] "r"(bit) : "cc"); \
    report(OP "q",vectors[i],bit,0,r,f,F_CF); \
}while(0)
#define COUNT(OP,SUFFIX,REG,MASK) do {u64 r=0x1122334455667788UL,f,fi=F_ARITH|2; \
 __asm__ volatile("pushq %[fi]; popfq; " OP SUFFIX " " REG "[a]," REG "[r]; pushfq; popq %[f]" \
 :[r] "+r"(r),[f] "=&r"(f):[a] "r"(vectors[i]),[fi] "r"(fi):"cc"); \
 report(OP SUFFIX,vectors[i],0,fi,r,f,MASK); }while(0)
int test_main(void) {
    for(u64 i=0;i<NVEC;i++) {
        ALL_ROTATE("rol"); ALL_ROTATE("ror"); ALL_ROTATE("rcl"); ALL_ROTATE("rcr");
        SCAN("bsf","q","%"); SCAN("bsr","q","%");
        COUNT("tzcnt","w","%w",F_CF|F_ZF);COUNT("tzcnt","l","%k",F_CF|F_ZF);COUNT("tzcnt","q","%",F_CF|F_ZF);
        COUNT("lzcnt","w","%w",F_CF|F_ZF);COUNT("lzcnt","l","%k",F_CF|F_ZF);COUNT("lzcnt","q","%",F_CF|F_ZF);
        COUNT("popcnt","w","%w",F_ARITH);COUNT("popcnt","l","%k",F_ARITH);COUNT("popcnt","q","%",F_ARITH);
        BIT("bts"); BIT("btr"); BIT("btc");
        u64 r=vectors[i],f,fi=F_ARITH|2;
        __asm__ volatile("pushq %[fi]; popfq; bswapq %[r]; pushfq; popq %[f]"
            :[r] "+r"(r),[f] "=&r"(f):[fi] "r"(fi):"cc");
        report("bswap64",vectors[i],0,fi,r,f,F_ARITH);
        u64 memory=vectors[i],source=7;
        __asm__ volatile("lock xaddq %[s],%[m]; pushfq; popq %[f]"
            :[s] "+r"(source),[m] "+m"(memory),[f] "=&r"(f)::"cc","memory");
        report("xadd64-old",vectors[i],7,0,source,f,F_ARITH);
        report_value("xadd64-new",memory);
    }
    flush_out();return 0;
}
