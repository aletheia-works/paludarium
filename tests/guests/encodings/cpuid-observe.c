/* Host identity values are observations, not the virtual CPUID contract. */
#include <stdint.h>
#include <stdio.h>
int main(void) {
    static const uint32_t leaves[]={0,1,7,0x80000000u,0x80000001u,0xffffffffu};
    for(unsigned i=0;i<sizeof(leaves)/sizeof(leaves[0]);i++) for(unsigned sub=0;sub<2;sub++) {
        uint64_t a=0xffffffff00000000ULL|leaves[i],c=0xffffffff00000000ULL|sub,b,d,after;
        const uint64_t flags=0x8d7;
        __asm__ volatile("pushq %[flags]; popfq; cpuid; pushfq; popq %[after]"
            : "+a"(a),"=b"(b),"+c"(c),"=d"(d),[after]"=r"(after)
            : [flags]"r"(flags) : "cc","memory");
        printf("%08x|%08x|%016llx|%016llx|%016llx|%016llx|%016llx\n",leaves[i],sub,
               (unsigned long long)a,(unsigned long long)b,(unsigned long long)c,
               (unsigned long long)d,(unsigned long long)(after&0xcd5));
        if((a|b|c|d)>>32 || (after&0xcd5)!=(flags&0xcd5)) return 2;
    }
    return ferror(stdout)?3:0;
}
