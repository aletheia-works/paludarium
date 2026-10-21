/* All implicit integer string widths, both DF directions; native oracle. */
#include "insn.h"
#define STRING(OP,SUFFIX,SIZE,KIND) do { \
    u64 input[8],output[8]; \
    for(u64 k=0;k<8;k++){input[k]=vectors[(i+k)%NVEC];output[k]=0;} \
    u64 acc=vectors[i],count=4,flags,fin=F_ARITH|2|(backwards?F_DF:0); \
    u64 from=(u64)input+(backwards?3*(SIZE):0),to=(u64)output+(backwards?3*(SIZE):0); \
    if((KIND)==3){for(u64 k=0;k<8;k++)output[k]=input[k];((u8 *)output)[2*(SIZE)]^=1;} \
    if((KIND)==4){for(u64 k=0;k<8;k++)output[k]=0;output[0]=acc;} \
    __asm__ volatile("pushq %[fi]; popfq; rep " OP SUFFIX "; pushfq; popq %[f]; cld" \
        : "+S"(from),"+D"(to),"+c"(count),"+a"(acc),[f] "=&r"(flags) :[fi] "r"(fin):"cc","memory"); \
    report(OP SUFFIX,vectors[i],backwards,fin,acc,flags,F_ARITH|F_DF); \
    report_value("count",count); \
    if((KIND)==0||(KIND)==2||(KIND)==3)report_value("source-offset",from-(u64)input); \
    if((KIND)!=2)report_value("destination-offset",to-(u64)output); \
    for(u64 k=0;k<8;k++)report_value("memory",output[k]); \
}while(0)
#define WIDTHS(OP,KIND) STRING(OP,"b",1,KIND);STRING(OP,"w",2,KIND);STRING(OP,"l",4,KIND);STRING(OP,"q",8,KIND)
int test_main(void) {
    for(u64 i=0;i<NVEC;i++)for(u64 backwards=0;backwards<2;backwards++) {
        WIDTHS("movs",0);WIDTHS("stos",1);WIDTHS("lods",2);WIDTHS("cmps",3);WIDTHS("scas",4);
    }
    flush_out();return 0;
}
