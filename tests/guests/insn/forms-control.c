#include "insn.h"
static const u64 counts[]={0,1,2,15,16,17,31,32,63,64,65};
#define DOUBLE(OP,SUF,WIDTH,REG) do { \
 for(u64 j=0;j<sizeof(counts)/sizeof(counts[0]);j++){ \
  u64 a=vectors[i],b=vectors[NVEC-1-i],c=counts[j],f,fi=F_ARITH|2; \
  __asm__ volatile("pushq %[fi]; popfq; " OP SUF " %%cl," REG "[b]," REG "[a]; pushfq; popq %[f]" \
   :[a] "+r"(a),[f] "=&r"(f):[b] "r"(b),"c"(c),[fi] "r"(fi):"cc"); \
  u64 n=c&((WIDTH)==64?63:31),mask=n?F_ARITH&~F_AF:F_ARITH; \
  if(n>1)mask&=~F_OF; if(n>(WIDTH)){a=0;mask=0;} \
  report(OP SUF,vectors[i],c,fi,a,f,mask); \
 } }while(0)
#define FLAGS(OP) do {u64 a=vectors[i],d=0x1122334455667788UL,f,fi=F_ARITH|2; \
 __asm__ volatile("pushq %[fi]; popfq; " OP "; pushfq; popq %[f]" \
 :"+a"(a),"+d"(d),[f] "=&r"(f):[fi] "r"(fi):"cc"); \
 report(OP,vectors[i],0,fi,a,f,F_ARITH);report_value("rdx",d); }while(0)
#define LOCK_BINARY(OP,SUF,REG,MASK) do {u64 a=vectors[i],b=vectors[NVEC-1-i],f,fi=F_ARITH|2; \
 __asm__ volatile("pushq %[fi]; popfq; lock " OP SUF " " REG "[b],%[a]; pushfq; popq %[f]" \
 :[a] "+m"(a),[f] "=&r"(f):[b] "r"(b),[fi] "r"(fi):"cc","memory"); \
 report("lock-" OP SUF,vectors[i],b,fi,a,f,MASK); }while(0)
#define LOCK_UNARY(OP,MASK) do {u64 a=vectors[i],f,fi=F_ARITH|2; \
 __asm__ volatile("pushq %[fi]; popfq; lock " OP "q %[a]; pushfq; popq %[f]" \
 :[a] "+m"(a),[f] "=&r"(f):[fi] "r"(fi):"cc","memory"); \
 report("lock-" OP,vectors[i],0,fi,a,f,MASK); }while(0)
#define BRANCH(OP,COUNT) do {u64 initial_count=(COUNT),branch_count=initial_count,r,f,fi=F_ARITH|2; \
 __asm__ volatile("pushq %[fi]; popfq; movq $0,%[r]; " OP " 1f; jmp 2f; 1: movq $1,%[r]; 2: pushfq; popq %[f]" \
 :"+c"(branch_count),[r] "=&r"(r),[f] "=&r"(f):[fi] "r"(fi):"cc"); \
 report(OP,initial_count,0,fi,r,f,F_ARITH);report_value("count",branch_count); }while(0)
int test_main(void){
 for(u64 i=0;i<NVEC;i++){
  DOUBLE("shld","w",16,"%w");DOUBLE("shrd","w",16,"%w");
  DOUBLE("shld","l",32,"%k");DOUBLE("shrd","l",32,"%k");
  DOUBLE("shld","q",64,"%");DOUBLE("shrd","q",64,"%");
  FLAGS("cbtw");FLAGS("cwtl");FLAGS("cwtd");FLAGS("clc");FLAGS("stc");FLAGS("cmc");FLAGS("lahf");FLAGS("sahf");FLAGS("pause");
  LOCK_BINARY("add","b","%b",F_ARITH);LOCK_BINARY("adc","w","%w",F_ARITH);
  LOCK_BINARY("sub","l","%k",F_ARITH);LOCK_BINARY("sbb","q","%",F_ARITH);
  LOCK_BINARY("and","q","%",F_LOGIC);LOCK_BINARY("or","q","%",F_LOGIC);LOCK_BINARY("xor","q","%",F_LOGIC);
  LOCK_UNARY("inc",F_ARITH);LOCK_UNARY("dec",F_ARITH);LOCK_UNARY("neg",F_ARITH);LOCK_UNARY("not",F_ARITH);
 }
 for(u64 c=0;c<4;c++){BRANCH("jrcxz",c);BRANCH("jecxz",c|0x123400000000UL);
  BRANCH("loop",c);BRANCH("loope",c);BRANCH("loopne",c);
  BRANCH("addr32 loop",c|0x123400000000UL);BRANCH("addr32 loope",c|0x123400000000UL);BRANCH("addr32 loopne",c|0x123400000000UL);}
 flush_out();return 0;
}
