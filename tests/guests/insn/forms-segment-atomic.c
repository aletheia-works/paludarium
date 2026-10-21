#include "insn.h"
typedef struct {u64 low,high;} __attribute__((aligned(16))) pair;
static struct {pair shadow,target;} __attribute__((aligned(16))) cells;
static pair *target=&cells.target;
static u64 address32;
static long set_base(u64 code,u64 base){
 long status;__asm__ volatile("syscall":"=a"(status):"a"(158L),"D"(code),"S"(base):"rcx","r11","memory");return status;
}
static void prepare(u64 i){cells.shadow.low=0x1122334455667788UL;cells.shadow.high=0x8877665544332211UL;target->low=vectors[i];target->high=vectors[NVEC-1-i];}
static u64 pointer(void){return (u64)&cells.shadow|(address32?0xdeadbeef00000000UL:0);}
static void result(const char *name,u64 i,u64 value,u64 flags,u64 mask){
 report(name,vectors[i],address32,F_ARITH|2,value,flags,mask);report_value("target-low",target->low);report_value("target-high",target->high);report_value("shadow-low",cells.shadow.low);report_value("shadow-high",cells.shadow.high);
}
#define BIN(S,A,R,OP,SUF,REG,MASK) do {prepare(i);u64 b=vectors[NVEC-1-i],p=pointer(),f,fi=F_ARITH|2; \
 __asm__ volatile("pushq %[fi]; popfq; " A " lock " OP SUF " " REG "[b]," S ":(" R "[p]); pushfq; popq %[f]" \
 :[f]"=&r"(f):[b]"r"(b),[p]"r"(p),[fi]"r"(fi):"cc","memory");result(S A OP SUF,i,b,f,MASK); }while(0)
#define UNARY(S,A,R,OP) do {prepare(i);u64 p=pointer(),f,fi=F_ARITH|2; \
 __asm__ volatile("pushq %[fi]; popfq; " A " lock " OP "q " S ":(" R "[p]); pushfq; popq %[f]" \
 :[f]"=&r"(f):[p]"r"(p),[fi]"r"(fi):"cc","memory");result(S A OP,i,target->low,f,F_ARITH); }while(0)
#define BIT(S,A,R,OP) do {prepare(i);u64 b=i%64,p=pointer(),f,fi=F_ARITH|2; \
 __asm__ volatile("pushq %[fi]; popfq; " A " lock " OP "q %[b]," S ":(" R "[p]); pushfq; popq %[f]" \
 :[f]"=&r"(f):[b]"r"(b),[p]"r"(p),[fi]"r"(fi):"cc","memory");result(S A OP,i,b,f,F_CF); }while(0)
#define EXCHANGE(S,A,R,OP,LOCK) do {prepare(i);u64 b=vectors[NVEC-1-i],p=pointer(),f,fi=F_ARITH|2; \
 __asm__ volatile("pushq %[fi]; popfq; " A " " LOCK OP "q %[b]," S ":(" R "[p]); pushfq; popq %[f]" \
 :[b]"+r"(b),[f]"=&r"(f):[p]"r"(p),[fi]"r"(fi):"cc","memory");result(S A OP,i,b,f,F_ARITH); }while(0)
#define CMP(S,A,R) do {for(u64 equal=0;equal<2;equal++){prepare(i);u64 a=target->low^(equal?0:1),b=vectors[NVEC-1-i],p=pointer(),f,fi=F_ARITH|2; \
 __asm__ volatile("pushq %[fi]; popfq; " A " lock cmpxchgq %[b]," S ":(" R "[p]); pushfq; popq %[f]" \
 :"+a"(a),[f]"=&r"(f):[b]"r"(b),[p]"r"(p),[fi]"r"(fi):"cc","memory");result(S A "cmpxchg",i,a,f,F_ARITH);}}while(0)
#define PAIR(S,A,R,OP,IS16) do {for(u64 equal=0;equal<2;equal++){prepare(i);u64 a=(IS16?target->low:target->low&0xffffffffUL)^(equal?0:1),d=IS16?target->high:target->low>>32,b=9,c=10,p=pointer(),f,fi=F_ARITH|2; \
 __asm__ volatile("pushq %[fi]; popfq; " A " lock " OP " " S ":(" R "[p]); pushfq; popq %[f]" \
 :"+a"(a),"+d"(d),[f]"=&r"(f):"b"(b),"c"(c),[p]"r"(p),[fi]"r"(fi):"cc","memory");result(S A OP,i,a,f,F_ARITH);report_value("rdx",d);}}while(0)
#define RUN(S,A,R) do {for(u64 i=0;i<NVEC;i++){ \
 BIN(S,A,R,"add","b","%b",F_ARITH);BIN(S,A,R,"adc","w","%w",F_ARITH); \
 BIN(S,A,R,"sub","l","%k",F_ARITH);BIN(S,A,R,"sbb","q","%",F_ARITH); \
 BIN(S,A,R,"and","q","%",F_LOGIC);BIN(S,A,R,"or","q","%",F_LOGIC);BIN(S,A,R,"xor","q","%",F_LOGIC); \
 UNARY(S,A,R,"inc");UNARY(S,A,R,"dec");UNARY(S,A,R,"neg");UNARY(S,A,R,"not"); \
 BIT(S,A,R,"bts");BIT(S,A,R,"btr");BIT(S,A,R,"btc"); \
 EXCHANGE(S,A,R,"xchg","");EXCHANGE(S,A,R,"xadd"," lock "); \
 CMP(S,A,R);PAIR(S,A,R,"cmpxchg8b",0);PAIR(S,A,R,"cmpxchg16b",1);}}while(0)
int test_main(void){
 u64 base=(u64)target-(u64)&cells.shadow;
 if(set_base(0x1002,base))return 2;address32=0;RUN("%%fs","","%");address32=1;RUN("%%fs","addr32","%k");if(set_base(0x1002,0))return 3;
 if(set_base(0x1001,base))return 4;address32=0;RUN("%%gs","","%");address32=1;RUN("%%gs","addr32","%k");if(set_base(0x1001,0))return 5;
 register u64 r10 __asm__("r10")=0x32,r8 __asm__("r8")=~0UL,r9 __asm__("r9")=0;long mapped;
 __asm__ volatile("syscall":"=a"(mapped):"a"(9L),"D"(0x100000000UL),"S"(4096UL),"d"(3UL),"r"(r10),"r"(r8),"r"(r9):"rcx","r11","memory");
 if(mapped!=0x100000000UL)return 6;target=(pair *)mapped;base=(u64)target-(u64)&cells.shadow;address32=1;
 if(set_base(0x1002,base))return 7;RUN("%%fs","addr32","%k");if(set_base(0x1002,0))return 8;
 if(set_base(0x1001,base))return 9;RUN("%%gs","addr32","%k");if(set_base(0x1001,0))return 10;
 flush_out();return 0;
}

