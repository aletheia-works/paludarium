/* Static target candidates; native output precedes implementation. */
#include "insn.h"
static const u64 counts[]={0,1,8,15,16,31,32,63,64,65,255,256};
#define BIN3(OP,SUF,REG,MASK,B) do {u64 a=vectors[i],b=(B),r=0x123456789abcdef0UL,f,fi=F_ARITH|2; \
 __asm__ volatile("pushq %[fi]; popfq; " OP SUF " " REG "[b]," REG "[a]," REG "[r]; pushfq; popq %[f]" \
 :[r] "+r"(r),[f] "=&r"(f):[a] "r"(a),[b] "r"(b),[fi] "r"(fi):"cc"); \
 report(OP SUF,a,b,fi,r,f,MASK); }while(0)
#define ADX(OP,SUF,REG) do {u64 a=vectors[i],b=vectors[NVEC-1-i],f,fi=F_ARITH|2; \
 __asm__ volatile("pushq %[fi]; popfq; " OP SUF " " REG "[b]," REG "[a]; pushfq; popq %[f]" \
 :[a] "+r"(a),[f] "=&r"(f):[b] "r"(b),[fi] "r"(fi):"cc"); \
 report(OP SUF,vectors[i],b,fi,a,f,F_ARITH); }while(0)
#define MULXP(PREFIX,SUF,REG) do {u64 d=vectors[i],b=vectors[NVEC-1-i],lo,hi,f,fi=F_ARITH|2; \
 __asm__ volatile("pushq %[fi]; popfq; " PREFIX " mulx" SUF " " REG "[b]," REG "[lo]," REG "[hi]; pushfq; popq %[f]" \
 :[lo] "=&r"(lo),[hi] "=&r"(hi),[f] "=&r"(f):"d"(d),[b] "r"(b),[fi] "r"(fi):"cc"); \
 report("mulx" SUF,d,b,fi,lo,f,F_ARITH);report_value("high",hi); }while(0)
#define RORX(SUF,REG,N) do {u64 a=vectors[i],r,f,fi=F_ARITH|2; \
 __asm__ volatile("pushq %[fi]; popfq; rorx" SUF " $" #N "," REG "[a]," REG "[r]; pushfq; popq %[f]" \
 :[r] "=&r"(r),[f] "=&r"(f):[a] "r"(a),[fi] "r"(fi):"cc"); \
 report("rorx" SUF,a,N,fi,r,f,F_ARITH); }while(0)
#define MOVBE(SUF,REG) do {u64 m=vectors[i],r=0x1122334455667788UL,f,fi=F_ARITH|2; \
 __asm__ volatile("pushq %[fi]; popfq; movbe" SUF " %[m]," REG "[r]; pushfq; popq %[f]" \
 :[r] "+r"(r),[f] "=&r"(f):[m] "m"(m),[fi] "r"(fi):"cc"); \
 report("movbe-load" SUF,vectors[i],0,fi,r,f,F_ARITH); \
 __asm__ volatile("pushq %[fi]; popfq; movbe" SUF " " REG "[r],%[m]; pushfq; popq %[f]" \
 :[m] "+m"(m),[f] "=&r"(f):[r] "r"(vectors[NVEC-1-i]),[fi] "r"(fi):"cc","memory"); \
 report("movbe-store" SUF,vectors[i],vectors[NVEC-1-i],fi,m,f,F_ARITH); }while(0)
#define ADXMEM(OP,DISP,IDX) do {u64 cells[3]={vectors[i],vectors[NVEC-1-i],~vectors[i]},a=vectors[i],f,fi=F_ARITH|2; \
 __asm__ volatile("pushq %[fi]; popfq; " OP "q " DISP "(%[p]),%[a]; pushfq; popq %[f]" \
 :[a] "+r"(a),[f] "=&r"(f):[p] "r"(&cells[1]),[fi] "r"(fi):"cc","memory"); \
 report(OP "-mem" DISP,vectors[i],cells[IDX],fi,a,f,F_ARITH); }while(0)
#define MULXMEM(DISP,IDX) do {u64 cells[3]={vectors[i],vectors[NVEC-1-i],~vectors[i]},d=vectors[i],lo,hi,f,fi=F_ARITH|2; \
 __asm__ volatile("pushq %[fi]; popfq; mulxq " DISP "(%[p]),%[lo],%[hi]; pushfq; popq %[f]" \
 :[lo] "=&r"(lo),[hi] "=&r"(hi),[f] "=&r"(f):"d"(d),[p] "r"(&cells[1]),[fi] "r"(fi):"cc","memory"); \
 report("mulx-mem" DISP,d,cells[IDX],fi,lo,f,F_ARITH);report_value("high",hi); }while(0)
#define SHIFTMEM(OP,SUF,REG,DISP,VALUE) do {u64 cells[3]={vectors[i],vectors[NVEC-1-i],~vectors[i]},b=counts[j],r=0x123456789abcdef0UL,f,fi=F_ARITH|2; \
 __asm__ volatile("pushq %[fi]; popfq; " OP SUF " " REG "[b]," DISP "(%[p])," REG "[r]; pushfq; popq %[f]" \
 :[r] "+r"(r),[f] "=&r"(f):[b] "r"(b),[p] "r"(&cells[1]),[fi] "r"(fi):"cc","memory"); \
 report(OP SUF "-mem" DISP,(VALUE),b,fi,r,f,F_ARITH); }while(0)
int test_main(void){
 for(u64 i=0;i<NVEC;i++){
  ADXMEM("adcx","0",1);ADXMEM("adcx","8",2);ADXMEM("adox","-8",0);MULXMEM("0",1);MULXMEM("8",2);
  ADX("adcx","l","%k");ADX("adcx","q","%");ADX("adox","l","%k");ADX("adox","q","%");
  BIN3("andn","l","%k",F_CF|F_OF|F_ZF|F_SF,vectors[NVEC-1-i]);BIN3("andn","q","%",F_CF|F_OF|F_ZF|F_SF,vectors[NVEC-1-i]);
  BIN3("pext","l","%k",F_ARITH,vectors[NVEC-1-i]);BIN3("pext","q","%",F_ARITH,vectors[NVEC-1-i]);
  for(u64 j=0;j<sizeof(counts)/sizeof(counts[0]);j++){
   SHIFTMEM("shlx","q","%","0",cells[1]);SHIFTMEM("shlx","q","%","8",cells[2]);SHIFTMEM("shlx","q","%","-8",cells[0]);
   SHIFTMEM("shrx","q","%","0",cells[1]);SHIFTMEM("shrx","l","%k","0",cells[1]);SHIFTMEM("shrx","l","%k","-4",cells[0]>>32);
   BIN3("bzhi","l","%k",F_CF|F_OF|F_ZF|F_SF,counts[j]);BIN3("bzhi","q","%",F_CF|F_OF|F_ZF|F_SF,counts[j]);
   BIN3("shlx","l","%k",F_ARITH,counts[j]);BIN3("shlx","q","%",F_ARITH,counts[j]);
   BIN3("shrx","l","%k",F_ARITH,counts[j]);BIN3("shrx","q","%",F_ARITH,counts[j]);
  }
  MULXP("","l","%k");MULXP("","q","%");
  MULXP(".byte 0x67;","q","%");MULXP(".byte 0x67,0x67;","q","%");
  RORX("l","%k",0);RORX("l","%k",1);RORX("l","%k",31);RORX("l","%k",32);RORX("l","%k",65);
  RORX("q","%",0);RORX("q","%",1);RORX("q","%",63);RORX("q","%",64);RORX("q","%",65);
  MOVBE("w","%w");MOVBE("l","%k");MOVBE("q","%");
 }
 flush_out();return 0;
}

