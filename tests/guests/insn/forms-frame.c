#include "insn.h"
/* 16-bit ENTER updates BP rather than all of RBP. Keep both its nesting
 * chain and LEAVE's frame in one mapped 64 KiB window, independently of ASLR.
 * The original caller stack remains the stack for every 64-bit form. */
static u8 frame_stack[65536] __attribute__((aligned(65536), used));
#define FRAME(NAME,INSN,N,W,L) \
extern void NAME(u64 *); \
__asm__(".text\n.global " #NAME "\n" #NAME ":\n" \
"pushq %rbp\n movq %rsp,%r10\n" \
".if " #W " == 2\n leaq frame_stack+32768(%rip),%rsp\n .endif\n" \
"subq $1024,%rsp\n movq %rsp,%r11\n leaq 512(%rsp),%rbp\n" \
"movq $32,%rcx\n movq %rbp,%rsi\n1: subq $8,%rsi\n movq $42,(%rsi)\n loop 1b\n" \
INSN " $24,$" #N "\n" L "\n" \
"movq %rsp,%rax\n subq %r11,%rax\n movq %rax,0(%rdi)\n" \
"movq %rbp,%rax\n subq %r11,%rax\n movq %rax,8(%rdi)\n" \
"pushfq\n popq %rax\n movq %rax,16(%rdi)\n" \
"movq %r10,%rsp\n popq %rbp\n ret\n");
FRAME(e0,"enter",0,8,"") FRAME(e1,"enter",1,8,"") FRAME(e2,"enter",2,8,"") FRAME(e31,"enter",31,8,"")
FRAME(w0,"enterw",0,2,"") FRAME(w1,"enterw",1,2,"") FRAME(w2,"enterw",2,2,"") FRAME(w31,"enterw",31,2,"")
FRAME(lw,"enterw",2,2,"leavew")
FRAME(ef3,".byte 0xf3; enter",2,8,"") FRAME(ef2,".byte 0xf2; enter",2,8,"")
FRAME(er44,".byte 0x44; enter",2,8,"") FRAME(er46,".byte 0x46; enter",2,8,"")
FRAME(er4c,".byte 0x4c; enter",2,8,"") FRAME(er4e,".byte 0x4e; enter",2,8,"")
FRAME(ew42,".byte 0x66,0x42; enter",2,2,"") FRAME(ew43,".byte 0x66,0x43; enter",2,2,"")
#define XP(P) do {u64 a=0x123456789abcde00UL|i,b=(u64)table; \
 __asm__ volatile(".byte " P "; xlatb":"+a"(a):"b"(b):"memory");report_value("xlat-prefix",a); }while(0)
#define PF(P) do {u64 f,word; \
 __asm__ volatile("pushq %[fi]; popfq; .byte " P "; pushfq; popq %[word]; pushfq; popq %[f]" \
 :[word]"=&r"(word),[f]"=&r"(f):[fi]"r"(fi):"cc","memory");report("pushfq-prefix",fi,0,fi,word&F_ARITH,f,F_ARITH); \
 __asm__ volatile("pushq %[fi]; .byte " P "; popfq; pushfq; popq %[f]" \
 :[f]"=&r"(f):[fi]"r"(fi):"cc","memory");report_value("popfq-prefix",f&F_ARITH); }while(0)
static u8 table[256];
int test_main(void){
 void (*fns[])(u64*)={e0,e1,e2,e31,w0,w1,w2,w31,lw,ef3,ef2,er44,er46,er4c,er4e,ew42,ew43};
 for(u64 i=0;i<sizeof(fns)/sizeof(fns[0]);i++){u64 r[3];fns[i](r);report_value("enter-rsp",r[0]);report_value("enter-rbp",r[1]);}
 for(u64 i=0;i<256;i++)table[i]=(u8)(i*73+19);
 for(u64 i=0;i<256;i++){u64 a=0x123456789abcde00UL|i,b=(u64)table,f;
 XP("0x66");XP("0x40");XP("0x45");XP("0x43");XP("0x4b");
 __asm__ volatile("xlatb; pushfq; popq %[f]" :"+a"(a),[f]"=r"(f):"b"(b):"memory");report_value("xlat",a);
 a=0x123456789abcde00UL|i;b|=0xdeadbeef00000000UL;
 __asm__ volatile("addr32 xlatb; pushfq; popq %[f]" :"+a"(a),[f]"=r"(f):"b"(b):"memory");report_value("xlat32",a);
 }
 for(u64 i=0;i<256;i++){
  long status;u64 a=0x123456789abcde00UL|i,b=0,f,fi=F_ARITH|2;
  __asm__ volatile("syscall":"=a"(status):"a"(158L),"D"(0x1002L),"S"(table):"rcx","r11","memory");
  if(status)return 2;
  __asm__ volatile("pushq %[fi]; popfq; fs xlatb; pushfq; popq %[f]":"+a"(a),[f]"=&r"(f):"b"(b),[fi]"r"(fi):"cc","memory");
  __asm__ volatile("syscall":"=a"(status):"a"(158L),"D"(0x1002L),"S"(0L):"rcx","r11","memory");
  report("xlat-fs",i,0,fi,a,f,F_ARITH);
  a=0x123456789abcde00UL|i;b=0xdeadbeef00000000UL;
  __asm__ volatile("syscall":"=a"(status):"a"(158L),"D"(0x1001L),"S"(table):"rcx","r11","memory");
  if(status)return 3;
  a=0x123456789abcde00UL|i;b=0;
  __asm__ volatile("pushq %[fi]; popfq; gs xlatb; pushfq; popq %[f]":"+a"(a),[f]"=&r"(f):"b"(b),[fi]"r"(fi):"cc","memory");
  report("xlat-gs64",i,0,fi,a,f,F_ARITH);
  a=0x123456789abcde00UL|i;b=0xdeadbeef00000000UL;
  __asm__ volatile("pushq %[fi]; popfq; gs addr32 xlatb; pushfq; popq %[f]":"+a"(a),[f]"=&r"(f):"b"(b),[fi]"r"(fi):"cc","memory");
  __asm__ volatile("syscall":"=a"(status):"a"(158L),"D"(0x1001L),"S"(0L):"rcx","r11","memory");
  report("xlat-gs32",i,0,fi,a,f,F_ARITH);
 }
 for(u64 i=0;i<NVEC;i++){
  u64 fi=(vectors[i]&F_ARITH)|2,f,word=0x123456789abcdef0UL;
  PF("0x67");PF("0x3e");PF("0x26");PF("0x65");PF("0xf2");PF("0x40");PF("0x44");PF("0x46");
  PF("0x48");PF("0x49");PF("0x4d");PF("0x4e");PF("0x4f");PF("0x42");PF("0x36");
  __asm__ volatile("pushq %[fi]; .byte 0x66,0x49,0x9d; pushfq; popq %[f]" :[f]"=&r"(f):[fi]"r"(fi):"cc","memory");
  report_value("popf-data16-rexwb",f&F_ARITH);
  __asm__ volatile("pushq %[fi]; popfq; pushfw; popw %w[word]; pushfq; popq %[f]" :[word]"+r"(word),[f]"=&r"(f):[fi]"r"(fi):"cc","memory");
  report("pushfw",fi,0,fi,word&F_ARITH,f,F_ARITH);
  __asm__ volatile("pushw %w[fi]; popfw; pushfq; popq %[f]" :[f]"=&r"(f):[fi]"r"(fi):"cc","memory");
  report_value("popfw",f&F_ARITH);
 }
 flush_out();return 0;
}


