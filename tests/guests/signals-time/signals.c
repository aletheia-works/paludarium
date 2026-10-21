#define _GNU_SOURCE
#include <signal.h>
#include <sys/ucontext.h>
#include <stddef.h>
typedef unsigned long u64;
static long sc(u64 n,u64 a,u64 b,u64 c,u64 d,u64 e,u64 f){register u64 r10 __asm__("r10")=d,r8 __asm__("r8")=e,r9 __asm__("r9")=f;long r;__asm__ volatile("syscall":"=a"(r):"a"(n),"D"(a),"S"(b),"d"(c),"r"(r10),"r"(r8),"r"(r9):"rcx","r11","memory");return r;}
static void emit(long a,long b,long c){long v[3]={a,b,c};sc(1,1,(u64)v,24,0,0,0);}
struct action {u64 handler,flags,restorer,mask;};
struct stack {u64 sp,flags,size;};
extern void restorer(void);
extern char fault_site[];
static char alt[16384] __attribute__((aligned(16)));
static volatile long count,depth;
static u64 copied_frame[64] __attribute__((aligned(16)));
static long pid;
static void handler(int sig,siginfo_t *info,void *context){
 ucontext_t *u=context;u64 mask=0;sc(14,0,0,(u64)&mask,8,0,0);++count;
#if CASE == 5
 char local;struct stack old={0};sc(131,0,(u64)&old,0,0,0,0);emit(sig,((u64)&local>=(u64)alt&&(u64)&local<(u64)alt+sizeof(alt)),old.flags);emit(u->uc_stack.ss_sp==(void*)alt,u->uc_stack.ss_size==sizeof(alt),u->uc_stack.ss_flags);
#elif CASE == 6
 ++depth;emit(depth,(mask>>(sig-1))&1,0);if(depth==1)sc(62,pid,sig,0,0,0,0);--depth;
#elif CASE >= 8 && CASE <= 12
 emit(sig,info->si_code,(u64)info->si_addr-(CASE==8?0x70000000:CASE==9?0x60000000:(u64)fault_site));
 emit(u->uc_mcontext.gregs[REG_RIP]==(long)fault_site,u->uc_mcontext.gregs[REG_EFL]&0xcd5,u->uc_mcontext.gregs[REG_TRAPNO]);
 emit(u->uc_mcontext.gregs[REG_ERR],u->uc_mcontext.gregs[REG_CR2]-(CASE==8?0x70000000:CASE==9?0x60000000:0),u->uc_mcontext.gregs[REG_R12]);
 u->uc_mcontext.gregs[REG_RIP]+=CASE==10||CASE==11?2:3;
#if CASE == 12
 u->uc_mcontext.gregs[REG_R12]=77;
#endif
#elif CASE == 20
 emit(sig,info->si_code,(u64)info->si_addr==0x60000000);emit(u->uc_mcontext.gregs[REG_RIP]==0x60000000,u->uc_mcontext.gregs[REG_ERR],u->uc_mcontext.gregs[REG_TRAPNO]);sc(10,0x60000000,4096,5,0,0,0);
#elif CASE == 21 || CASE == 22
 emit(sig,info->si_code,(u64)info->si_addr==0x60000000);emit(u->uc_mcontext.gregs[REG_ERR],u->uc_mcontext.gregs[REG_TRAPNO],0);sc(10,0x60000000,4096,3,0,0,0);
#elif CASE == 18
 emit(sig,1,0);for(int i=0;i<64;i++)copied_frame[i]=((u64*)((char*)u-8))[i];__asm__ volatile("mov %0,%%rsp;mov $15,%%eax;syscall"::"r"((char*)copied_frame+8):"rax","memory");__builtin_unreachable();
#elif CASE == 15
 emit((u64)u->uc_mcontext.fpregs%64,u->uc_mcontext.fpregs!=0,0);
#elif CASE == 16 || CASE == 17 || CASE == 19
 emit(sig,count,0);
#elif CASE == 13
 emit(sig,1,0);u->uc_mcontext.gregs[REG_RIP]=-1;
#else
 emit(sig,info->si_code,(mask>>(sig-1))&1);
#endif
}
static long install(int sig,u64 flags){struct action a={(u64)handler,flags|4|0x4000000,(u64)restorer,0};return sc(13,sig,(u64)&a,0,8,0,0);}
void test_main(void){pid=sc(39,0,0,0,0,0,0);
#if CASE == 0
 struct action a={(u64)handler,4|0x4000000,(u64)restorer,0},b={0};emit(sc(13,10,(u64)&a,(u64)&b,8,0,0),b.handler,sc(13,9,(u64)&a,0,8,0,0));sc(13,10,0,(u64)&b,8,0,0);emit(b.handler==(u64)handler,b.restorer==(u64)restorer,b.mask);
#elif CASE == 1
 install(10,0);emit(sc(62,pid,10,0,0,0,0),count,0);
#elif CASE == 2
 struct action a={1,0,0,0};sc(13,10,(u64)&a,0,8,0,0);emit(sc(62,pid,10,0,0,0,0),1,0);
#elif CASE == 3
 sc(62,pid,15,0,0,0,0);
#elif CASE == 4
 install(10,0);u64 mask=1UL<<9;sc(14,0,(u64)&mask,0,8,0,0);sc(62,pid,10,0,0,0,0);sc(62,pid,10,0,0,0,0);emit(count,0,0);sc(14,1,(u64)&mask,0,8,0,0);emit(count,1,0);
#elif CASE == 5
 struct stack s={(u64)alt,0,sizeof(alt)};sc(131,(u64)&s,0,0,0,0,0);install(10,0x08000000);sc(62,pid,10,0,0,0,0);emit(count,0,0);
#elif CASE == 6
 install(10,0x40000000);sc(62,pid,10,0,0,0,0);emit(count,0,0);
#elif CASE == 7
 install(10,0x80000000);sc(62,pid,10,0,0,0,0);sc(62,pid,10,0,0,0,0);
#elif CASE >= 8 && CASE <= 12
 install(CASE==10?4:CASE==11?8:11,0);register u64 r12 __asm__("r12")=41;
#if CASE == 9
 sc(9,0x60000000,4096,3,0x32,-1,0);*(volatile char*)0x60000000=42;sc(10,0x60000000,4096,1,0,0,0);
#endif
#if CASE == 10
 __asm__ volatile("pushq $0x246;popfq;.global fault_site\nfault_site:ud2":"+r"(r12)::"memory","cc");
#elif CASE == 11
 __asm__ volatile("mov $1,%%eax;xor %%edx,%%edx;xor %%ecx,%%ecx;pushq $0x246;popfq;.global fault_site\nfault_site:div %%ecx":"+r"(r12)::"rax","rcx","rdx","memory","cc");
#elif CASE == 9
 __asm__ volatile("mov $0x60000000,%%eax;pushq $0x246;popfq;.global fault_site\nfault_site:movb $1,(%%rax)":"+r"(r12)::"rax","memory","cc");
#else
 __asm__ volatile("mov $0x70000000,%%eax;pushq $0x246;popfq;.global fault_site\nfault_site:mov (%%rax),%%rbx":"+r"(r12)::"rax","rbx","memory","cc");
#endif
 emit(r12,CASE==9?*(volatile char*)0x60000000:0,count);
#elif CASE == 13
 install(10,0);sc(62,pid,10,0,0,0,0);
#elif CASE == 20
 sc(9,0x60000000,4096,3,0x32,-1,0);*(volatile char*)0x60000000=(char)0xc3;install(11,0);((void(*)(void))0x60000000)();emit(count,1,0);
#elif CASE == 21 || CASE == 22
 sc(9,0x60000000,4096,CASE==21?0:1,0x32,-1,0);install(11,0);*(volatile char*)0x60000000=1;emit(count,*(volatile char*)0x60000000,0);
#elif CASE == 18
 install(10,0);sc(62,pid,10,0,0,0,0);emit(count,1,0);
#elif CASE == 15
 install(10,0);sc(62,pid,10,0,0,0,0);
#elif CASE == 16 || CASE == 17 || CASE == 19
 install(14,CASE==17?0x10000000:0);long timer[4]={0,0,0,1000};long request[2]={CASE==19?0x7fffffffffffffffL:0,50000000},remaining[2]={0,0};emit(sc(38,0,(u64)timer,0,0,0,0),0,0);long result=sc(35,(u64)request,(u64)remaining,0,0,0,0);emit(result,(CASE==19?remaining[0]>0:(remaining[0]==0&&remaining[1]>0&&remaining[1]<=50000000)),count);
#elif CASE == 14
 emit(offsetof(ucontext_t,uc_mcontext),offsetof(ucontext_t,uc_sigmask),offsetof(siginfo_t,si_addr));emit(offsetof(mcontext_t,fpregs),sizeof(mcontext_t),offsetof(ucontext_t,uc_stack));emit(REG_RSP,REG_RIP,REG_EFL);
#endif
}
__asm__(".global restorer\nrestorer:mov $15,%rax\nsyscall\n.global _start\n_start:xor %rbp,%rbp\nand $-16,%rsp\ncall test_main\nxor %edi,%edi\nmov $60,%eax\nsyscall\n");




