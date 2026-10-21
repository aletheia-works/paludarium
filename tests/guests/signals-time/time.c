/* Native syscall oracle. No libc: only the U4 syscall and integer ISA under test. */
typedef unsigned long u64;
static long sc(u64 n,u64 a,u64 b,u64 c,u64 d,u64 e,u64 f){
 register u64 r10 __asm__("r10")=d,r8 __asm__("r8")=e,r9 __asm__("r9")=f; long ret;
 __asm__ volatile("syscall":"=a"(ret):"a"(n),"D"(a),"S"(b),"d"(c),"r"(r10),"r"(r8),"r"(r9):"rcx","r11","memory");return ret;
}
static void emit(long a,long b,long c){long values[3]={a,b,c};sc(1,1,(u64)values,sizeof(values),0,0,0);}
void test_main(void){
 long r; long ts[2]={0,0}; long out[2]={-1,-1};
#if CASE == 0
 r=sc(228,1,(u64)ts,0,0,0,0);emit(r,ts[0]>=0,ts[1]>=0&&ts[1]<1000000000);
#elif CASE == 1
 r=sc(228,0,(u64)ts,0,0,0,0);emit(r,ts[0]>0,ts[1]>=0&&ts[1]<1000000000);
#elif CASE == 2
 emit(sc(228,~0UL,(u64)ts,0,0,0,0),sc(228,1,1,0,0,0,0),0);
#elif CASE == 3
 emit(sc(35,(u64)ts,(u64)out,0,0,0,0),out[0],out[1]);
#elif CASE == 4
 ts[1]=1000000000;emit(sc(35,(u64)ts,0,0,0,0,0),sc(35,1,0,0,0,0,0),0);
#elif CASE == 5
 ts[0]=-1;emit(sc(35,(u64)ts,0,0,0,0,0),0,0);
#elif CASE == 6
 emit(sc(230,1,1,(u64)ts,(u64)out,0,0),out[0],out[1]);
#elif CASE == 7
 emit(sc(230,~0UL,0,(u64)ts,0,0,0),sc(230,1,0,1,0,0,0),0);
#endif
}__asm__(".global _start\n_start:\n xor %rbp,%rbp\n and $-16,%rsp\n call test_main\n xor %edi,%edi\n mov $60,%eax\n syscall\n");

