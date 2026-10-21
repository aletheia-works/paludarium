/* Native syscall oracle. No libc: only the U4 syscall and integer ISA under test. */
typedef unsigned long u64;
static long sc(u64 n,u64 a,u64 b,u64 c,u64 d,u64 e,u64 f){
 register u64 r10 __asm__("r10")=d,r8 __asm__("r8")=e,r9 __asm__("r9")=f; long ret;
 __asm__ volatile("syscall":"=a"(ret):"a"(n),"D"(a),"S"(b),"d"(c),"r"(r10),"r"(r8),"r"(r9):"rcx","r11","memory");return ret;
}
static void emit(long a,long b,long c){long values[3]={a,b,c};sc(1,1,(u64)values,sizeof(values),0,0,0);}
void test_main(void){
 const u64 at=0x60000000; long p,r;
#if CASE == 0
 emit(sc(9,0,0,3,0x22,-1,0),sc(11,at,0,0,0,0,0),sc(10,at+1,0,3,0,0,0));
#elif CASE == 1
 p=sc(9,at,4097,3,0x31,-1,0);if(p<0){emit(p,0,0);return;} *(volatile char*)at=41; *(volatile char*)(at+4096)=42;
 emit(p==(long)at,*(volatile char*)at,*(volatile char*)(at+4096));sc(11,at,8192,0,0,0,0);
#elif CASE == 2
 sc(9,at,4096,3,0x32,-1,0);*(volatile char*)at=41;
 r=sc(9,at,~(u64)0,3,0x32,-1,0);emit(r,*(volatile char*)at,0);
#elif CASE == 3
 sc(9,at,4096,3,0x32,-1,0);*(volatile char*)at=41;
 r=sc(9,at,4096,3,0x100022,-1,0);emit(r,*(volatile char*)at,0);
#elif CASE == 4
 sc(9,at,4096,3,0x32,-1,0); sc(9,at+8192,4096,3,0x32,-1,0);
 emit(sc(10,at,12288,1,0,0,0),sc(10,at+1,4096,1,0,0,0),sc(10,at,4096,8,0,0,0));
#elif CASE == 5
 sc(9,at,12288,3,0x32,-1,0);sc(11,at+4096,4096,0,0,0,0);emit(sc(11,at,12288,0,0,0,0),0,0);
 *(volatile char*)at=1;
#elif CASE == 6
 p=sc(12,0,0,0,0,0,0); r=sc(12,p+8192,0,0,0,0,0);long grown=r==p+8192;
 long shrunk=sc(12,p,0,0,0,0,0)==p;long fail=sc(12,~(u64)0,0,0,0,0,0)==p;emit(grown,shrunk,fail);
#elif CASE == 8
 sc(9,at,4096,3,0x32,-1,0);sc(9,at+8192,4096,3,0x32,-1,0);emit(sc(10,at,12288,0,0,0,0),0,0);long value=*(volatile char*)at;emit(value,0,0);
#elif CASE == 9
 sc(9,at,4096,3,0x32,-1,0);*(volatile char*)at=41;emit(sc(9,at,4096,3,0x32,-1,1),*(volatile char*)at,0);
#elif CASE == 7
 p=sc(9,at+123,4096,3,0x22,-1,0);emit(p==(long)at,p>=0,p>=0?sc(11,p,4096,0,0,0,0):p);
#endif
}
__asm__(".global _start\n_start:\n xor %rbp,%rbp\n and $-16,%rsp\n call test_main\n xor %edi,%edi\n mov $60,%eax\n syscall\n");

