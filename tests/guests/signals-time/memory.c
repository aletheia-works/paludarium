/* Native syscall oracle. No libc: only the signals/time syscall and integer ISA under test. */
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
#elif CASE == 10
 /* MADV_DONTNEED zeroes private anonymous pages; shared ones keep their contents. */
 sc(9,at,8192,3,0x32,-1,0);*(volatile char*)at=41;*(volatile char*)(at+4096)=42;
 r=sc(28,at,1,4,0,0,0);emit(r,*(volatile char*)at,*(volatile char*)(at+4096));
 p=sc(9,at+65536,4096,3,0x31,-1,0);*(volatile char*)p=43;
 r=sc(28,p,4096,4,0,0,0);emit(r,*(volatile char*)p,sc(28,p,4096,8,0,0,0));
 emit(sc(28,at,8192,8,0,0,0),sc(28,at,8192,2,0,0,0),sc(28,at,0,4,0,0,0));
#elif CASE == 11
 /* Invalid advice, alignment and length, and a hole in the range. */
 sc(9,at,4096,3,0x32,-1,0);*(volatile char*)at=41;
 emit(sc(28,at,4096,99,0,0,0),sc(28,at+1,4096,4,0,0,0),sc(28,at,~(u64)0,4,0,0,0));
 p=sc(28,at,12288,0,0,0,0);r=sc(28,at,12288,4,0,0,0);emit(p,r,*(volatile char*)at);
 emit(sc(28,at,12288,8,0,0,0),sc(28,at+4096,4096,0,0,0,0),0);
#elif CASE == 12
 /* mremap grows in place, moves when blocked, keeps the contents and shrinks. */
 sc(9,at,4096,3,0x32,-1,0);*(volatile char*)at=41;
 r=sc(25,at,4096,8192,0,0,0);*(volatile char*)(at+4096)=42;emit(r==(long)at,*(volatile char*)at,*(volatile char*)(at+4096));
 sc(9,at+8192,4096,1,0x32,-1,0);
 r=sc(25,at,8192,12288,0,0,0);p=sc(25,at,8192,12288,1,0,0);emit(r,p>0&&p!=(long)at,0);
 if(p>0){emit(*(volatile char*)p,*(volatile char*)(p+4096),*(volatile char*)(p+8192));r=sc(25,p,12288,4096,0,0,0);emit(r==p,0,0);}
 emit(sc(25,at+1,4096,4096,1,0,0),sc(25,at+65536,4096,8192,1,0,0),sc(25,at,4096,0,1,0,0));
#elif CASE == 13
 /* MREMAP_FIXED replaces the target; MREMAP_DONTUNMAP leaves the old range empty. */
 sc(9,at,4096,3,0x32,-1,0);*(volatile char*)at=41;
 sc(9,at+65536,8192,3,0x32,-1,0);*(volatile char*)(at+65536+4096)=43;
 r=sc(25,at,4096,4096,7,at+65536,0);emit(r==(long)(at+65536),*(volatile char*)(at+65536),*(volatile char*)at);
 emit(*(volatile char*)(at+65536+4096),sc(25,at,4096,4096,8,0,0),sc(25,at,4096,4096,2,at+65536,0));
 emit(sc(25,at,4096,8192,5,0,0),sc(25,at,4096,4096,3,at+2048,0),sc(25,at,4096,4096,3,at,0));
#elif CASE == 14
 /* Old length 0 maps shared memory again; msync checks its arguments and the range. */
 sc(9,at,4096,3,0x31,-1,0);*(volatile char*)at=41;
 p=sc(25,at,0,4096,1,0,0);if(p>0)*(volatile char*)p=42;emit(p>0&&p!=(long)at,*(volatile char*)at,0);
 sc(9,at+65536,4096,3,0x32,-1,0);emit(sc(25,at+65536,0,4096,1,0,0),sc(25,at,0,4096,0,0,0),0);
 emit(sc(26,at,4096,4,0,0,0),sc(26,at,4096,3,0,0,0),sc(26,at+1,4096,4,0,0,0));
 emit(sc(26,at,0,4,0,0,0),sc(26,at,8192,4,0,0,0),sc(26,at,4096,8,0,0,0));
 emit(sc(26,at,~(u64)0,1,0,0,0),sc(26,at,4096,2,0,0,0),sc(26,at+65536,4096,1,0,0,0));
#elif CASE == 7
 p=sc(9,at+123,4096,3,0x22,-1,0);emit(p==(long)at,p>=0,p>=0?sc(11,p,4096,0,0,0,0):p);
#endif
}
__asm__(".global _start\n_start:\n xor %rbp,%rbp\n and $-16,%rsp\n call test_main\n xor %edi,%edi\n mov $60,%eax\n syscall\n");

