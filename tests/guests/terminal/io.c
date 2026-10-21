/* Linux x86-64 oracle: raw syscalls and integer instructions only. */
typedef unsigned long u64;
static long sc(u64 n,u64 a,u64 b,u64 c){long r;__asm__ volatile("syscall":"=a"(r):"a"(n),"D"(a),"S"(b),"d"(c):"rcx","r11","memory");return r;}
static void bytes(const void*p,u64 n){sc(1,1,(u64)p,n);}
static void value(long x){bytes(&x,8);}
static u64 length(const char*p){u64 n=0;while(p[n])n++;return n;}
void test_main(u64 *stack){
#if CASE == 0
 u64 argc=*stack;char **argv=(char**)(stack+1);char **env=argv+argc+1;value(argc);
 for(u64 i=0;i<argc;i++){u64 n=length(argv[i]);value(n);bytes(argv[i],n);}
 for(;*env;env++){const char*s=*env;if(s[0]=='U'&&s[1]=='9'&&s[2]=='_'&&s[3]=='T'&&s[4]=='E'&&s[5]=='S'&&s[6]=='T'&&s[7]=='='){value(length(s));bytes(s,length(s));}}
#elif CASE == 1
 char b[8]={0};long n=sc(0,0,(u64)b,8);value(n);if(n>0)bytes(b,n);value(sc(0,0,(u64)b,8));
#elif CASE == 2
 sc(1,1,(u64)"out",3);sc(1,2,(u64)"err",3);
#else
 char b[36]={0};long fd=0;u64 request=0x5401;u64 ptr=(u64)b;u64 n=36;
#if CASE == 4 || CASE == 7 || CASE == 13
 request=0x5413;n=8;
#endif
#if CASE == 5
 fd=999;
#elif CASE == 8
 ptr=1;
#elif CASE == 9
 request=0xdeadbeef;
#elif CASE == 10
 fd=sc(32,0,0,0);
#elif CASE == 11
 fd=sc(2,stack[2],0,0);
#elif CASE == 12
 sc(3,0,0,0);
#elif CASE == 13
 fd=1;
#endif
 long r=sc(16,fd,request,ptr);value(r);if(r==0)bytes(b,n);
#endif
}
__asm__(".global _start\n_start:\n xor %rbp,%rbp\n mov %rsp,%rdi\n and $-16,%rsp\n call test_main\n xor %edi,%edi\n mov $60,%eax\n syscall\n");
