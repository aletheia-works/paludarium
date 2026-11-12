/* Each system call twice: with clean arguments, then with the upper half of
   every 32-bit argument dirty (and bits 16-31 of a umode_t). Linux casts the
   registers to the types its SYSCALL_DEFINEs declare, so the two match, except
   for unsigned long arguments it reads whole (mprotect's prot). readv's vlen
   and vmsplice's nr_segs are unsigned long too, but import_iovec takes them as
   unsigned (until Linux 965e5e451146, 2026-11-05, which makes a dirty one
   EINVAL; the CI kernel predates it). Only whether they match is printed:
   the results themselves are the other guests' business. */
#include <signal.h>
#include <stdio.h>
#include <string.h>
static long sc(long n,long a,long b,long c,long d,long e,long f){
 register long r10 __asm__("r10")=d,r8 __asm__("r8")=e,r9 __asm__("r9")=f; long o;
 __asm__ volatile("syscall":"=a"(o):"a"(n),"D"(a),"S"(b),"d"(c),"r"(r10),"r"(r8),"r"(r9):"rcx","r11","memory"); return o;}
#define S0(n) sc(n,0,0,0,0,0,0)
#define S1(n,a) sc(n,(long)(a),0,0,0,0,0)
#define S2(n,a,b) sc(n,(long)(a),(long)(b),0,0,0,0)
#define S3(n,a,b,c) sc(n,(long)(a),(long)(b),(long)(c),0,0,0)
#define S4(n,a,b,c,d) sc(n,(long)(a),(long)(b),(long)(c),(long)(d),0,0)
#define S5(n,a,b,c,d,e) sc(n,(long)(a),(long)(b),(long)(c),(long)(d),(long)(e),0)
#define S6(n,a,b,c,d,e,f) sc(n,(long)(a),(long)(b),(long)(c),(long)(d),(long)(e),(long)(f))
#define W(v) ((long)(unsigned)(v)|0x1234567800000000L)
static void out(const char*n,long c,long d){if(c==d)printf("%s: same\n",n);else printf("%s: differs, %ld then %ld\n",n,c,d);}
/* Run the block once with D(v)=v and once with D(v)=W(v); r is the result. */
#define P(name,...) do{long r_[2];for(int dirty=0;dirty<2;dirty++){long r=0;__VA_ARGS__;r_[dirty]=r;}out(name,r_[0],r_[1]);}while(0)
#define D(v) (dirty?W(v):(long)(int)(v))
static char F[]="/tmp/paludarium-arguments-file",G[]="/tmp/paludarium-arguments-dir",H[]="/tmp/paludarium-arguments-h",L[]="/tmp/paludarium-arguments-l";
static char buf[4096];static unsigned char st[256];
static int fd;
/* A SA_RESTART handler that fills the pipe a blocked read waits on. */
static int sp[2];
static void tick(int s){(void)s;S3(1,sp[1],"x",1);}
static void arm(void){long it[4]={0,0,0,20000};S3(38,0,it,0);}
int main(void){
 S1(87,F);S1(87,H);S1(87,L);S1(84,G);
 fd=S3(2,F,66,0644);S3(1,fd,"hello world",11);
 S2(83,G,0755);
 P("syscall number",{r=sc(dirty?W(39):39,0,0,0,0,0,0)==S0(39);});
 /* Numbers that one handler serves among others: files, epoll, sockets. */
 P("number of lseek",{r=sc(dirty?W(8):8,fd,0,1,0,0,0);});
 P("number of epoll_create1",{long e=sc(dirty?W(291):291,0,0,0,0,0,0);r=e>=0;S1(3,e);});
 P("number of socket",{long k=sc(dirty?W(41):41,1,1,0,0,0,0);r=k>=0;S1(3,k);});
 P("negative syscall number",{r=sc(dirty?0x12345678ffffffffL:-1L,0,0,0,0,0,0);});
 #ifdef RESTARTS
 /* Case 61: a dirty rax with a restart. poll is ERESTARTNOHAND, so a handler
    makes it EINTR even with SA_RESTART; read is ERESTARTSYS and runs again.
    It needs a real-time itimer, so it runs on the emulator's own host only. */
 {struct sigaction a;memset(&a,0,sizeof a);a.sa_handler=tick;a.sa_flags=SA_RESTART;sigaction(SIGALRM,&a,0);}
 S2(293,sp,0);
 P("poll restart",{int pf[2]={sp[0],1};arm();r=sc(dirty?W(7):7,(long)pf,1,-1,0,0,0);char c;S3(0,sp[0],&c,1);});
 P("read restart",{char c;arm();r=sc(dirty?W(0):0,sp[0],(long)&c,1,0,0,0);});
 S1(3,sp[0]);S1(3,sp[1]);signal(SIGALRM,SIG_DFL);
 #else
 /* files */
 P("open flags,mode",{long f=S3(2,F,D(0),D(0));r=f>=0;S1(3,f);});
 P("openat dfd,flags",{long f=S4(257,D(-100),F,D(0),D(0));r=f>=0;S1(3,f);});
 P("creat mode",{long f=S2(85,H,D(0600));S2(5,f,st);r=*(unsigned*)(st+24);S1(3,f);S1(87,H);});
 P("lseek whence",{r=S3(8,fd,2,D(0));});
 P("pread64 fd",{r=S4(17,D(fd),buf,3,1);});
 P("readv vlen",{long iov[2]={(long)buf,3};r=S3(19,fd,iov,dirty?W(1):1);});
 P("writev vlen",{long iov[2]={(long)"abc",3};r=S3(20,fd,iov,dirty?W(1):1);});
 P("preadv vlen",{long iov[2]={(long)buf,3};r=S5(295,fd,iov,dirty?W(1):1,0,0);});
 P("access mode",{r=S2(21,F,D(4));});
 P("faccessat dfd,mode",{r=S3(269,D(-100),F,D(4));});
 P("faccessat2 mode,flags",{r=S4(439,D(-100),F,D(4),D(0x200));});
 P("newfstatat flags",{r=S4(262,D(-100),F,st,D(0x100));});
 P("statx flags,mask",{r=S5(332,D(-100),F,D(0x100),D(0x7ff),buf);if(!r)r=*(unsigned*)buf;});
 P("utimensat flags",{r=S4(280,D(-100),F,0,D(0x100));});
 P("fchmod mode",{r=S2(91,fd,D(0640));S2(5,fd,st);r=r*100000+*(unsigned*)(st+24);S2(91,fd,0644);});
 P("chmod mode hi16",{r=S2(90,F,dirty?0x12340000|0640:0640);S2(5,fd,st);r=r*100000+*(unsigned*)(st+24);S2(91,fd,0644);});
 P("fchmodat dfd,mode",{r=S3(268,D(-100),F,D(0640));S2(5,fd,st);r=r*100000+*(unsigned*)(st+24);S2(91,fd,0644);});
 P("fchmodat2 flags",{r=S4(452,D(-100),F,D(0640),D(0));S2(5,fd,st);r=r*100000+*(unsigned*)(st+24);S2(91,fd,0644);});
 P("fchown -1,-1",{r=S3(93,fd,D(-1),D(-1));S2(5,fd,st);r=r*100000+*(unsigned*)(st+28);});
 P("fchownat flags",{r=S5(260,D(-100),F,D(-1),D(-1),D(0x100));});
 P("open mode hi16",{long f=S3(2,H,65,dirty?0x12340000|0600:0600);S2(5,f,st);r=*(unsigned*)(st+24);S1(3,f);S1(87,H);});
 P("mkdir mode hi16",{r=S2(83,H,dirty?0x12340000|0700:0700);S2(4,H,st);r=r*100000+*(unsigned*)(st+24);S1(84,H);});
 P("mkdir mode",{r=S2(83,H,D(0700));S2(4,H,st);r=r*100000+*(unsigned*)(st+24);S1(84,H);});
 P("mkdirat dfd,mode",{r=S3(258,D(-100),H,D(0700));S1(84,H);});
 P("mknodat mode,dev",{r=S4(259,D(-100),H,D(0100600),D(0));S1(87,H);});
 P("unlinkat flags",{S2(83,H,0700);r=S3(263,D(-100),H,D(0x200));S1(84,H);});
 P("linkat flags",{r=S5(265,D(-100),F,D(-100),H,D(0));S1(87,H);});
 P("symlinkat dfd",{r=S3(266,F,D(-100),L);S1(87,L);});
 P("readlinkat bufsiz",{S2(88,F,L);r=S4(267,D(-100),L,buf,D(100));S1(87,L);});
 P("renameat2 flags",{S3(2,H,66,0644);r=S5(316,D(-100),H,D(-100),L,D(0));S1(87,L);S1(87,H);});
 P("getdents64 count",{long d=S2(2,G,65536);r=S3(217,d,buf,D(4096));S1(3,d);});
 P("flock cmd",{r=S2(73,fd,D(1));S2(73,fd,8);});
 P("fadvise64 advice",{r=S4(221,fd,0,0,D(0));});
 P("fallocate mode",{r=S4(285,fd,D(0),0,20);});
 P("sync_file_range flags",{r=S4(277,fd,0,0,D(1));});
 P("copy_file_range flags",{long g=S3(2,H,66,0644);long o=0;r=S6(326,fd,&o,g,0,3,D(0));S1(3,g);S1(87,H);});
 P("sendfile fds",{long g=S3(2,H,66,0644);long o=0;r=S4(40,D(g),D(fd),&o,3);S1(3,g);S1(87,H);});
 P("splice fds,flags",{int p[2];S2(293,p,0);long o=0;r=S6(275,D(fd),&o,D(p[1]),0,3,D(0));long g=S3(2,H,66,0644);r=r*10+S6(275,D(p[0]),0,D(g),0,3,D(0));S1(3,g);S1(87,H);S1(3,p[0]);S1(3,p[1]);});
 P("tee fds,flags",{int p[2],q[2];S2(293,p,0);S2(293,q,0);S3(1,p[1],"abc",3);r=S4(276,D(p[0]),D(q[1]),3,D(0));if(r>0)r=r*10+S3(0,q[0],buf,3);S1(3,p[0]);S1(3,p[1]);S1(3,q[0]);S1(3,q[1]);});
 P("vmsplice fd,nr_segs,flags",{int p[2];S2(293,p,0);long iov[2]={(long)"abc",3};r=S4(278,D(p[1]),iov,dirty?W(1):1,D(0));if(r>0)r=r*10+S3(0,p[0],buf,3);S1(3,p[0]);S1(3,p[1]);});
 P("dup3 flags",{long g=S3(292,fd,50,D(0x80000));r=g>=0?S2(72,50,1):g;S1(3,50);});
 P("pipe2 flags",{int p[2];r=S2(293,p,D(0x80000));if(!r){r=S2(72,p[0],1);S1(3,p[0]);S1(3,p[1]);}});
 P("close_range flags",{S1(32,fd);r=S3(436,D(100),D(200),D(4));});
 P("memfd_create flags",{long m=S2(319,"p",D(1));r=m>=0?S2(72,m,1):m;S1(3,m);});
 P("umask",{long o=S1(95,D(022));r=S1(95,o);});
 /* memory */
 P("madvise behavior",{r=S3(28,buf-((long)buf&4095),4096,D(0));});
 P("msync flags",{long m=S6(9,0,4096,3,0x22,-1,0);r=S3(26,m,4096,D(4));S2(11,m,4096);});
 P("mprotect prot(ulong)",{long m=S6(9,0,4096,3,0x22,-1,0);r=S3(10,m,4096,dirty?W(1):1);S2(11,m,4096);});
 P("mmap fd(ulong)",{long m=S6(9,0,4096,1,2,dirty?W(fd):fd,0);r=m>0;S2(11,m,4096);});
 P("mlock2 flags",{r=S3(325,buf-((long)buf&4095),4096,D(0));});
 P("mlockall flags",{r=S1(151,D(0));});
 /* signals */
 P("kill pid,sig",{r=S2(62,D(S0(39)),D(0));});
 P("tkill tid,sig",{r=S2(200,D(S0(186)),D(0));});
 P("tgkill sig",{r=S3(234,D(S0(39)),D(S0(186)),D(0));});
 P("rt_sigaction sig",{unsigned long a[4];r=S4(13,D(10),0,a,8);if(!r)r=a[0];});
 P("rt_sigprocmask how",{unsigned long s=0,o;r=S4(14,D(0),&s,&o,8);});
 P("rt_sigqueueinfo sig",{int info[32]={0};info[2]=-1;r=S3(129,D(S0(39)),D(0),info);});
 P("pidfd_open flags",{long p=S2(434,D(S0(39)),D(0));r=p>=0;if(p>=0){r=S4(424,D(p),D(0),0,D(0));S1(3,p);}});
 P("signalfd4 fd,flags",{unsigned long m=1<<9;long s=S4(289,D(-1),&m,8,D(0x80000));r=s>=0?S2(72,s,1):s;S1(3,s);});
 P("alarm seconds",{S1(37,D(0));r=S1(37,0);});
 P("getitimer which",{long v[4];r=S2(36,D(0),v);});
 P("setitimer which",{long v[4]={0},o[4];r=S3(38,D(0),v,o);});
 /* processes */
 P("wait4 pid,options",{r=S4(61,D(-1),0,D(1),0);});
 P("waitid which,options",{int info[32];r=S5(247,D(0),0,info,D(5),0);});
 P("getpriority which,who",{r=S2(140,D(0),D(0));});
 P("setpriority prio",{long p=S2(140,0,0);r=S3(141,D(0),D(0),D(20-p));});
 P("getrlimit resource",{long l[2];r=S2(97,D(7),l);if(!r)r=l[0];});
 P("setrlimit resource",{long l[2];S2(97,7,l);r=S2(160,D(7),l);});
 P("prlimit64 pid,resource",{long l[2];r=S4(302,D(0),D(7),0,l);if(!r)r=l[0];});
 P("getrusage who",{r=S2(98,D(0),buf);});
 P("prctl option",{r=S1(157,D(3));});
 P("arch_prctl option",{long v;r=S2(158,D(0x1003),&v);if(!r)r=v!=0;});
 P("setpgid",{r=S2(109,D(0),D(0));});
 P("getpgid",{r=S1(121,D(0))>0;});
 P("getsid",{r=S1(124,D(0))>0;});
 P("setresuid -1",{r=S3(117,D(-1),D(-1),D(-1));});
 P("setresgid -1",{r=S3(119,D(-1),D(-1),D(-1));});
 P("setreuid -1",{r=S2(113,D(-1),D(-1));});
 P("setfsuid -1",{r=S1(122,D(-1));});
 P("getgroups size",{r=S2(115,D(0),0);});
 P("sched_getaffinity pid,len",{r=S3(204,D(0),D(128),buf);});
 /* time */
 P("clock_gettime clock",{long t[2];r=S2(228,D(1),t);});
 P("clock_getres clock",{long t[2];r=S2(229,D(1),t);if(!r)r=t[1];});
 P("clock_nanosleep clock,flags",{long t[2]={0,0};r=S4(230,D(1),D(0),t,0);});
 P("timer_create clock",{int id;long ev[8]={0};((int*)ev)[3]=1;r=S3(222,D(1),ev,&id);if(!r){long v[4]={0};r=S4(223,D(id),D(0),v,0);r=r*10+S2(224,D(id),v);r=r*10+S1(225,D(id));r=r*10+S1(226,D(id));}});
 P("timerfd_create clock,flags",{long t=S2(283,D(1),D(0x80000));r=t>=0?S2(72,t,1):t;if(t>=0){long v[4]={0};r=r*10+S4(286,D(t),D(0),v,0);}S1(3,t);});
 /* events */
 P("eventfd2 count,flags",{long e=S2(290,D(5),D(0x80000));r=e>=0?S2(72,e,1):e;if(e>=0){unsigned long v=0;S3(0,e,&v,8);r=r*10+v;}S1(3,e);});
 P("eventfd count",{long e=S1(284,D(5));unsigned long v=0;S3(0,e,&v,8);r=v;S1(3,e);});
 P("epoll_create1 flags",{long e=S1(291,D(0x80000));r=e>=0?S2(72,e,1):e;S1(3,e);});
 P("epoll_ctl op,fd",{long e=S1(291,0);int p[2];S2(293,p,0);unsigned ev[3]={1,7,0};r=S4(233,D(e),D(1),D(p[0]),ev);r=r*10+S4(232,D(e),ev,D(1),D(0));r=r*10+S4(233,e,D(2),D(p[0]),ev);S1(3,e);S1(3,p[0]);S1(3,p[1]);});
 P("epoll_pwait maxev,timeout",{long e=S1(291,0);unsigned ev[3];r=S6(281,D(e),ev,D(1),D(0),0,8);S1(3,e);});
 P("poll nfds,timeout",{int pf[2]={fd,1};r=S3(7,pf,D(1),D(0));});
 P("ppoll nfds(uint)",{int pf[2]={fd,1};long t[2]={0,0};r=S5(271,pf,D(1),t,0,8);});
 P("select n",{long tv[2]={0,0};r=S5(23,D(0),0,0,0,tv);});
 P("pselect6 n",{long tv[2]={0,0};r=S6(270,D(0),0,0,0,tv,0);});
 P("futex op,val",{static unsigned w=0;long t[2]={0,0};r=S4(202,&w,D(128),D(0),t);});
 P("futex wake op,val",{static unsigned w=0;r=S3(202,&w,D(129),D(1));});
 P("getrandom flags",{r=S3(318,buf,8,D(1));});
 /* sockets */
 P("socket domain,type,proto",{long s=S3(41,D(1),D(1),D(0));r=s>=0;S1(3,s);});
 P("socket inet",{long s=S3(41,D(2),D(2),D(0));r=s>=0;S1(3,s);});
 P("socketpair",{int sv[2];r=S4(53,D(1),D(1),D(0),sv);if(!r){r=S6(44,D(sv[0]),"ab",2,D(0x4000),0,D(0));r=r*10+S6(45,D(sv[1]),buf,2,D(0x40),0,0);r=r*10+S2(48,D(sv[0]),D(1));S1(3,sv[0]);S1(3,sv[1]);}});
 P("setsockopt level,name,len",{long s=S3(41,1,1,0);int v=1;r=S5(54,D(s),D(1),D(2),&v,D(4));int g=0,gl=4;r=r*10+S5(55,D(s),D(1),D(2),&g,&gl);r=r*10+g;S1(3,s);});
 P("bind/listen/accept4",{long s=S3(41,1,1,0);char a[110]={1,0};strcpy(a+2,"/tmp/paludarium-arguments-sock");S1(87,"/tmp/paludarium-arguments-sock");r=S3(49,D(s),a,D(33));r=r*10+S2(50,D(s),D(4));long c=S3(41,1,1,0);r=r*10+S3(42,D(c),a,D(33));long k=S4(288,D(s),0,0,D(0x80000));r=r*10+(k>=0);if(k>=0)r=r*10+S2(72,k,1);S1(3,k);S1(3,c);S1(3,s);S1(87,"/tmp/paludarium-arguments-sock");});
 P("sendmsg/recvmsg flags",{int sv[2];S4(53,1,1,0,sv);long iov[2]={(long)"xy",2};long m[7]={0,0,(long)iov,1,0,0,0};r=S3(46,sv[0],m,D(0x4000));long iov2[2]={(long)buf,2};long m2[7]={0,0,(long)iov2,1,0,0,0};r=r*10+S3(47,sv[1],m2,D(0x40));S1(3,sv[0]);S1(3,sv[1]);});
 #endif
 S1(3,fd);S1(87,F);S1(84,G);
 return 0;
}
