/* Raw Linux ABI: native result is regenerated before every comparison. */
static long call(long n,long a,long b,long c,long d,long e,long f) {
 register long r10 __asm__("r10")=d,r8 __asm__("r8")=e,r9 __asm__("r9")=f;
 long out; __asm__ volatile("syscall":"=a"(out):"a"(n),"D"(a),"S"(b),"d"(c),"r"(r10),"r"(r8),"r"(r9):"rcx","r11","memory"); return out;
}
#define S(n,a,b,c) call(n,(long)(a),(long)(b),(long)(c),0,0,0)
static char p[]="/tmp/paludarium-files-fixture",q[]="/tmp/paludarium-files-link",r[]="/tmp/paludarium-files-renamed";
static char buf[4096]; static long results[96]; static unsigned char st[144];
/* "/proc/self/fd/<n>", and whether a read link (n bytes) is b. */
static char *numbered(const char *s,long n) {
 static char b[32]; char *q=b; char d[12]; int k=0;
 while(*s)*q++=*s++; do{d[k++]='0'+n%10;n/=10;}while(n); while(k)*q++=d[--k]; *q=0; return b;
}
static char *fdpath(long n) { return numbered("/proc/self/fd/",n); }
static long same(const char *a,long n,const char *b){long i=0;for(;b[i];i++)if(i>=n||a[i]!=b[i])return 0;return i==n;}
static long starts(const char *a,long n,const char *b){long i=0;for(;b[i];i++)if(i>=n||a[i]!=b[i])return 0;return 1;}
/* Whole pages of the program's own data (in the file) and bss (not). */
static char data_pages[8192] __attribute__((aligned(4096))) = {1, 2, 3};
static char bss_pages[8192] __attribute__((aligned(4096)));
#if CASE==56
/* fcntl(fd, cmd, flock) with the syscall at lock_at, so that a handler can
   tell from the frame that a signal came during the call. */
__asm__(".global lock_call\nlock_call: xor %ecx,%ecx\nmov $72,%eax\n.global lock_at\nlock_at: syscall\n"
        ".global lock_ret\nlock_ret: ret\n.global restorer\nrestorer: mov $15,%rax\nsyscall");
extern long lock_call(long fd,long cmd,void *fl);
extern char lock_at[],lock_ret[];
extern void restorer(void);
static long hit,hit_rax,hit_at,hit_fd;
/* ucontext: the registers from byte 40 (rax 13th, rcx 14th, rip 16th).
   rcx holds lock_ret only once the syscall ran; a signal during the wait
   leaves rip at lock_at with rax the call's number again (SA_RESTART) or
   at lock_ret with -EINTR. */
static void interrupted(int sig,void *info,unsigned char *uc) {
 (void)sig;(void)info;
 unsigned long rip=*(unsigned long*)(uc+168),rcx=*(unsigned long*)(uc+152);
 if(!hit&&rcx==(unsigned long)lock_ret&&(rip==(unsigned long)lock_at||rip==(unsigned long)lock_ret)){
  hit=1;hit_rax=*(long*)(uc+144);hit_at=rip==(unsigned long)lock_at;S(1,hit_fd,"h",1);
 }
}
#endif
void _start(void) {
 long fd,x=0;
 if(CASE==0) results[x++]=S(4,0,st,0);
 else if(CASE==1) results[x++]=S(6,0,st,0);
 else if(CASE==2) results[x++]=call(262,-100,0,(long)st,0,0,0);
 else {
 S(87,p,0,0);S(87,q,0,0);S(87,r,0,0);
 fd=call(257,-100,(long)p,66,0644,0,0);
 if(CASE==3){results[x++]=fd>=0;results[x++]=S(1,fd,"abc",3);results[x++]=S(8,fd,0,0);results[x++]=S(0,fd,buf,4);results[x++]=buf[0]+buf[1]+buf[2];}
 if(CASE==4){results[x++]=S(86,p,q,0);results[x++]=S(4,q,st,0);results[x++]=*(long*)(st+16);}
 if(CASE==5){results[x++]=S(88,p,q,0);results[x++]=S(89,q,buf,4096);results[x++]=S(6,q,st,0);results[x++]=(*(unsigned*)(st+24)&0170000)==0120000;}
 if(CASE==6){results[x++]=S(82,p,r,0);results[x++]=S(4,p,st,0);results[x++]=S(4,r,st,0);}
 if(CASE==7){results[x++]=S(73,fd,6,0);long b=S(2,p,2,0);results[x++]=S(73,b,6,0);results[x++]=S(73,fd,8,0);results[x++]=S(73,b,6,0);S(3,b,0,0);}
 if(CASE==8){results[x++]=S(5,fd,st,0);results[x++]=S(5,-1,st,0);results[x++]=S(5,fd,1,0);}
 if(CASE==9){results[x++]=S(1,fd,"xyz",3);S(87,p,0,0);results[x++]=S(8,fd,0,0);results[x++]=S(0,fd,buf,3);results[x++]=buf[0]+buf[1]+buf[2];}
 if(CASE==10){long d=S(32,fd,0,0);results[x++]=d>=0;results[x++]=S(1,d,"ab",2);results[x++]=S(8,fd,0,1);S(3,d,0,0);}
 if(CASE==11){results[x++]=S(2,p,193,0644);results[x++]=S(8,fd,-1,0);results[x++]=S(0,fd,1,1);}
 if(CASE==12){results[x++]=S(83,r,0755,0);results[x++]=S(4,r,st,0);results[x++]=(*(unsigned*)(st+24)&0170000)==0040000;results[x++]=S(84,r,0,0);}
 if(CASE==13){long d=S(2,"/tmp",65536,0);long n=S(217,d,buf,4096);results[x++]=n>0;results[x++]=S(217,d,buf,1);S(3,d,0,0);}
 if(CASE==14){results[x++]=call(265,-100,(long)p,-100,(long)q,0,0);results[x++]=call(264,-100,(long)q,-100,(long)r,0,0);results[x++]=call(263,-100,(long)r,0,0,0,0);}
 if(CASE==15){results[x++]=call(266,(long)p,-100,(long)q,0,0,0);results[x++]=call(267,-100,(long)q,(long)buf,4096,0,0);}
 if(CASE==16){results[x++]=S(2,p,131072,0);results[x++]=call(262,-100,(long)p,(long)st,0x100,0,0);}
 if(CASE==17){results[x++]=S(77,fd,8,0);results[x++]=S(5,fd,st,0);results[x++]=*(long*)(st+48);results[x++]=S(8,fd,0,2);}
 if(CASE==18){long d=S(72,fd,0,10);results[x++]=d;results[x++]=S(72,d,3,0)&3;results[x++]=S(3,d,0,0);}
 if(CASE==19){S(88,"/tmp/missing",q,0);results[x++]=S(4,q,st,0);results[x++]=S(6,q,st,0);results[x++]=S(2,q,131072,0);}
 if(CASE==20){results[x++]=S(4,"",st,0);results[x++]=S(2,"",0,0);results[x++]=S(89,"",buf,10);}
 if(CASE==21){S(87,p,0,0);S(88,p,q,0);long d=S(2,q,66,0600);results[x++]=d>=0;results[x++]=S(1,d,"a",1);results[x++]=S(4,p,st,0);results[x++]=*(long*)(st+48);S(3,d,0,0);}
 if(CASE==22){S(83,r,0755,0);long d=S(2,r,65536,0);S(82,r,q,0);long f=call(257,d,(long)"child",66,0600,0,0);results[x++]=f>=0;results[x++]=S(1,f,"ok",2);S(3,f,0,0);results[x++]=call(263,d,(long)"child",0,0,0,0);S(3,d,0,0);S(84,q,0,0);}
 if(CASE==23){S(3,0,0,0);long d=S(2,p,2,0);results[x++]=d;results[x++]=S(1,d,"io",2);S(8,d,0,0);results[x++]=S(0,d,buf,2);S(3,d,0,0);}
 if(CASE==24){long original=S(32,1,0,0);results[x++]=S(33,fd,1,0);results[x++]=S(1,1,"io",2);S(33,original,1,0);S(3,original,0,0);S(8,fd,0,0);results[x++]=S(0,fd,buf,2);}
 if(CASE==25){long d=S(33,1,6,0);results[x++]=d;results[x++]=S(1,d,"out",3);S(3,d,0,0);}
 if(CASE==26){long d=S(32,fd,0,0);long b=S(2,p,2,0);results[x++]=S(73,fd,6,0);S(3,fd,0,0);results[x++]=S(73,b,6,0);S(3,d,0,0);results[x++]=S(73,b,6,0);S(3,b,0,0);}
 if(CASE==27){S(1,fd,"a",1);results[x++]=S(72,fd,4,1024);S(8,fd,0,0);results[x++]=S(1,fd,"b",1);S(8,fd,0,0);results[x++]=S(0,fd,buf,2);}
 if(CASE==28){results[x++]=S(1,fd,1,0x7fffffff);results[x++]=S(0,fd,1,0x7fffffff);}
 if(CASE==29){S(83,r,0755,0);results[x++]=S(4,r,st,0);results[x++]=*(long*)(st+16);S(84,r,0,0);}
 if(CASE==30){S(86,p,q,0);results[x++]=S(82,p,q,0);results[x++]=S(4,p,st,0);results[x++]=*(long*)(st+16);S(2,r,66,0600);results[x++]=S(82,p,r,0);results[x++]=S(4,r,st,0);results[x++]=*(long*)(st+16);}
 if(CASE==31){long d=S(2,p,64,0600);results[x++]=d>=0;results[x++]=S(0,d,buf,1);S(3,d,0,0);}
 if(CASE==32){S(83,r,0755,0);S(88,r,q,0);results[x++]=S(84,"/tmp/paludarium-files-link/",0,0);results[x++]=S(82,"/tmp/paludarium-files-link/",p,0);results[x++]=S(87,"/tmp/paludarium-files-link/",0,0);results[x++]=S(4,r,st,0);results[x++]=S(6,q,st,0);results[x++]=S(2,"/tmp/paludarium-files-unused",64|65536,0600);results[x++]=S(4,"/tmp/paludarium-files-unused",st,0);S(87,"/tmp/paludarium-files-unused",0,0);S(87,q,0,0);S(84,r,0,0);}
 #define MODE() (*(unsigned*)(st+24)&07777)
 #define MTIME() (*(long*)(st+88))
 if(CASE==33){S(95,077,0,0);results[x++]=S(95,022,0,0);results[x++]=S(95,077,0,0);long d=S(2,q,66,0666);S(5,d,st,0);results[x++]=MODE();S(3,d,0,0);results[x++]=S(83,r,0777,0);S(4,r,st,0);results[x++]=MODE();S(84,r,0,0);S(95,022,0,0);}
 if(CASE==34){results[x++]=S(90,p,0600,0);S(4,p,st,0);results[x++]=MODE();results[x++]=S(91,fd,0640,0);S(5,fd,st,0);results[x++]=MODE();results[x++]=call(268,-100,(long)p,0604,0,0,0);S(4,p,st,0);results[x++]=MODE();
  S(88,p,q,0);results[x++]=S(90,q,0611,0);S(6,q,st,0);results[x++]=(*(unsigned*)(st+24)&0170000)==0120000;S(4,p,st,0);results[x++]=MODE();results[x++]=S(90,"/tmp/paludarium-files-missing",0600,0);results[x++]=S(91,99,0600,0);}
 if(CASE==35){static long t[4];const long omit=(1L<<30)-2;
  t[0]=1;t[1]=2;t[2]=1000;t[3]=500;results[x++]=call(280,-100,(long)p,(long)t,0,0,0);S(4,p,st,0);results[x++]=MTIME();results[x++]=*(long*)(st+96);
  t[1]=omit;t[3]=omit;results[x++]=call(280,-100,(long)p,(long)t,0,0,0);S(4,p,st,0);results[x++]=MTIME();
  S(88,p,q,0);t[1]=0;t[2]=-3;t[3]=7;results[x++]=call(280,-100,(long)q,(long)t,0x100,0,0);S(6,q,st,0);results[x++]=MTIME();S(4,p,st,0);results[x++]=MTIME();
  t[2]=2000;t[3]=0;results[x++]=call(280,fd,0,(long)t,0,0,0);S(5,fd,st,0);results[x++]=MTIME();
  t[2]=3000;results[x++]=call(280,fd,(long)"",(long)t,0x1000,0,0);S(5,fd,st,0);results[x++]=MTIME();
  t[1]=1000000000;results[x++]=call(280,-100,(long)p,(long)t,0,0,0);t[1]=0;results[x++]=call(280,-100,(long)p,(long)t,2,0,0);results[x++]=call(280,fd,0,(long)t,0x100,0,0);
  t[1]=omit;t[3]=omit;results[x++]=call(280,-100,(long)"/tmp/paludarium-files-missing",(long)t,0,0,0);results[x++]=call(280,-100,(long)p,8,0,0,0);}
 if(CASE==36){int pipefd[2];S(22,pipefd,0,0);results[x++]=S(74,fd,0,0);results[x++]=S(75,fd,0,0);results[x++]=S(74,pipefd[0],0,0);results[x++]=S(75,99,0,0);results[x++]=S(162,0,0,0);
  results[x++]=call(221,fd,0,0,2,0,0);results[x++]=call(221,pipefd[0],0,0,2,0,0);results[x++]=call(221,fd,0,0,6,0,0);results[x++]=call(221,fd,0,-1,0,0,0);results[x++]=call(221,99,0,0,0,0,0);S(3,pipefd[0],0,0);S(3,pipefd[1],0,0);}
 #define MMAP(len,prot,flags,f,off) call(9,0,len,prot,flags,f,off)
 if(CASE==37){S(1,fd,"hello",5);char*m=(char*)MMAP(8192,1,2,fd,0);results[x++]=(long)m>0;results[x++]=m[0]+m[4];results[x++]=m[5];results[x++]=S(8,fd,0,1);
  char*w=(char*)MMAP(4096,3,2,fd,0);w[0]='X';S(8,fd,0,0);S(0,fd,buf,1);results[x++]=buf[0];results[x++]=m[0];
  long d=S(2,p,0,0);char*s=(char*)MMAP(4096,1,1,d,0);results[x++]=s[1];results[x++]=S(10,s,4096,3);results[x++]=MMAP(4096,3,1,d,0);
  results[x++]=S(28,m,4096,8);results[x++]=S(28,m,4096,4);results[x++]=m[1];
  results[x++]=S(11,m,8192,0);results[x++]=S(11,w,4096,0);results[x++]=S(11,s,4096,0);S(3,d,0,0);}
 if(CASE==38){S(1,fd,buf,4096);S(1,fd,"Z",1);long w=S(2,p,1,0),o=S(2,p,010000000,0),d=S(2,"/tmp",65536,0);int pipefd[2];S(22,pipefd,0,0);
  char*m=(char*)MMAP(4096,1,2,fd,4096);results[x++]=m[0];results[x++]=m[1];results[x++]=S(11,m,4096,0);
  results[x++]=MMAP(4096,1,2,w,0);results[x++]=MMAP(4096,1,1,w,0);results[x++]=MMAP(4096,1,2,o,0);results[x++]=MMAP(4096,1,2,d,0);results[x++]=MMAP(4096,1,2,pipefd[0],0);
  results[x++]=MMAP(4096,1,2,99,0);results[x++]=MMAP(0,1,2,99,0);results[x++]=MMAP(0,1,2,fd,0);results[x++]=MMAP(4096,1,2,fd,1);results[x++]=MMAP(4096,1,2,fd,-4096);results[x++]=MMAP(4096,1,2,fd,1L<<62)>0;
  S(3,w,0,0);S(3,o,0,0);S(3,d,0,0);S(3,pipefd[0],0,0);S(3,pipefd[1],0,0);}
 if(CASE==39||CASE==40){static long a,b;int pf[2];S(1,fd,"0123456789",10);S(8,fd,0,0);
  long o=call(257,-100,(long)q,66,0644,0,0),ro=S(2,q,0,0),ap=S(2,q,02001,0),wo=S(2,p,1,0),d=S(2,"/tmp",65536,0);S(22,pf,0,0);
  if(CASE==39){ /* copy_file_range(fd_in, off_in, fd_out, off_out, len, flags) */
   results[x++]=call(326,fd,0,o,0,4,0);results[x++]=S(8,fd,0,1);results[x++]=S(8,o,0,1);
   a=2;b=0;results[x++]=call(326,fd,(long)&a,o,(long)&b,100,0);results[x++]=a;results[x++]=b;results[x++]=S(8,fd,0,1);
   results[x++]=call(326,fd,(long)&a,o,(long)&b,100,0);results[x++]=call(326,fd,0,o,0,1,1);results[x++]=call(326,99,0,o,0,1,0);
   results[x++]=call(326,fd,0,ro,0,1,0);results[x++]=call(326,fd,0,ap,0,1,0);results[x++]=call(326,wo,0,o,0,1,0);
   results[x++]=call(326,d,0,o,0,1,0);results[x++]=call(326,pf[0],0,o,0,1,0);results[x++]=call(326,fd,0,pf[1],0,1,0);
   a=0;b=2;results[x++]=call(326,fd,(long)&a,fd,(long)&b,4,0);a=0;b=10;results[x++]=call(326,fd,(long)&a,fd,(long)&b,4,0);
   a=-1;results[x++]=call(326,fd,(long)&a,o,0,1,0);a=-100;results[x++]=call(326,fd,(long)&a,o,0,1,0);results[x++]=call(326,fd,1,o,0,1,0);
  } else { /* sendfile(out_fd, in_fd, offset, count) */
   results[x++]=call(40,o,fd,0,4,0,0);results[x++]=S(8,fd,0,1);results[x++]=S(8,o,0,1);
   a=6;results[x++]=call(40,o,fd,(long)&a,100,0,0);results[x++]=a;results[x++]=S(8,fd,0,1);
   results[x++]=call(40,o,fd,(long)&a,100,0,0);results[x++]=call(40,o,fd,0,0,0,0);
   results[x++]=call(40,pf[1],fd,0,3,0,0);results[x++]=S(0,pf[0],buf,3);results[x++]=buf[0]+buf[1]+buf[2];
   results[x++]=call(40,o,pf[0],0,1,0,0);a=0;results[x++]=call(40,o,pf[0],(long)&a,1,0,0);
   results[x++]=call(40,ap,fd,0,1,0,0);results[x++]=call(40,ro,fd,0,1,0,0);results[x++]=call(40,o,wo,0,1,0,0);results[x++]=call(40,o,d,0,1,0,0);
   a=-1;results[x++]=call(40,o,fd,(long)&a,1,0,0);results[x++]=a;results[x++]=call(40,o,fd,1,1,0,0);results[x++]=call(40,99,fd,0,1,0,0);
  }
  /* What the output file holds. */
  long n=call(17,o,(long)buf,64,0,0,0);results[x++]=n;long sum=0;for(long i=0;i<n&&i<64;i++)sum=sum*31+buf[i];results[x++]=sum;
  S(3,o,0,0);S(3,ro,0,0);S(3,ap,0,0);S(3,wo,0,0);S(3,d,0,0);S(3,pf[0],0,0);S(3,pf[1],0,0);}
 if(CASE==41){ /* statx(dirfd, path, flags, mask, buffer): the fields a stat has */
  static unsigned char sx[256];static long t[4]={0,0,1234,5678};
  #define SX(f,fl,m) call(332,-100,(long)(f),fl,m,(long)sx,0)
  #define SXMODE() (*(unsigned short*)(sx+28))
  #define SXTYPE() (SXMODE()&0170000)
  S(1,fd,"abc",3);call(280,-100,(long)p,(long)t,0,0,0);
  results[x++]=SX(p,0,0x7ff);results[x++]=*(unsigned*)sx&0x7ff;results[x++]=*(unsigned*)(sx+16);results[x++]=SXMODE();
  results[x++]=*(long*)(sx+40);results[x++]=*(long*)(sx+112);results[x++]=*(unsigned*)(sx+120);
  S(88,p,q,0);results[x++]=SX(q,0x100,0x7ff);results[x++]=SXTYPE()==0120000;results[x++]=SX(q,0,0x7ff);results[x++]=SXTYPE()==0100000;
  results[x++]=call(332,fd,(long)"",0x1000,0x7ff,(long)sx,0);results[x++]=*(long*)(sx+40);results[x++]=call(332,fd,(long)"",0,0x7ff,(long)sx,0);
  results[x++]=call(332,-100,(long)"",0x1000,0x7ff,(long)sx,0);results[x++]=SXTYPE()==0040000;
  results[x++]=SX(p,0x6000,0x7ff);results[x++]=SX(p,1,0x7ff);results[x++]=SX(p,0,0x80000000);
  results[x++]=SX("/tmp/paludarium-files-missing",0,0x7ff);results[x++]=call(332,-100,1,0,0x7ff,(long)sx,0);
  results[x++]=call(332,-100,(long)p,0,0x7ff,1,0);results[x++]=call(332,99,(long)"",0x1000,0x7ff,(long)sx,0);
  /* A mask of 0 is allowed; which fields it reports depends on the kernel
     (from 6.13 multigrain timestamps leave out MTIME and CTIME), so only the
     result is compared. */
  results[x++]=SX(p,0,0);
  /* The mount's ID comes whatever the mask asks for: STATX_MNT_ID, or in its
     place STATX_MNT_ID_UNIQUE when that is asked for (Linux 6.8). Which IDs
     the mounts have depends on the system, so only that the file and its
     directory share one, and that the unique ID is past 2^31, are compared. */
  #define SXMASK() (*(unsigned*)sx&0x5000)
  #define SXMNT() (*(unsigned long*)(sx+144))
  results[x++]=SX(p,0,0x7ff);results[x++]=SXMASK();unsigned long mnt=SXMNT();results[x++]=mnt!=0;
  results[x++]=SX(p,0,0);results[x++]=SXMASK();results[x++]=SXMNT()==mnt;
  results[x++]=SX("/tmp",0x100,0x7ff);results[x++]=SXMASK();results[x++]=SXMNT()==mnt;
  results[x++]=SX(p,0,0x5000);results[x++]=SXMASK();results[x++]=SXMNT()>=1UL<<31;
  S(87,q,0,0);}
 if(CASE==50){ /* getdents64 of a new directory: itself, its parent, and one file */
  static char d[]="/tmp/paludarium-files-dents",f[]="/tmp/paludarium-files-dents/a",e[]="/tmp/paludarium-files-dents/.";
  static char up[]="/tmp/paludarium-files-dents/..";
  S(87,f,0,0);S(84,d,0,0);results[x++]=S(83,d,0755,0);long c=S(2,f,66,0644);S(3,c,0,0);
  S(4,e,st,0);long self=*(long*)(st+8);S(4,up,st,0);long parent=*(long*)(st+8);
  long l=S(2,d,0200000,0);
  /* A buffer too small for two entries: one entry a call, in a stable count. */
  for(long round=0;round<2;round++){
   long dots=0,dotdot=0,a=0,calls=0,n;
   while((n=S(217,l,buf,32))>0){
    calls++;
    for(long o=0;o<n;o+=*(unsigned short*)(buf+o+16)){
     char *name=buf+o+19;long ino=*(long*)(buf+o);long type=(unsigned char)buf[o+18];
     if(name[0]=='.'&&!name[1])dots+=ino==self&&type==4;
     else if(name[0]=='.'&&name[1]=='.'&&!name[2])dotdot+=ino==parent&&type==4;
     else if(name[0]=='a'&&!name[1])a+=type==8;
    }
   }
   results[x++]=dots;results[x++]=dotdot;results[x++]=a;results[x++]=calls;results[x++]=n;
   results[x++]=S(8,l,0,0);
  }
  S(3,l,0,0);S(87,f,0,0);S(84,d,0,0);}
 if(CASE==52){ /* getdents64 goes on by what it returned: unlinks, seeks, dup and fork */
  static char d[]="/tmp/paludarium-files-unlinks",f[]="/tmp/paludarium-files-unlinks/f00";
  char *tens=f+sizeof(f)-3,*ones=f+sizeof(f)-2;
  for(long i=0;i<30;i++){*tens='0'+i/10;*ones='0'+i%10;S(87,f,0,0);}
  S(84,d,0,0);results[x++]=S(83,d,0755,0);
  for(long i=0;i<30;i++){*tens='0'+i/10;*ones='0'+i%10;S(3,S(2,f,66,0644),0,0);}
  long l=S(2,d,0200000,0),n;
  /* What a file entry's name was at each step: an entry a call. */
  static char first[8],again[8];
  long off=0,seen=0;
  for(long i=0;i<5&&(n=S(217,l,buf,32))>0;i++)if(i==4)off=*(long*)(buf+8);
  n=S(217,l,buf,32);for(int i=0;i<8;i++)first[i]=buf[19+i];
  /* A saved offset leads to the same entry, also on a new description. */
  results[x++]=S(8,l,off,0)==off;
  S(217,l,buf,32);for(int i=0;i<8;i++)again[i]=buf[19+i];
  long same=1;for(int i=0;i<8;i++)same&=first[i]==again[i];results[x++]=same;
  long other=S(2,d,0200000,0);S(8,other,off,0);S(217,other,buf,32);
  same=1;for(int i=0;i<8;i++)same&=first[i]==buf[19+i];results[x++]=same;S(3,other,0,0);
  /* dup and fork share the position: every entry comes once. */
  S(8,l,0,0);long copy=S(32,l,0,0);seen=0;
  for(long i=0;i<4;i++)if(S(217,i&1?copy:l,buf,32)>0)seen++;
  long pid=S(57,0,0,0);
  if(!pid){S(217,l,buf,32);S(60,0,0,0);}
  call(61,pid,0,0,0,0,0);seen++;
  while(S(217,copy,buf,32)>0)seen++;
  results[x++]=seen;S(3,copy,0,0);
  /* Unlinking each entry as it comes leaves none behind. */
  S(8,l,0,0);seen=0;
  while((n=S(217,l,buf,32))>0)
   for(long o=0;o<n;o+=*(unsigned short*)(buf+o+16)){
    char *name=buf+o+19;
    if(name[0]!='f')continue;
    *tens=name[1];*ones=name[2];results[x]=S(87,f,0,0);seen+=!results[x];
   }
  results[x++]=seen;results[x++]=n;
  S(8,l,0,0);seen=0;
  while((n=S(217,l,buf,32))>0)if(buf[19]=='f')seen++;
  results[x++]=seen;results[x++]=S(84,d,0,0);
  S(3,l,0,0);}
 if(CASE==54){ /* fcntl's record locks between two processes: conflicts, splits, release */
  /* struct flock: l_type, l_whence, l_start, l_len, l_pid. */
  static long fl[4];
  #define LK(cmd,f_,type,whence,start,len) (((short*)fl)[0]=(type),((short*)fl)[1]=(whence),fl[1]=(start),fl[2]=(len),((int*)fl)[6]=0,S(72,f_,cmd,fl))
  long pipe[2];S(22,pipe,0,0);long *pfd=pipe;int *ends=(int*)pfd;
  long me=S(39,0,0,0);
  results[x++]=LK(6,fd,1,0,0,10);
  /* The owner's own lock never conflicts with it. */
  results[x++]=LK(5,fd,1,0,0,10);results[x++]=((short*)fl)[0];
  long pid=S(57,0,0,0);
  if(!pid){
   long r[8],k=0;
   r[k++]=LK(5,fd,1,0,5,1);r[k++]=((short*)fl)[0];r[k++]=fl[1];r[k++]=fl[2];r[k++]=((int*)fl)[6]==S(110,0,0,0);
   r[k++]=LK(6,fd,0,0,5,1);r[k++]=LK(6,fd,1,0,20,5);
   S(1,ends[1],r,k*8);S(60,0,0,0);
  }
  call(61,pid,0,0,0,0,0);
  long got[8];results[x++]=S(0,ends[0],got,7*8);for(int i=0;i<7;i++)results[x++]=got[i];
  /* The child's lock went when it exited. */
  results[x++]=LK(5,fd,1,0,20,5);results[x++]=((short*)fl)[0];
  /* Unlocking the middle splits the lock in two. */
  results[x++]=LK(6,fd,2,0,3,2);
  pid=S(57,0,0,0);
  if(!pid){
   long r[8],k=0;
   LK(5,fd,1,0,3,2);r[k++]=((short*)fl)[0];
   LK(5,fd,1,0,0,1);r[k++]=fl[1];r[k++]=fl[2];
   LK(5,fd,1,0,7,1);r[k++]=fl[1];r[k++]=fl[2];
   /* To the end of the file, read back as a length of 0. */
   S(1,ends[1],r,k*8);S(60,0,0,0);
  }
  call(61,pid,0,0,0,0,0);results[x++]=S(0,ends[0],got,5*8);for(int i=0;i<5;i++)results[x++]=got[i];
  results[x++]=LK(6,fd,0,0,100,0);
  pid=S(57,0,0,0);
  if(!pid){long r[3];LK(5,fd,1,0,200,1);r[0]=((short*)fl)[0];r[1]=fl[1];r[2]=fl[2];S(1,ends[1],r,24);S(60,0,0,0);}
  call(61,pid,0,0,0,0,0);results[x++]=S(0,ends[0],got,3*8);for(int i=0;i<3;i++)results[x++]=got[i];
  /* Closing any descriptor of the file drops the process's locks on it. */
  long other=S(2,p,0,0);S(3,other,0,0);
  pid=S(57,0,0,0);
  if(!pid){long r[1];LK(5,fd,1,0,0,1000);r[0]=((short*)fl)[0];S(1,ends[1],r,8);S(60,0,0,0);}
  call(61,pid,0,0,0,0,0);results[x++]=S(0,ends[0],got,8);results[x++]=got[0];
  /* F_SETLKW waits until the holder lets go. */
  long ready[2];S(22,ready,0,0);int *rd=(int*)ready;
  pid=S(57,0,0,0);
  if(!pid){
   LK(6,fd,1,0,0,1);S(1,rd[1],"r",1);
   long ts[2]={0,50000000};S(35,ts,0,0);LK(6,fd,2,0,0,1);S(60,0,0,0);
  }
  S(0,rd[0],buf,1);results[x++]=LK(7,fd,1,0,0,1);
  call(61,pid,0,0,0,0,0);
  results[x++]=me>0;
  #undef LK
 }
 if(CASE==55){ /* fcntl's lock arguments, checked in Linux's order, and OFD locks */
  static long fl[4];
  #define LK(cmd,f_,type,whence,start,len) (((short*)fl)[0]=(type),((short*)fl)[1]=(whence),fl[1]=(start),fl[2]=(len),((int*)fl)[6]=0,S(72,f_,cmd,fl))
  results[x++]=LK(6,fd,3,0,0,1);results[x++]=LK(6,fd,1,3,0,1);results[x++]=LK(6,fd,1,0,-1,1);
  results[x++]=LK(6,fd,1,0,0,-1);results[x++]=LK(6,fd,1,0,0x7fffffffffffffffL,2);
  results[x++]=LK(5,fd,2,0,0,1);results[x++]=LK(5,fd,3,0,0,1);results[x++]=S(72,fd,6,1);results[x++]=S(72,fd,5,1);
  long ro=S(2,p,0,0),wo=S(2,p,1,0);
  results[x++]=LK(6,ro,1,0,0,1);results[x++]=LK(6,wo,0,0,0,1);results[x++]=LK(6,ro,0,0,0,1);results[x++]=LK(6,wo,1,0,0,1);
  results[x++]=LK(6,ro,2,0,0,1);
  /* A negative length locks the bytes before the start; SEEK_CUR and SEEK_END. */
  results[x++]=LK(6,fd,1,0,10,-5);S(1,fd,"0123456789",10);results[x++]=LK(6,fd,1,1,-2,1);results[x++]=LK(6,fd,1,2,0,0);
  /* l_pid must be 0 for an OFD lock. */
  ((short*)fl)[0]=1;((short*)fl)[1]=0;fl[1]=0;fl[2]=1;((int*)fl)[6]=1;results[x++]=S(72,fd,37,fl);
  ((short*)fl)[0]=1;((short*)fl)[1]=0;fl[1]=0;fl[2]=1;((int*)fl)[6]=1;results[x++]=S(72,fd,36,fl);
  /* Two descriptions of one process conflict over OFD locks, and with its record locks. */
  results[x++]=LK(6,fd,2,0,0,0);
  long a=S(2,p,2,0),b=S(2,p,2,0);
  results[x++]=LK(37,a,1,0,100,1);results[x++]=LK(37,b,1,0,100,1);
  results[x++]=LK(36,b,1,0,100,1);results[x++]=((short*)fl)[0];results[x++]=((int*)fl)[6];results[x++]=fl[1];
  results[x++]=LK(6,b,1,0,100,1);results[x++]=LK(37,a,0,0,100,1);
  long dup=S(32,a,0,0);S(3,a,0,0);results[x++]=LK(37,b,1,0,100,1);
  S(3,dup,0,0);results[x++]=LK(37,b,1,0,100,1);
  S(3,ro,0,0);S(3,wo,0,0);S(3,b,0,0);
  #undef LK
 }
 if(CASE==56){ /* F_SETLKW and F_OFD_SETLKW interrupted by a signal: EINTR, or SA_RESTART's restart */
#if CASE==56
  static long fl[4];
  #define LK(cmd,f_,type,whence,start,len) (((short*)fl)[0]=(type),((short*)fl)[1]=(whence),fl[1]=(start),fl[2]=(len),((int*)fl)[6]=0,S(72,f_,cmd,fl))
  for(long round=0;round<4;round++){
   long cmd=round&1?38:7,restart=round>>1;
   int hp[2],rp[2],gp[2];call(293,(long)hp,04000,0,0,0,0);S(22,rp,0,0);S(22,gp,0,0);
   LK(6,fd,1,0,0,1);
   /* The handler is set before fork: a signal before the wait only runs it. */
   hit_fd=hp[1];
   unsigned long a[4]={(unsigned long)interrupted,4|0x4000000|(restart?0x10000000:0),(unsigned long)restorer,0};
   call(13,10,(long)a,0,8,0,0);
   long pid=S(57,0,0,0);
   if(!pid){
    long own=cmd==38?S(2,p,2,0):fd;
    ((short*)fl)[0]=1;((short*)fl)[1]=0;fl[1]=0;fl[2]=1;((int*)fl)[6]=0;
    long r[6],k=0;
    r[k++]=lock_call(own,cmd,fl);r[k++]=hit;r[k++]=hit_rax;r[k++]=hit_at;
    /* F_GETLK finds the parent's lock after EINTR, none after a restart took it. */
    LK(cmd==38?36:5,own,1,0,0,1);r[k++]=((short*)fl)[0];r[k++]=((int*)fl)[6]==S(110,0,0,0);
    /* A signal sent late may interrupt this read too. */
    S(1,rp[1],r,k*8);while(S(0,gp[0],buf,1)==-4);S(60,0,0,0);
   }
   /* Signal until the child's handler saw the signal come during the wait. */
   while(S(0,hp[0],buf,1)!=1){S(62,pid,10,0);S(24,0,0,0);}
   if(restart)LK(6,fd,2,0,0,1);
   long got[6];results[x++]=S(0,rp[0],got,6*8);for(int i=0;i<6;i++)results[x++]=got[i];
   /* A restarted wait took the lock: the parent sees it. */
   LK(5,fd,1,0,0,1);results[x++]=((short*)fl)[0];results[x++]=((int*)fl)[6]==pid?1:((int*)fl)[6];
   S(1,gp[1],"g",1);call(61,pid,0,0,0,0,0);LK(6,fd,2,0,0,1);
   S(3,hp[0],0,0);S(3,hp[1],0,0);S(3,rp[0],0,0);S(3,rp[1],0,0);S(3,gp[0],0,0);S(3,gp[1],0,0);
  }
  #undef LK
#endif
 }
 if(CASE==57){ /* EDEADLK: two processes that would wait for each other's record locks */
  static long fl[4];
  #define LK(cmd,f_,type,whence,start,len) (((short*)fl)[0]=(type),((short*)fl)[1]=(whence),fl[1]=(start),fl[2]=(len),((int*)fl)[6]=0,S(72,f_,cmd,fl))
  int rp[2],gp[2];S(22,rp,0,0);S(22,gp,0,0);
  LK(6,fd,1,0,0,1);
  long pid=S(57,0,0,0);
  if(!pid){
   LK(6,fd,1,0,1,1);S(1,rp[1],"r",1);S(0,gp[0],buf,1);
   long r=LK(7,fd,1,0,0,1);
   /* The one that would close the cycle lets go, so the other one goes on. */
   if(r==-35)LK(6,fd,2,0,1,1);
   S(1,rp[1],&r,8);S(60,0,0,0);
  }
  S(0,rp[0],buf,1);S(1,gp[1],"g",1);
  /* Whichever of the two asks second gets EDEADLK, in either order. */
  long mine=LK(7,fd,1,0,1,1);
  if(mine==-35)LK(6,fd,2,0,0,1);
  long theirs=0;results[x++]=S(0,rp[0],&theirs,8);call(61,pid,0,0,0,0,0);
  results[x++]=mine<theirs?mine:theirs;results[x++]=mine<theirs?theirs:mine;
  S(3,rp[0],0,0);S(3,rp[1],0,0);S(3,gp[0],0,0);S(3,gp[1],0,0);
  #undef LK
 }
 if(CASE==58){ /* letting go of a lock ends the waits for it: waiting then closes no cycle */
  static long fl[4];
  #define LK(cmd,f_,type,whence,start,len) (((short*)fl)[0]=(type),((short*)fl)[1]=(whence),fl[1]=(start),fl[2]=(len),((int*)fl)[6]=0,S(72,f_,cmd,fl))
  int rp[2];S(22,rp,0,0);
  LK(6,fd,1,0,0,1);
  long t=1,theirs=1,rounds=0;
  for(;rounds<10000;rounds++){
   long pid=S(57,0,0,0);
   if(!pid){LK(6,fd,1,0,1,1);S(1,rp[1],"r",1);long r=LK(7,fd,1,0,0,1);S(1,rp[1],&r,8);S(60,0,0,0);}
   S(0,rp[0],buf,1);S(24,0,0,0);
   /* EDEADLK shows that the child already waits for byte 0. Otherwise the
      child got EDEADLK itself and gave byte 1 up by exiting: try again. */
   long m=LK(7,fd,1,0,1,1);
   if(m==-35){
    /* Unlocking byte 0 ends the child's wait for it, so the parent's wait
       for the child's byte 1 is no deadlock: it ends when the child exits. */
    LK(6,fd,2,0,0,1);t=LK(7,fd,1,0,1,1);
    S(0,rp[0],&theirs,8);call(61,pid,0,0,0,0,0);break;
   }
   S(0,rp[0],&theirs,8);call(61,pid,0,0,0,0,0);LK(6,fd,2,0,1,1);
  }
  results[x++]=rounds<10000;results[x++]=t;results[x++]=theirs;
  S(3,rp[0],0,0);S(3,rp[1],0,0);
  #undef LK
 }
 if(CASE==53){ /* extended attributes in user.*, as any owner of the file may use them */
  static char f[]="/tmp/paludarium-files-xattr",l[]="/tmp/paludarium-files-xattr-link",h[]="/tmp/paludarium-files-xattr-hard";
  static char d[]="/tmp/paludarium-files-xattr-dir",n[]="/tmp/paludarium-files-xattr-none";
  static char a[]="user.a",b[]="user.b",none[]="user.none",other[]="unknown.a",empty[]="";
  static char longest[256],toolong[257],big[65537];
  S(87,l,0,0);S(87,h,0,0);S(87,f,0,0);S(84,d,0,0);
  long c=S(2,f,66,0644);results[x++]=c>=0;
  /* A set, then a get of the size, of the value, and with too small a buffer. */
  results[x++]=call(188,(long)f,(long)a,(long)"one",3,0,0);
  results[x++]=call(191,(long)f,(long)a,0,0,0,0);
  results[x++]=call(191,(long)f,(long)a,(long)buf,8,0,0);results[x++]=buf[0];results[x++]=buf[2];
  results[x++]=call(191,(long)f,(long)a,(long)buf,2,0,0);
  results[x++]=call(191,(long)f,(long)none,(long)buf,8,0,0);
  /* Flags. */
  results[x++]=call(188,(long)f,(long)a,(long)"x",1,1,0);
  results[x++]=call(188,(long)f,(long)b,(long)"x",1,2,0);
  results[x++]=call(188,(long)f,(long)a,(long)"two!",4,2,0);
  results[x++]=call(188,(long)f,(long)b,(long)"bb",2,1,0);
  results[x++]=call(188,(long)f,(long)a,(long)"x",1,4,0);
  results[x++]=call(191,(long)f,(long)a,0,0,0,0);
  /* An empty value is a value. */
  results[x++]=call(188,(long)f,(long)"user.e",(long)"",0,0,0);
  results[x++]=call(191,(long)f,(long)"user.e",(long)buf,8,0,0);
  results[x++]=call(197,(long)f,(long)"user.e",0,0,0,0);
  /* The list: its size, too small a buffer, and the names in any order. */
  long size=call(194,(long)f,0,0,0,0,0);results[x++]=size;
  results[x++]=call(194,(long)f,(long)buf,1,0,0,0);
  long listed=call(194,(long)f,(long)buf,sizeof(buf),0,0,0);results[x++]=listed;
  long sum=0,names=0;for(long i=0;i<listed;i++){sum+=buf[i];names+=!buf[i];}
  results[x++]=sum;results[x++]=names;
  /* Names. */
  for(int i=0;i<255;i++){longest[i]='x';toolong[i]='x';}toolong[255]='x';
  char *prefix="user.";for(int i=0;i<5;i++){longest[i]=prefix[i];toolong[i]=prefix[i];}
  results[x++]=call(191,(long)f,(long)longest,(long)buf,8,0,0);
  results[x++]=call(191,(long)f,(long)toolong,(long)buf,8,0,0);
  results[x++]=call(188,(long)f,(long)toolong,(long)"x",1,0,0);
  results[x++]=call(191,(long)f,(long)empty,(long)buf,8,0,0);
  results[x++]=call(188,(long)f,(long)empty,(long)"x",1,0,0);
  results[x++]=call(191,(long)f,(long)"user.",(long)buf,8,0,0);
  results[x++]=call(188,(long)f,(long)"user.",(long)"x",1,0,0);
  results[x++]=call(191,(long)f,(long)other,(long)buf,8,0,0);
  results[x++]=call(188,(long)f,(long)other,(long)"x",1,0,0);
  results[x++]=call(197,(long)f,(long)other,0,0,0,0);
  results[x++]=call(191,(long)f,16,(long)buf,8,0,0);
  results[x++]=call(188,(long)f,16,(long)"x",1,0,0);
  /* Values. */
  results[x++]=call(188,(long)f,(long)a,(long)big,65537,0,0);
  results[x++]=call(188,(long)f,(long)a,16,1,0,0);
  results[x++]=call(191,(long)f,(long)a,16,8,0,0);
  results[x++]=call(194,(long)f,16,64,0,0,0);
  /* A symbolic link: user.* is for files and directories. */
  S(88,f,l,0);
  results[x++]=call(191,(long)l,(long)a,0,0,0,0);
  results[x++]=call(192,(long)l,(long)a,0,0,0,0);
  results[x++]=call(189,(long)l,(long)a,(long)"x",1,0,0);
  results[x++]=call(198,(long)l,(long)a,0,0,0,0);
  results[x++]=call(195,(long)l,0,0,0,0,0);
  results[x++]=call(194,(long)l,0,0,0,0,0);
  /* A hard link and a rename keep them. */
  S(86,f,h,0);results[x++]=call(191,(long)h,(long)a,0,0,0,0);
  /* A directory has them too. */
  results[x++]=S(83,d,0755,0);
  results[x++]=call(188,(long)d,(long)a,(long)"d",1,0,0);
  results[x++]=call(191,(long)d,(long)a,0,0,0,0);
  /* Paths and descriptors. */
  results[x++]=call(191,(long)n,(long)a,(long)buf,8,0,0);
  results[x++]=call(188,(long)n,(long)a,(long)"x",1,0,0);
  results[x++]=call(194,(long)n,0,0,0,0,0);
  results[x++]=call(197,(long)n,(long)a,0,0,0,0);
  results[x++]=call(193,c,(long)a,0,0,0,0);
  results[x++]=call(190,c,(long)"user.c",(long)"cc",2,0,0);
  results[x++]=call(196,c,0,0,0,0,0);
  results[x++]=call(199,c,(long)"user.c",0,0,0,0);
  results[x++]=call(199,c,(long)"user.c",0,0,0,0);
  results[x++]=call(193,-1,(long)a,0,0,0,0);
  results[x++]=call(190,-1,(long)a,(long)"x",1,0,0);
  results[x++]=call(196,-1,0,0,0,0,0);
  results[x++]=call(199,-1,(long)a,0,0,0,0);
  /* Removing, and an open file with no name left. */
  results[x++]=call(197,(long)f,(long)b,0,0,0,0);
  results[x++]=call(197,(long)f,(long)b,0,0,0,0);
  results[x++]=call(191,(long)f,(long)b,0,0,0,0);
  S(87,l,0,0);S(87,h,0,0);S(87,f,0,0);
  results[x++]=call(193,c,(long)a,0,0,0,0);
  results[x++]=call(190,c,(long)b,(long)"x",1,0,0);
  S(3,c,0,0);S(84,d,0,0);}
 if(CASE==51){ /* getdents64 lists in the file system's order, the same on every read */
  static char d[]="/tmp/paludarium-files-order",f[]="/tmp/paludarium-files-order/f00";
  char *tens=f+sizeof(f)-3,*ones=f+sizeof(f)-2;
  for(long i=0;i<20;i++){*tens='0'+i/10;*ones='0'+i%10;S(87,f,0,0);}
  S(84,d,0,0);results[x++]=S(83,d,0755,0);
  for(long i=0;i<20;i++){*tens='0'+i/10;*ones='0'+i%10;S(3,S(2,f,66,0644),0,0);}
  long l=S(2,d,0200000,0),n;
  for(long round=0;round<2;round++){
   /* All at once, then one entry a call. */
   while((n=S(217,l,buf,round?32:4096))>0)
    for(long o=0;o<n;o+=*(unsigned short*)(buf+o+16)){
     char *name=buf+o+19;
     if(name[0]=='f')results[x++]=(name[1]-'0')*10+name[2]-'0';
    }
   results[x++]=n;
   S(8,l,0,0);
  }
  S(3,l,0,0);
  for(long i=0;i<20;i++){*tens='0'+i/10;*ones='0'+i%10;S(87,f,0,0);}
  S(84,d,0,0);}
 if(CASE==49){ /* AF_UNIX bind makes a socket file, which connect finds */
  static char sa[110]="\1\0/tmp/paludarium-files-socket"; long len=2+sizeof("/tmp/paludarium-files-socket");
  char *path=sa+2; S(87,path,0,0); S(95,022,0,0);
  long l=S(41,1,1,0),o=S(41,1,1,0),c=S(41,1,1,0),c2=S(41,1,1,0);
  results[x++]=S(49,l,sa,len);results[x++]=S(4,path,st,0);
  results[x++]=*(unsigned*)(st+24)&0177777;
  results[x++]=S(49,o,sa,len);results[x++]=S(50,l,1,0);
  results[x++]=S(42,c,sa,len);long a=S(43,l,0,0);results[x++]=a>=0;
  results[x++]=S(1,c,"s",1);results[x++]=S(0,a,buf,1);results[x++]=buf[0];
  results[x++]=S(87,path,0,0);results[x++]=S(42,c2,sa,len);
  char *b=sa+2; const char *f=p; while((*b++=*f++)){} /* a path that is a regular file */
  results[x++]=S(49,o,sa,2+sizeof(p));
  S(3,a,0,0);S(3,l,0,0);S(3,o,0,0);S(3,c,0,0);S(3,c2,0,0);}
 if(CASE==48){ /* MADV_DONTNEED on the program's own data and bss */
  data_pages[0]=9;data_pages[4096]=9;bss_pages[0]=9;bss_pages[4096]=9;
  results[x++]=S(28,data_pages,8192,4);results[x++]=data_pages[0];results[x++]=data_pages[1];results[x++]=data_pages[4096];
  results[x++]=S(28,bss_pages,8192,4);results[x++]=bss_pages[0];results[x++]=bss_pages[4096];
  results[x++]=S(28,bss_pages,4096,8);results[x++]=S(28,data_pages,4096,8);}
 if(CASE==47){ /* MADV_DONTNEED on a private file mapping: its pages read the file again */
  static char data[9000];for(int i=0;i<9000;i++)data[i]='a'+i%26;S(1,fd,data,9000);
  char*m=(char*)MMAP(12288,3,2,fd,0);results[x++]=(long)m>0;
  m[0]='X';m[4096]='Y';m[8999]='Z';m[9000]='W';
  results[x++]=S(28,m,12288,4);results[x++]=m[0];results[x++]=m[4096];results[x++]=m[8999];results[x++]=m[9000];
  /* The file as it is when the page is read again, written after the mapping was made. */
  call(18,fd,(long)"Q",1,1,0,0);m[1]='R';results[x++]=S(28,m,4096,4);results[x++]=m[1];
  /* Only the range given. */
  m[4096]='S';m[8192]='T';results[x++]=S(28,m+8192,4096,4);results[x++]=m[4096];results[x++]=m[8192];
  /* A mapping from an offset, and that mapping moved by mremap. */
  char*o=(char*)MMAP(4096,3,2,fd,4096);o[0]='U';results[x++]=S(28,o,4096,4);results[x++]=o[0];
  char*to=(char*)MMAP(4096,3,0x22,-1,0);o[1]='V';char*mv=(char*)call(25,(long)o,4096,4096,3,(long)to,0);
  results[x++]=mv==to;results[x++]=mv[1];results[x++]=S(28,mv,4096,4);results[x++]=mv[1];
  /* Shared anonymous memory is not a file's: it keeps its contents, as before. */
  char*sh=(char*)MMAP(4096,3,0x21,-1,0);sh[0]=9;results[x++]=S(28,sh,4096,4);results[x++]=sh[0];
  S(11,m,12288,0);S(11,mv,4096,0);S(11,sh,4096,0);}
 if(CASE==46){ /* /dev: the memory devices, and the links into /proc/self/fd */
  static const char *devs[]={"/dev/null","/dev/zero","/dev/full","/dev/random","/dev/urandom"};
  static char t[300];long k;
  #define LINK(path,want) (k=call(89,(long)(path),(long)t,300,0,0,0),same(t,k,want))
  for(int i=0;i<5;i++){S(4,devs[i],st,0);results[x++]=*(unsigned*)(st+24);results[x++]=*(long*)(st+40);}
  long z=S(2,"/dev/zero",2,0);for(int i=0;i<8;i++)buf[i]=7;
  results[x++]=S(0,z,buf,8);results[x++]=buf[0]+buf[7];results[x++]=S(1,z,"ab",2);results[x++]=call(17,z,(long)buf,4,100,0,0);
  long fu=S(2,"/dev/full",2,0);results[x++]=S(1,fu,"ab",2);results[x++]=S(0,fu,buf,4);
  long ur=S(2,"/dev/urandom",0,0),rd=S(2,"/dev/random",0,0);results[x++]=S(0,ur,buf,16);results[x++]=S(0,rd,buf,16);
  long nl=S(2,"/dev/null",0,0);results[x++]=S(0,nl,buf,4);results[x++]=S(1,nl,"x",1);
  S(6,"/dev/stdin",st,0);results[x++]=*(unsigned*)(st+24);results[x++]=*(long*)(st+48);
  results[x++]=LINK("/dev/stdin","/proc/self/fd/0");results[x++]=LINK("/dev/stdout","/proc/self/fd/1");
  results[x++]=LINK("/dev/stderr","/proc/self/fd/2");results[x++]=LINK("/dev/fd","/proc/self/fd");
  S(4,"/dev/fd",st,0);results[x++]=*(unsigned*)(st+24);S(4,"/dev",st,0);results[x++]=*(unsigned*)(st+24);
  results[x++]=LINK(numbered("/dev/fd/",fd),p);long re=S(2,numbered("/dev/fd/",fd),0,0);results[x++]=re>=0;results[x++]=LINK(fdpath(re),p);
  long mp=call(9,0,4096,3,2,z,0);results[x++]=mp>0;if(mp>0){results[x++]=*(char*)mp;*(char*)mp=1;S(11,mp,4096,0);}
  long ms=call(9,0,4096,3,1,z,0);results[x++]=ms>0;if(ms>0)S(11,ms,4096,0);
  long zr=S(2,"/dev/zero",0,0);results[x++]=call(9,0,4096,3,1,zr,0);
  results[x++]=S(2,"/dev/stdin",0400000,0);results[x++]=call(89,(long)"/dev/null",(long)t,300,0,0,0);
  results[x++]=S(2,"/dev",1,0);results[x++]=S(2,"/dev",2,0);results[x++]=S(2,"/dev/null",0200000,0);
  long fds[]={z,fu,ur,rd,nl,re,zr};for(unsigned i=0;i<sizeof fds/sizeof fds[0];i++)S(3,fds[i],0,0);}
 if(CASE==45){ /* /proc/self/fd: a link per open descriptor */
  static char t[300],u[300],gone[300];long k,k2;
  #define RL(n,o) call(89,(long)fdpath(n),(long)(o),300,0,0,0)
  #define LMODE() (*(unsigned*)(st+24))
  k=RL(fd,t);results[x++]=same(t,k,p);S(6,fdpath(fd),st,0);results[x++]=LMODE();results[x++]=*(long*)(st+48);
  S(4,fdpath(fd),st,0);long ino=*(long*)(st+8);S(5,fd,st,0);results[x++]=ino==*(long*)(st+8);
  long ro=S(2,p,0,0);S(6,fdpath(ro),st,0);results[x++]=LMODE();
  S(1,fd,"abc",3);long re=S(2,fdpath(fd),0,0);results[x++]=re>=0;results[x++]=S(0,re,buf,3);results[x++]=buf[0]+buf[1]+buf[2];results[x++]=S(8,fd,0,1);
  k=RL(re,t);results[x++]=same(t,k,p);
  /* Through a symbolic link, ".." and ".": the resolved path. */
  S(88,p,q,0);long viaq=S(2,q,0,0),dots2=S(2,"/tmp/./../tmp/paludarium-files-fixture",0,0);
  k=RL(viaq,t);results[x++]=same(t,k,p);k=RL(dots2,t);results[x++]=same(t,k,p);
  long again=S(2,fdpath(viaq),0,0);results[x++]=again>=0;k=RL(again,t);results[x++]=same(t,k,p);
  S(3,viaq,0,0);S(3,dots2,0,0);S(3,again,0,0);S(87,q,0,0);
  {char *q=gone;const char *r=p;while(*r)*q++=*r++;r=" (deleted)";while(*r)*q++=*r++;*q=0;}
  S(87,p,0,0);k=RL(fd,t);results[x++]=same(t,k,gone);
  /* The removed file opens again through its link, as Linux opens it: the
     same file, with an offset of its own. O_CREAT | O_EXCL finds the link
     there, O_NOFOLLOW does not follow it, and O_TRUNC empties the file. */
  long dl=S(2,fdpath(fd),2,0);results[x++]=dl>=0;results[x++]=S(8,dl,0,1);results[x++]=S(0,dl,buf,3);
  results[x++]=buf[0]+buf[1]+buf[2];S(1,dl,"Z",1);S(8,fd,0,0);results[x++]=S(0,fd,buf,4);results[x++]=buf[3];
  S(5,dl,st,0);long dino=*(long*)(st+8);S(5,fd,st,0);results[x++]=dino==*(long*)(st+8);results[x++]=*(long*)(st+16);
  results[x++]=S(2,fdpath(fd),0302,0);results[x++]=S(2,fdpath(fd),0400000,0);results[x++]=S(2,fdpath(fd),0200000,0);
  long dt=S(2,fdpath(fd),01000,0);results[x++]=dt>=0;S(5,fd,st,0);results[x++]=*(long*)(st+48);S(3,dt,0,0);S(3,dl,0,0);
  /* Read-only with O_APPEND stays read-only; a closed descriptor's link is
     not there, whatever the flags. */
  long ra=S(2,fdpath(fd),02000,0);results[x++]=S(1,ra,"q",1);S(3,ra,0,0);
  results[x++]=S(2,fdpath(900),0302,0);results[x++]=S(2,fdpath(900),0400000,0);
  long m=call(319,(long)"named",2,0,0,0,0);k=RL(m,t);results[x++]=same(t,k,"/memfd:named (deleted)");
  long mr=S(2,fdpath(m),0,0);results[x++]=mr>=0;S(1,m,"xy",2);results[x++]=S(0,mr,buf,2);results[x++]=buf[0]+buf[1];
  results[x++]=S(72,mr,1033,1);S(72,m,1033,4);results[x++]=S(72,mr,1034,0);
  /* O_RDONLY | O_TRUNC still empties it; F_SEAL_GROW does not stop that. */
  long tr=S(2,fdpath(m),01000,0);results[x++]=tr>=0;S(5,m,st,0);results[x++]=*(long*)(st+48);S(3,tr,0,0);S(5,mr,st,0);results[x++]=*(long*)(st+16);
  int pf[2];S(22,pf,0,0);k=RL(pf[0],t);k2=RL(pf[1],u);u[k2]=0;results[x++]=starts(t,k,"pipe:[");results[x++]=same(t,k,u);
  S(6,fdpath(pf[1]),st,0);results[x++]=LMODE();
  long pw=S(2,fdpath(pf[1]),1,0);results[x++]=pw>=0;results[x++]=S(1,pw,"q",1);results[x++]=S(0,pf[0],buf,1);results[x++]=buf[0];
  int sv[2];call(53,1,1,0,(long)sv,0,0);k=RL(sv[0],t);k2=RL(sv[1],u);u[k2]=0;results[x++]=starts(t,k,"socket:[");results[x++]=!same(t,k,u);
  results[x++]=S(2,fdpath(sv[0]),2,0);
  long ev=call(290,0,0,0,0,0,0);k=RL(ev,t);results[x++]=same(t,k,"anon_inode:[eventfd]");
  long ep=call(291,0,0,0,0,0,0);k=RL(ep,t);results[x++]=same(t,k,"anon_inode:[eventpoll]");
  long tf=call(283,1,0,0,0,0,0);k=RL(tf,t);results[x++]=same(t,k,"anon_inode:[timerfd]");
  long dn=S(2,"/dev/null",2,0);k=RL(dn,t);results[x++]=same(t,k,"/dev/null");
  results[x++]=call(89,(long)"/proc/self/fd/999",(long)t,300,0,0,0);results[x++]=call(89,(long)"/proc/self/fd/03",(long)t,300,0,0,0);
  results[x++]=call(89,(long)"/proc/self/fd",(long)t,300,0,0,0);results[x++]=S(4,"/proc/self/fd/999",st,0);
  S(4,"/proc/self/fd",st,0);results[x++]=LMODE();
  long dd=S(2,"/proc/self/fd",65536,0),total=0,open=0,dots=0;
  for(;;){long nb=S(217,dd,buf,4096);if(nb<=0)break;for(long o=0;o<nb;o+=*(unsigned short*)(buf+o+16)){total++;if(buf[o+19]=='.')dots++;}}
  for(int i=0;i<1024;i++)if(S(72,i,1,0)>=0)open++;
  results[x++]=total==open+2;results[x++]=dots;
  long fds[]={ro,re,m,mr,pf[0],pf[1],pw,sv[0],sv[1],ev,ep,tf,dn,dd};for(unsigned i=0;i<sizeof fds/sizeof fds[0];i++)S(3,fds[i],0,0);}
 if(CASE==44){ /* memfd_create(name, flags) and its seals */
  #define MFD(n,f) call(319,(long)(n),f,0,0,0,0)
  #define SEALS(m) S(72,m,1034,0)
  #define ADD(m,v) S(72,m,1033,v)
  static char longname[251];for(int i=0;i<250;i++)longname[i]='a';
  long m=MFD("plain",0);results[x++]=m>=0;S(5,m,st,0);results[x++]=*(unsigned*)(st+24);results[x++]=*(long*)(st+16);
  results[x++]=S(72,m,3,0);results[x++]=S(72,m,1,0);results[x++]=S(1,m,"hello",5);S(8,m,0,0);results[x++]=S(0,m,buf,5);
  results[x++]=SEALS(m);results[x++]=ADD(m,2);
  long s=MFD("sealed",3);results[x++]=S(72,s,1,0);results[x++]=SEALS(s);S(1,s,"abcdefgh",8);
  results[x++]=ADD(s,2);results[x++]=S(77,s,4,0);results[x++]=S(77,s,16,0);
  results[x++]=ADD(s,4);results[x++]=S(77,s,32,0);results[x++]=call(18,s,(long)"xy",2,15,0,0);results[x++]=call(18,s,(long)"xy",2,14,0,0);
  results[x++]=call(285,s,0,0,100,0,0);results[x++]=call(285,s,1,0,100,0,0);results[x++]=call(285,s,0,0,8,0,0);
  results[x++]=ADD(s,8);results[x++]=S(1,s,"z",1);results[x++]=S(1,s,"",0);results[x++]=call(285,s,3,0,1,0,0);
  results[x++]=call(9,0,4096,3,1,s,0);long r=call(9,0,4096,1,1,s,0);results[x++]=r>0;if(r>0)S(11,r,4096,0);
  results[x++]=ADD(s,1);results[x++]=ADD(s,0x20);results[x++]=ADD(s,0x40);results[x++]=SEALS(s);
  long n=MFD("noexec",8);S(5,n,st,0);results[x++]=*(unsigned*)(st+24);results[x++]=SEALS(n);results[x++]=S(91,n,0777,0);results[x++]=S(91,n,0644,0);
  long e=MFD("exec",0x12);results[x++]=ADD(e,0x20);results[x++]=SEALS(e);results[x++]=S(1,e,"z",1);
  results[x++]=MFD("bad",0x100);results[x++]=MFD("both",0x18);results[x++]=MFD(longname,0);longname[249]=0;long l=MFD(longname,0);results[x++]=l>=0;results[x++]=MFD(1,0);
  /* F_SEAL_GROW stops a write at the last page that ends within the file. */
  static char big[7000];long g=MFD("grow",2);S(77,g,5000,0);ADD(g,4);
  results[x++]=S(1,g,big,7000);results[x++]=S(1,g,big,1000);results[x++]=call(18,g,(long)big,900,4000,0,0);S(3,g,0,0);
  /* Memfds share a filesystem with each other and with no mount. */
  static long from;long c1=MFD("c1",0),c2=MFD("c2",0);S(1,c1,"abcdef",6);
  results[x++]=call(326,c1,(long)&from,fd,0,3,0);results[x++]=call(326,c1,(long)&from,c2,0,3,0);results[x++]=from;
  S(5,c1,st,0);long i1=*(long*)(st+8);S(5,c2,st,0);results[x++]=i1!=*(long*)(st+8);S(3,c1,0,0);S(3,c2,0,0);
  int pf[2];S(22,pf,0,0);results[x++]=SEALS(fd);results[x++]=ADD(pf[0],1);results[x++]=ADD(pf[1],1);
  S(3,m,0,0);S(3,s,0,0);S(3,n,0,0);S(3,e,0,0);S(3,l,0,0);S(3,pf[0],0,0);S(3,pf[1],0,0);}
 if(CASE==43){ /* fallocate(fd, mode, offset, len): the modes tmpfs and ext4 share */
  #define FA(f,m,o,l) call(285,f,m,o,l,0,0)
  #define SIZE() (S(5,fd,st,0),*(long*)(st+48))
  #define BYTES() (call(17,fd,(long)buf,10,0,0,0)==10?buf[0]+buf[1]*3+buf[2]*5+buf[3]*7+buf[4]*11+buf[5]*13+buf[9]*17:-1)
  int pf[2];S(22,pf,0,0);int sv[2];call(53,1,1,0,(long)sv,0,0);
  long ro=S(2,p,0,0),ap=S(2,p,1025,0),d=S(2,"/tmp",65536,0);
  S(1,fd,"abcdef",6);
  results[x++]=FA(fd,0,0,10);results[x++]=SIZE();results[x++]=BYTES();
  results[x++]=FA(fd,1,0,100);results[x++]=SIZE();results[x++]=FA(fd,0,2,3);results[x++]=SIZE();
  results[x++]=FA(fd,3,1,2);results[x++]=BYTES();results[x++]=SIZE();
  results[x++]=FA(fd,3,8,100);results[x++]=SIZE();results[x++]=FA(ap,3,3,1);results[x++]=BYTES();results[x++]=SIZE();
  results[x++]=FA(fd,2,0,1);results[x++]=FA(fd,0x100,0,1);results[x++]=FA(fd,4,0,1);results[x++]=FA(fd,9,0,1);results[x++]=FA(fd,0x21,0,1);
  results[x++]=FA(fd,0,-1,1);results[x++]=FA(fd,0,0,0);results[x++]=FA(fd,0,0,-1);results[x++]=FA(99,0,0,1);results[x++]=FA(99,0,-1,1);
  results[x++]=FA(ro,0,0,1);results[x++]=FA(ro,0x100,0,1);results[x++]=FA(pf[1],0,0,1);results[x++]=FA(pf[0],0,0,1);results[x++]=FA(d,0,0,1);results[x++]=FA(sv[0],0,0,1);
  results[x++]=FA(fd,0,0x7fffffffffffffffL,1);results[x++]=FA(fd,1,1,0x7fffffffffffffffL);results[x++]=SIZE();
  S(3,ro,0,0);S(3,ap,0,0);S(3,d,0,0);S(3,pf[0],0,0);S(3,pf[1],0,0);S(3,sv[0],0,0);S(3,sv[1],0,0);}
 if(CASE==62){ /* openat2(dirfd, path, how, size): open_how's checks and RESOLVE_* */
  static unsigned long how[8];static char u2[]="/tmp/paludarium-files-unused";
  #define HOW(f,m,r) (how[0]=(f),how[1]=(m),how[2]=(r))
  #define O2(d,path,sz) call(437,d,(long)(path),(long)how,sz,0,0)
  #define OK2(d,path) {long o=O2(d,path,24);results[x++]=o>=0;S(3,o,0,0);}
  S(87,u2,0,0);long t=S(2,"/tmp",0200000,0);
  HOW(0,0,0);OK2(-100,p);results[x++]=O2(-100,p,23);results[x++]=O2(-100,p,4097);
  how[3]=1;results[x++]=O2(-100,p,32);results[x++]=O2(-100,p,4096);how[3]=0;
  {long o=O2(-100,p,32);results[x++]=o>=0;results[x++]=S(72,o,3,0);S(3,o,0,0);}
  results[x++]=call(437,-100,(long)p,8,24,0,0);results[x++]=O2(-100,"",24);results[x++]=O2(-100,0,24);
  /* Flags and mode: what openat would ignore, openat2 refuses. */
  HOW(4,0,0);results[x++]=O2(-100,p,24);HOW(1L<<32,0,0);results[x++]=O2(-100,p,24);
  HOW(0,0644,0);results[x++]=O2(-100,p,24);HOW(0100,010644,0);results[x++]=O2(-100,u2,24);
  HOW(0300000,0644,0);results[x++]=O2(-100,u2,24);HOW(020000002,0600,0);results[x++]=O2(-100,"/tmp",24);
  HOW(020200000,0600,0);results[x++]=O2(-100,"/tmp",24);HOW(010000002,0,0);results[x++]=O2(-100,p,24);
  HOW(012400000,0,0);{long o=O2(-100,p,24);results[x++]=o>=0;results[x++]=S(72,o,3,0);results[x++]=S(72,o,1,0);S(3,o,0,0);}
  HOW(0,0,0x40);results[x++]=O2(-100,p,24);HOW(0,0,0x18);results[x++]=O2(-100,p,24);
  HOW(01000,0,0x20);results[x++]=O2(-100,p,24);HOW(0100,0600,0x20);results[x++]=O2(-100,u2,24);
  HOW(0301,0640,0);{long o=O2(-100,u2,24);results[x++]=o>=0;S(5,o,st,0);results[x++]=MODE();S(3,o,0,0);}
  results[x++]=O2(-100,u2,24);S(87,u2,0,0);
  /* A FIFO opens as through openat. */
  S(133,u2,010644,0);HOW(04000,0,0);{long rd=O2(-100,u2,24);results[x++]=rd>=0;HOW(04001,0,0);long w=O2(-100,u2,24);results[x++]=w>=0;S(3,w,0,0);S(3,rd,0,0);}
  results[x++]=O2(-100,u2,24);S(87,u2,0,0);
  /* RESOLVE_NO_SYMLINKS and RESOLVE_NO_MAGICLINKS. */
  S(88,p,q,0);S(88,"paludarium-files-fixture",r,0);
  HOW(0,0,4);results[x++]=O2(-100,q,24);results[x++]=O2(-100,numbered("/dev/fd/",fd),24);
  HOW(012400000,0,4);OK2(-100,q);
  HOW(0,0,2);OK2(-100,q);results[x++]=O2(-100,fdpath(fd),24);results[x++]=O2(-100,numbered("/dev/fd/",fd),24);
  results[x++]=O2(-100,"/proc/self/exe",24);results[x++]=O2(-100,fdpath(900),24);
  HOW(0,0,0);OK2(-100,fdpath(fd));HOW(010400000,0,2);OK2(-100,fdpath(fd));
  /* RESOLVE_BENEATH and RESOLVE_IN_ROOT from /tmp. */
  HOW(0,0,8);OK2(t,"paludarium-files-fixture");OK2(t,"paludarium-files-renamed");
  results[x++]=O2(t,p,24);results[x++]=O2(t,"../tmp/paludarium-files-fixture",24);results[x++]=O2(t,"paludarium-files-link",24);
  HOW(0200000,0,8);OK2(t,".");
  HOW(0,0,0x10);OK2(t,"/paludarium-files-fixture");OK2(t,"../../paludarium-files-fixture");OK2(t,"paludarium-files-renamed");
  results[x++]=O2(t,"paludarium-files-link",24);
  {long pd=S(2,"/proc/self/fd",0200000,0);HOW(0,0,8);results[x++]=O2(pd,numbered("",fd),24);
   HOW(0,0,0x10);results[x++]=O2(pd,numbered("",fd),24);HOW(0,0,1);results[x++]=O2(pd,numbered("",fd),24);
   HOW(0,0,0);OK2(pd,numbered("",fd));S(3,pd,0,0);}
  /* RESOLVE_NO_XDEV: /proc and /dev are mounts of their own (whether
     /tmp is one depends on the system, so nothing here crosses into it). */
  HOW(0,0,1);OK2(t,"paludarium-files-fixture");
  results[x++]=O2(-100,"/proc/self/status",24);results[x++]=O2(-100,"/dev/null",24);
  results[x++]=O2(t,"../proc/self/status",24);
  HOW(0,0,0);OK2(-100,"/proc/self/status");
  S(3,t,0,0);}
 if(CASE==64){ /* a link in /proc/self/fd leads path calls to the descriptor's file */
  static long ts[4];static char here[300];long ok;
  long op=S(2,p,010000000,0);S(1,fd,"abcd",4);
  results[x++]=S(90,fdpath(fd),0600,0);S(5,fd,st,0);results[x++]=MODE();
  results[x++]=S(91,op,0640,0);results[x++]=S(93,op,-1,-1);results[x++]=call(280,op,0,0,0,0,0);results[x++]=S(77,op,0,0);
  results[x++]=S(90,fdpath(op),0640,0);S(4,p,st,0);results[x++]=MODE();
  results[x++]=call(268,-100,(long)fdpath(op),0604,0,0,0);S(4,p,st,0);results[x++]=MODE();
  results[x++]=call(452,-100,(long)fdpath(op),0644,0,0,0);S(4,p,st,0);results[x++]=MODE();
  results[x++]=call(452,-100,(long)fdpath(op),0644,0x100,0,0);
  results[x++]=S(90,fdpath(900),0600,0);
  /* A symbolic link an O_PATH | O_NOFOLLOW descriptor holds: not followed
     again, and its mode cannot change. */
  S(88,p,q,0);long ol=S(2,q,010400000,0);results[x++]=S(90,fdpath(ol),0600,0);S(4,p,st,0);results[x++]=MODE();
  results[x++]=S(80,fdpath(ol),0,0);results[x++]=S(76,fdpath(ol),0,0);S(5,fd,st,0);results[x++]=*(long*)(st+48);
  {static char *argv[]={"x",0};results[x++]=call(59,(long)fdpath(ol),(long)argv,0,0,0,0);}
  /* chown to the IDs it has, utimensat and truncate. */
  long uid=S(107,0,0,0),gid=S(108,0,0,0);
  results[x++]=S(92,fdpath(op),uid,gid);results[x++]=call(260,-100,(long)fdpath(op),uid,gid,0,0);
  results[x++]=S(92,fdpath(op),-1,-1);results[x++]=S(92,fdpath(900),-1,-1);
  ts[0]=1;ts[1]=0;ts[2]=1000;ts[3]=0;results[x++]=call(280,-100,(long)fdpath(op),(long)ts,0,0,0);
  S(5,fd,st,0);results[x++]=MTIME();
  results[x++]=S(76,fdpath(op),2,0);S(5,fd,st,0);results[x++]=*(long*)(st+48);
  results[x++]=S(76,fdpath(900),0,0);
  results[x++]=S(21,fdpath(op),4,0);results[x++]=call(439,-100,(long)fdpath(op),6,0x200,0,0);results[x++]=S(21,fdpath(900),0,0);
  /* chdir to a directory an O_PATH descriptor holds. */
  ok=S(79,here,300,0);long dp=S(2,"/tmp",010200000,0);results[x++]=S(80,fdpath(dp),0,0);
  S(79,buf,300,0);results[x++]=same(buf,4,"/tmp")&&buf[4]==0;results[x++]=S(80,fdpath(op),0,0);
  if(ok>0)S(80,here,0,0);
  /* execve reaches the file: a directory is EACCES, a file of no format
     it knows (and that nothing has open to write) ENOEXEC. */
  {static char *argv[]={"x",0};static char u2[]="/tmp/paludarium-files-unused";
   results[x++]=call(59,(long)fdpath(dp),(long)argv,0,0,0,0);
   S(87,u2,0,0);long w=S(2,u2,0101,0700);S(1,w,"xx",2);S(3,w,0,0);long xp=S(2,u2,010000000,0);
   results[x++]=call(59,(long)fdpath(xp),(long)argv,0,0,0,0);S(3,xp,0,0);S(87,u2,0,0);}
  /* A removed file is reached through its descriptor. */
  S(87,p,0,0);results[x++]=S(90,fdpath(fd),0611,0);S(5,fd,st,0);results[x++]=MODE();
  results[x++]=S(76,fdpath(fd),1,0);S(5,fd,st,0);results[x++]=*(long*)(st+48);
  ts[2]=2000;results[x++]=call(280,-100,(long)fdpath(fd),(long)ts,0,0,0);S(5,fd,st,0);results[x++]=MTIME();
  results[x++]=S(21,fdpath(fd),4,0);
  S(3,op,0,0);S(3,ol,0,0);S(3,dp,0,0);}
 if(CASE==65){ /* extended attributes through a link in /proc/self/fd */
  long op=S(2,p,010000000,0);
  results[x++]=call(188,(long)fdpath(op),(long)"user.k",(long)"v",1,0,0);
  results[x++]=call(191,(long)p,(long)"user.k",(long)buf,8,0,0);results[x++]=buf[0];
  results[x++]=call(191,(long)fdpath(op),(long)"user.k",(long)buf,8,0,0);
  results[x++]=call(192,(long)fdpath(op),(long)"user.k",(long)buf,8,0,0);
  results[x++]=call(194,(long)fdpath(op),(long)buf,64,0,0,0);
  results[x++]=call(197,(long)fdpath(op),(long)"user.k",0,0,0,0);
  results[x++]=call(191,(long)p,(long)"user.k",(long)buf,8,0,0);
  results[x++]=call(188,(long)fdpath(900),(long)"user.k",(long)"v",1,0,0);
  S(3,op,0,0);}
 if(CASE==68){ /* a link in /proc/self/fd (and /proc/self/cwd, /dev/fd) inside a path: the walk goes on from the descriptor's file */
  #define UNDER(pre,n,rest) ({static char u[256];char *a=numbered(pre,n),*o=u;while(*a)*o++=*a++;const char *b=rest;while(*b)*o++=*b++;*o=0;u;})
  #define INODE(n) (S(4,n,st,0)<0?-1:*(long*)(st+8))
  static char dd[]="/tmp/paludarium-files-dir",dd2[]="/tmp/paludarium-files-dir2",here[300];
  S(1,fd,"abcd",4);long d=S(2,"/tmp",0200000,0),op=S(2,"/tmp",010200000,0);
  results[x++]=S(4,UNDER("/proc/self/fd/",d,"/paludarium-files-fixture"),st,0);results[x++]=*(long*)(st+48);
  long o=S(2,UNDER("/proc/self/fd/",d,"/paludarium-files-fixture"),0,0);results[x++]=o>=0;results[x++]=S(0,o,buf,4);S(3,o,0,0);
  results[x++]=S(4,UNDER("/proc/self/fd/",op,"/paludarium-files-fixture"),st,0);
  results[x++]=S(4,UNDER("/dev/fd/",d,"/paludarium-files-fixture"),st,0);
  results[x++]=S(4,UNDER("/proc/self/fd/",fd,"/x"),st,0);results[x++]=S(4,UNDER("/proc/self/fd/",900,"/x"),st,0);
  results[x++]=S(4,UNDER("/proc/self/fd/",d,"/missing"),st,0);
  results[x++]=INODE(UNDER("/proc/self/fd/",d,"/.."))==INODE("/");results[x++]=INODE(UNDER("/proc/self/fd/",d,"/."))==INODE("/tmp");
  /* Creating and removing through it, and a directory renamed since it was opened. */
  results[x++]=S(83,UNDER("/proc/self/fd/",d,"/paludarium-files-dir"),0755,0);results[x++]=S(4,dd,st,0);
  long e=S(2,dd,0200000,0);S(82,dd,dd2,0);
  long w=S(2,UNDER("/proc/self/fd/",e,"/inner"),0101,0600);results[x++]=w>=0;S(3,w,0,0);
  results[x++]=S(4,"/tmp/paludarium-files-dir2/inner",st,0);
  results[x++]=S(87,UNDER("/proc/self/fd/",e,"/inner"),0,0);results[x++]=S(4,"/tmp/paludarium-files-dir2/inner",st,0);
  results[x++]=S(84,dd2,0,0);results[x++]=S(4,UNDER("/proc/self/fd/",e,"/inner"),st,0);
  /* The working directory's link. */
  long ok=S(79,here,300,0);S(80,"/tmp",0,0);results[x++]=S(4,"/proc/self/cwd/paludarium-files-fixture",st,0);if(ok>0)S(80,here,0,0);
  results[x++]=S(4,"/proc/self/exe/x",st,0);
  /* openat2's RESOLVE_* flags meet the link inside the path too: a magic link (ELOOP) and another mount (EXDEV). */
  {static unsigned long how[3];how[0]=0;how[1]=0;
   for(int k=0;k<3;k++){how[2]=k==0?0x02:k==1?0x04:0x01;long o2=call(437,-100,(long)UNDER("/proc/self/fd/",d,"/paludarium-files-fixture"),(long)how,24,0,0);results[x++]=o2>=0?0:o2;if(o2>=0)S(3,o2,0,0);}
   how[2]=0x10;long o3=call(437,-100,(long)UNDER("/proc/self/fd/",d,"/paludarium-files-fixture"),(long)how,24,0,0);results[x++]=o3>=0;if(o3>=0)S(3,o3,0,0);}
  S(3,e,0,0);S(3,d,0,0);S(3,op,0,0);}
 if(CASE==66){ /* an O_PATH descriptor refuses I/O (EBADF), as Linux's fdget has it */
  static long xv[2];static int pf[2];
  S(1,fd,"abcd",4);long op=S(2,p,010000000,0),dp=S(2,"/tmp",010200000,0);
  results[x++]=S(74,op,0,0);results[x++]=S(75,op,0,0);results[x++]=call(221,op,0,0,0,0,0);
  results[x++]=S(0,op,buf,1);results[x++]=S(1,op,"x",1);results[x++]=call(17,op,(long)buf,1,0,0,0);
  results[x++]=S(8,op,0,0);results[x++]=S(16,op,0x541B,xv);results[x++]=S(73,op,1,0);
  results[x++]=call(285,op,0,0,8,0,0);results[x++]=call(9,0,4096,1,2,op,0);
  results[x++]=call(193,op,(long)"user.k",(long)buf,8,0,0);results[x++]=call(190,op,(long)"user.k",(long)"v",1,0,0);
  results[x++]=call(196,op,(long)buf,64,0,0,0);results[x++]=call(199,op,(long)"user.k",0,0,0,0);
  results[x++]=S(217,dp,buf,4096);results[x++]=call(40,fd,op,0,1,0,0);results[x++]=call(326,op,0,fd,0,1,0);
  results[x++]=S(72,op,4,0);results[x++]=S(72,op,1,0);results[x++]=S(72,op,3,0)&0xffffff;
  results[x++]=S(5,op,st,0);results[x++]=S(138,op,buf,0);results[x++]=S(81,dp,0,0);
  pf[0]=op;pf[1]=1;results[x++]=S(7,pf,1,0);results[x++]=((short*)pf)[3];
  {static unsigned long set[16];set[op/64]=1UL<<(op%64);static long tv[2];results[x++]=call(23,op+1,(long)set,0,0,(long)tv,0);}
  long ep=S(291,0,0,0);xv[0]=1;results[x++]=call(233,ep,1,op,(long)xv,0,0);
  results[x++]=call(233,op,1,ep,(long)xv,0,0);results[x++]=call(232,op,(long)xv,1,0,0,0);S(3,ep,0,0);
  long d=S(32,op,0,0);results[x++]=d>=0;results[x++]=S(3,d,0,0);
  S(3,op,0,0);S(3,dp,0,0);}
 if(CASE==42){ /* close_range(first, last, flags): 4..7 are copies of fd 3 */
  #define CR(f,l,fl) call(436,f,l,fl,0,0,0)
  #define OPEN(n) (S(72,n,1,0)>=0)
  S(32,fd,0,0);S(32,fd,0,0);S(32,fd,0,0);S(32,fd,0,0);
  results[x++]=CR(5,6,0);results[x++]=OPEN(5);results[x++]=OPEN(6);results[x++]=OPEN(7);results[x++]=S(72,5,1,0);
  results[x++]=CR(4,5,4);results[x++]=S(72,4,1,0);results[x++]=S(72,fd,1,0);
  results[x++]=CR(6,5,0);results[x++]=CR(4,4,1);results[x++]=CR(4,4,8);results[x++]=OPEN(4);
  results[x++]=CR(100,~0u,0);results[x++]=CR(7,~0u,2);results[x++]=OPEN(7);results[x++]=OPEN(4);
  results[x++]=CR(0x100000004L,4,0);results[x++]=OPEN(4);results[x++]=S(32,fd,0,0);
  results[x++]=CR(4,4,6);results[x++]=S(72,4,1,0);S(3,4,0,0);}
 if(CASE==59){ /* descriptors and fcntl/ioctl commands in registers with a dirty upper half: Linux reads an int */
  #define W(n) ((long)(n)|0x500000000L)
  long d=S(72,W(fd),1030,10);results[x++]=d;results[x++]=S(72,W(d),1,0);results[x++]=S(72,W(d),2,0);results[x++]=S(72,d,1,0);
  results[x++]=S(16,W(d),0x5451,0);results[x++]=S(72,d,1,0);results[x++]=S(72,W(fd),3,0)&3;
  results[x++]=S(1,W(fd),"abc",3);results[x++]=S(8,W(fd),1,0);results[x++]=S(0,W(fd),buf,2);
  results[x++]=S(5,W(fd),st,0);results[x++]=*(long*)(st+48);results[x++]=S(73,W(fd),6,0);results[x++]=S(73,W(fd),8,0);
  long e=S(32,W(fd),0,0);results[x++]=e;results[x++]=S(3,W(e),0,0);results[x++]=S(72,e,1,0);
  long t=S(2,"/tmp",65536,0);long o=call(257,W(t),(long)(p+5),0,0,0,0);results[x++]=o>=0;
  results[x++]=S(72,0x7fffffff00000000L|99,1,0);results[x++]=S(72,d,W(1),0);results[x++]=S(16,d,W(0x5450),0);results[x++]=S(72,d,W(1),0);results[x++]=S(72,W(0xffffffffL),1,0);
  S(3,d,0,0);S(3,t,0,0);S(3,o,0,0);}
 if(CASE==63){ /* renameat2: RENAME_NOREPLACE (1), RENAME_EXCHANGE (2), and the flags Linux refuses */
  #define R2(a,b,f) call(316,-100,(long)(a),-100,(long)(b),f,0)
  #define RSIZE(n) (S(4,n,st,0)<0?-1:*(long*)(st+48))
  #define ISDIR(n) (S(6,n,st,0)<0?-1:(*(unsigned*)(st+24)&0170000)==040000)
  #define LINKS(n) (S(4,n,st,0)<0?-1:*(long*)(st+16))
  static char d[]="/tmp/paludarium-files-dir",sub[]="/tmp/paludarium-files-dir/sub";
  S(1,fd,"abc",3);long o=S(2,q,66,0600);S(1,o,"quux!",5);S(3,o,0,0);
  results[x++]=R2(p,q,8);results[x++]=R2(p,q,3);results[x++]=R2(p,q,6);results[x++]=R2(p,q,5);
  results[x++]=R2(p,q,1);results[x++]=R2(p,p,1);results[x++]=R2("/tmp/paludarium-files-missing",q,1);
  results[x++]=R2(p,r,2);results[x++]=R2(p,r,1);results[x++]=RSIZE(p);results[x++]=RSIZE(r);results[x++]=R2(r,p,0);
  /* An exchange swaps the files; the descriptor's name follows its file. */
  results[x++]=R2(p,q,2);results[x++]=RSIZE(p);results[x++]=RSIZE(q);
  long n=S(89,fdpath(fd),buf,4096);results[x++]=same(buf,n,q);results[x++]=R2(p,p,2);
  /* A directory and a file, in one directory and between two. */
  S(83,d,0755,0);S(83,sub,0755,0);
  results[x++]=R2(d,q,2);results[x++]=ISDIR(q);results[x++]=ISDIR(d);
  n=S(89,fdpath(fd),buf,4096);results[x++]=same(buf,n,d);results[x++]=R2(q,d,2);
  results[x++]=R2(d,sub,2);results[x++]=R2(sub,d,2);results[x++]=R2(d,sub,1);
  o=S(2,r,66,0600);S(3,o,0,0);long before=LINKS("/tmp"),dlinks=LINKS(d);
  results[x++]=R2(r,sub,2);results[x++]=ISDIR(r);results[x++]=ISDIR(sub);
  results[x++]=LINKS(d)-dlinks;results[x++]=LINKS("/tmp")-before;
  S(84,r,0,0);S(87,sub,0,0);S(84,d,0,0);}
 S(3,fd,0,0);S(87,p,0,0);S(87,q,0,0);S(87,r,0,0);
 }
 S(1,1,results,x*8);if(CASE==3||CASE==9)S(1,1,buf,3);if(CASE==23||CASE==24||CASE==27||CASE==59)S(1,1,buf,2);if(CASE==5||CASE==15)S(1,1,buf,sizeof(p)-1);S(60,0,0,0);
}




