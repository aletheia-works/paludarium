/* Raw Linux ABI: native result is regenerated before every comparison. */
static long call(long n,long a,long b,long c,long d,long e,long f) {
 register long r10 __asm__("r10")=d,r8 __asm__("r8")=e,r9 __asm__("r9")=f;
 long out; __asm__ volatile("syscall":"=a"(out):"a"(n),"D"(a),"S"(b),"d"(c),"r"(r10),"r"(r8),"r"(r9):"rcx","r11","memory"); return out;
}
#define S(n,a,b,c) call(n,(long)(a),(long)(b),(long)(c),0,0,0)
static char p[]="/tmp/paludarium-files-fixture",q[]="/tmp/paludarium-files-link",r[]="/tmp/paludarium-files-renamed";
static char buf[4096]; static long results[64]; static unsigned char st[144];
/* "/proc/self/fd/<n>", and whether a read link (n bytes) is b. */
static char *numbered(const char *s,long n) {
 static char b[32]; char *q=b; char d[12]; int k=0;
 while(*s)*q++=*s++; do{d[k++]='0'+n%10;n/=10;}while(n); while(k)*q++=d[--k]; *q=0; return b;
}
static char *fdpath(long n) { return numbered("/proc/self/fd/",n); }
static long same(const char *a,long n,const char *b){long i=0;for(;b[i];i++)if(i>=n||a[i]!=b[i])return 0;return i==n;}
static long starts(const char *a,long n,const char *b){long i=0;for(;b[i];i++)if(i>=n||a[i]!=b[i])return 0;return 1;}
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
  results[x++]=SX(p,0,0);S(87,q,0,0);}
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
 S(3,fd,0,0);S(87,p,0,0);S(87,q,0,0);S(87,r,0,0);
 }
 S(1,1,results,x*8);if(CASE==3||CASE==9)S(1,1,buf,3);if(CASE==23||CASE==24||CASE==27)S(1,1,buf,2);if(CASE==5||CASE==15)S(1,1,buf,sizeof(p)-1);S(60,0,0,0);
}




