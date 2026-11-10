/* splice (275), tee (276) and vmsplice (278) through the raw Linux ABI; the
   native result is regenerated before every comparison. Each case writes its
   results as longs. Pipes are only compared empty or full of whole pages, as
   Linux counts a pipe's capacity in page buffers. */
static long call(long n,long a,long b,long c,long d,long e,long f) {
 register long r10 __asm__("r10")=d,r8 __asm__("r8")=e,r9 __asm__("r9")=f;
 long out; __asm__ volatile("syscall":"=a"(out):"a"(n),"D"(a),"S"(b),"d"(c),"r"(r10),"r"(r8),"r"(r9):"rcx","r11","memory"); return out;
}
#define S(n,a,b,c) call(n,(long)(a),(long)(b),(long)(c),0,0,0)
#define SPLICE(i,oi,o,oo,len,fl) call(275,i,(long)(oi),o,(long)(oo),len,fl)
#define TEE(i,o,len,fl) call(276,i,o,len,fl,0,0)
#define VMSPLICE(f,iov,n,fl) call(278,f,(long)(iov),n,fl,0,0)
#define R(v) (results[x++]=(v))
static char p[]="/tmp/paludarium-splice-in",q[]="/tmp/paludarium-splice-out",big[]="/tmp/paludarium-splice-big",fifo[]="/tmp/paludarium-splice-fifo";
static char buf[16384]; static long results[128]; static long x;
static char page[8192] __attribute__((aligned(4096)));
static long sum(const char *b,long n){long s=0;for(long i=0;i<n;i++)s=s*31+b[i];return s;}
/* What a pipe holds (FIONREAD). */
static long unread(long fd){int n=-1;long r=S(16,fd,0x541b,&n);return r<0?r:n;}
/* SIGPIPE is blocked, so whether one is pending tells it was raised; it is
   taken again with rt_sigtimedwait. */
static unsigned long pipe_mask=1UL<<12;
static long sigpipe_pending(void){
 unsigned long set=0;S(127,&set,8,0);long was=(set>>12)&1;
 static long zero[2];if(was)call(128,(long)&pipe_mask,0,(long)zero,8,0,0);return was;
}
static void pipe_of(int *fds,long flags,long size){call(293,(long)fds,flags,0,0,0,0);if(size)S(72,fds[0],1031,size);}
void _start(void) {
 call(14,0,(long)&pipe_mask,0,8,0,0);
 S(87,p,0,0);S(87,q,0,0);S(87,big,0,0);S(87,fifo,0,0);
 long fd=call(257,-100,(long)p,66,0644,0,0);S(1,fd,"0123456789",10);S(8,fd,0,0);
 long o=call(257,-100,(long)q,66,0644,0,0);
 int pf[2];pipe_of(pf,0,0);
 static long a,b;
 if(CASE==69){ /* a file and a pipe, with Linux's checks in order */
  long ro=S(2,q,0,0),ap=S(2,q,02001,0),wo=S(2,p,1,0),d=S(2,"/tmp",65536,0),op=S(2,p,010000000,0),efd=S(290,0,0,0);
  R(SPLICE(99,0,99,0,0,0));R(SPLICE(fd,0,pf[1],0,4,0x10));R(SPLICE(99,0,pf[1],0,4,0));R(SPLICE(fd,0,99,0,4,0));
  R(SPLICE(fd,0,pf[1],0,4,0));R(S(8,fd,0,1));long n=S(0,pf[0],buf,16);R(n);R(sum(buf,n));
  a=6;R(SPLICE(fd,&a,pf[1],0,100,0));R(a);R(S(8,fd,0,1));
  R(SPLICE(pf[0],0,o,0,100,0));R(S(8,o,0,1));
  S(1,pf[1],"abc",3);b=10;R(SPLICE(pf[0],0,o,&b,100,0));R(b);R(S(8,o,0,1));
  /* An offset for a pipe, before the access is looked at; then reading the offset. */
  a=0;R(SPLICE(pf[0],&a,o,0,1,0));R(SPLICE(fd,0,pf[1],&a,1,0));R(SPLICE(pf[1],&a,o,0,1,0));
  R(SPLICE(fd,1,pf[1],0,1,0));R(SPLICE(pf[0],0,o,1,1,0));
  /* An unreadable offset for a pipe end is still ESPIPE: __do_splice looks at the pipe first. */
  R(SPLICE(pf[0],1,o,0,1,0));R(SPLICE(fd,0,pf[1],1,1,0));
  R(SPLICE(fd,0,o,0,1,0));R(SPLICE(pf[1],0,o,0,1,0));R(SPLICE(fd,0,pf[0],0,1,0));R(SPLICE(pf[0],0,pf[1],0,1,0));
  R(SPLICE(pf[0],0,o,0,1,2));R(SPLICE(pf[0],0,ro,0,1,0));R(SPLICE(pf[0],0,ap,0,1,0));
  R(SPLICE(d,0,pf[1],0,1,0));R(SPLICE(wo,0,pf[1],0,1,0));R(SPLICE(op,0,pf[1],0,1,0));R(SPLICE(op,0,pf[1],0,0,0));
  a=-1;R(SPLICE(fd,&a,pf[1],0,1,0));a=0x7fffffffffffffffL;R(SPLICE(fd,&a,pf[1],0,1,0));b=-1;R(SPLICE(pf[0],0,o,&b,1,0));
  a=100;R(SPLICE(fd,&a,pf[1],0,1,0));R(a);
  R(SPLICE(efd,0,pf[1],0,1,0));S(1,pf[1],"z",1);R(SPLICE(pf[0],0,efd,0,1,0));R(SPLICE(pf[0],0,o,0,1,0));
  /* A pipe of one page takes one page of a larger file; full, it takes none. */
  long g=call(257,-100,(long)big,66,0644,0,0);for(long i=0;i<8192;i++)buf[i]='a'+i%26;S(1,g,buf,8192);S(8,g,0,0);
  int one[2];pipe_of(one,0,4096);R(SPLICE(g,0,one[1],0,8192,0));R(S(8,g,0,1));R(SPLICE(g,0,one[1],0,8192,2));
  int nb[2];pipe_of(nb,04000,4096);R(SPLICE(g,0,nb[1],0,4096,0));R(SPLICE(g,0,nb[1],0,4096,0));
  R(SPLICE(one[0],0,o,0,100000,0));R(SPLICE(nb[0],0,o,0,100000,0));R(SPLICE(nb[0],0,o,0,1,0));
  /* No reader: EPIPE and SIGPIPE, even with nothing left to read. */
  int gone[2];pipe_of(gone,0,0);S(3,gone[0],0,0);R(SPLICE(fd,0,gone[1],0,1,0));R(sigpipe_pending());
  a=1000;R(SPLICE(fd,&a,gone[1],0,1,0));R(sigpipe_pending());
  /* No writer: an empty pipe is at its end. */
  S(3,gone[1],0,0);int ended[2];pipe_of(ended,0,0);S(3,ended[1],0,0);R(SPLICE(ended[0],0,o,0,1,0));
  /* A FIFO opened for reading and writing is one pipe. */
  R(S(133,fifo,0010644,0));long ff=S(2,fifo,04002,0);a=0;R(SPLICE(fd,&a,ff,0,3,0));R(SPLICE(ff,0,o,0,10,0));R(SPLICE(ff,0,ff,0,1,0));
  S(3,ro,0,0);S(3,ap,0,0);S(3,wo,0,0);S(3,d,0,0);S(3,op,0,0);S(3,efd,0,0);S(3,g,0,0);S(3,ff,0,0);
 }
 if(CASE==70){ /* tee, and splice between two pipes */
  int a2[2],b2[2],c2[2];pipe_of(a2,0,0);pipe_of(b2,0,0);pipe_of(c2,0,0);
  S(1,a2[1],"hello",5);
  R(TEE(a2[0],b2[1],100,0));R(unread(a2[0]));R(unread(b2[0]));R(TEE(a2[0],b2[1],2,0));R(unread(b2[0]));
  long n=S(0,b2[0],buf,100);R(n);R(sum(buf,n));
  R(TEE(a2[0],b2[1],0,0x10));R(TEE(99,b2[1],0,0));R(TEE(99,b2[1],1,0));R(TEE(a2[0],99,1,0));R(TEE(a2[0],a2[1],1,0));
  R(TEE(fd,b2[1],1,0));R(TEE(a2[0],o,1,0));R(TEE(a2[1],b2[1],1,0));R(TEE(a2[0],b2[0],1,0));
  R(SPLICE(a2[0],0,c2[1],0,3,0));R(unread(a2[0]));R(SPLICE(a2[0],0,c2[1],0,100,0));n=S(0,c2[0],buf,100);R(n);R(sum(buf,n));
  R(TEE(a2[0],b2[1],1,2));R(SPLICE(a2[0],0,c2[1],0,1,2));
  S(72,a2[0],4,04000);R(TEE(a2[0],b2[1],1,0));R(SPLICE(a2[0],0,c2[1],0,1,0));S(72,a2[0],4,0);
  S(72,c2[1],4,04000);R(TEE(a2[0],c2[1],1,0));R(SPLICE(a2[0],0,c2[1],0,1,0));S(72,c2[1],4,0);
  S(3,a2[1],0,0);R(TEE(a2[0],b2[1],1,0));R(SPLICE(a2[0],0,c2[1],0,1,0));
  /* A full output, then one without a reader. */
  int full[2],e[2];pipe_of(full,0,4096);S(1,full[1],buf,4096);pipe_of(e,0,0);S(1,e[1],"x",1);
  R(TEE(e[0],full[1],1,2));R(SPLICE(e[0],0,full[1],0,1,2));
  S(3,full[0],0,0);R(TEE(e[0],full[1],1,0));R(sigpipe_pending());R(SPLICE(e[0],0,full[1],0,1,0));R(sigpipe_pending());R(unread(e[0]));
  int f2[2],g2[2];pipe_of(f2,0,0);pipe_of(g2,0,0);S(3,f2[0],0,0);S(3,g2[1],0,0);
  R(TEE(g2[0],f2[1],1,0));R(sigpipe_pending());R(SPLICE(g2[0],0,f2[1],0,1,0));R(sigpipe_pending());
  /* Two pages into a pipe of one: one page goes. */
  int h[2],i2[2];pipe_of(h,0,0);pipe_of(i2,0,4096);for(long k=0;k<8192;k++)buf[k]='A'+k%26;S(1,h[1],buf,8192);
  R(TEE(h[0],i2[1],8192,0));R(unread(h[0]));R(unread(i2[0]));S(0,i2[0],buf,8192);
  R(SPLICE(h[0],0,i2[1],0,8192,0));R(unread(h[0]));n=S(0,i2[0],buf,8192);R(n);R(sum(buf,n));
 }
 if(CASE==71){ /* vmsplice: to a pipe from the guest's buffers, and back */
  static struct {const char *base;long len;} iov[2]={{"abc",3},{"defg",4}},bad[1]={{(const char*)1,3}},neg[2]={{"a",1},{"b",-1}},none[1]={{"a",0}};
  R(VMSPLICE(pf[1],iov,2,0));long n=S(0,pf[0],buf,100);R(n);R(sum(buf,n));
  R(VMSPLICE(pf[1],iov,2,0x10));R(VMSPLICE(99,iov,2,0));R(VMSPLICE(fd,iov,1,0));R(VMSPLICE(fd,iov,0,0));R(VMSPLICE(fd,none,1,0));
  R(VMSPLICE(pf[1],iov,0,0));R(VMSPLICE(pf[1],iov,1025,0));R(VMSPLICE(pf[1],1,1,0));R(VMSPLICE(pf[1],bad,1,0));R(VMSPLICE(pf[1],neg,2,0));
  long op=S(2,"/tmp",010000000,0);R(VMSPLICE(op,iov,1,0));S(3,op,0,0);
  S(1,pf[1],"hello",5);static struct {char *base;long len;} out[2]={{buf,3},{buf+10,10}};
  R(VMSPLICE(pf[0],out,2,0));R(buf[0]+buf[1]+buf[2]);R(buf[10]+buf[11]);R(VMSPLICE(pf[0],out,2,2));
  S(1,pf[1],"z",1);static struct {char *base;long len;} wild[1]={{(char*)1,1}};R(VMSPLICE(pf[0],wild,1,0));R(unread(pf[0]));S(0,pf[0],buf,1);
  /* A page-aligned buffer fills a pipe of one page; full, it takes none. */
  for(long k=0;k<8192;k++)page[k]='0'+k%10;
  int one[2];pipe_of(one,0,4096);static struct {char *base;long len;} pg[1]={{page,8192}};
  R(VMSPLICE(one[1],pg,1,0));R(unread(one[0]));R(VMSPLICE(one[1],pg,1,2));
  /* The pipe's O_NONBLOCK does not count, only the flag. */
  int nb[2];pipe_of(nb,04000,4096);R(VMSPLICE(nb[1],pg,1,0));R(VMSPLICE(nb[1],pg,1,2));R(unread(nb[0]));
  static struct {char *base;long len;} back[1]={{buf,8192}};R(VMSPLICE(one[0],back,1,0));R(sum(buf,4096));
  S(3,one[0],0,0);R(VMSPLICE(one[1],iov,1,0));R(sigpipe_pending());
  /* A pipe opened for reading and writing takes the bytes. */
  R(S(133,fifo,0010644,0));long ff=S(2,fifo,04002,0);R(VMSPLICE(ff,iov,2,0));R(unread(ff));S(3,ff,0,0);
 }
 if(CASE==72){ /* sockets and devices as the other end, and a splice that waits */
  int sv[2];call(53,1,1,0,(long)sv,0,0);S(1,sv[1],"sock",4);
  R(SPLICE(sv[0],0,pf[1],0,100,0));R(SPLICE(pf[0],0,sv[1],0,100,0));long n=S(0,sv[0],buf,10);R(n);R(sum(buf,n));
  R(SPLICE(sv[0],0,pf[1],0,100,2));a=0;R(SPLICE(sv[0],&a,pf[1],0,1,0));R(SPLICE(pf[0],0,sv[1],&a,1,0));
  long nul=S(2,"/dev/null",1,0),zero=S(2,"/dev/zero",0,0);
  S(1,pf[1],"nul",3);R(SPLICE(pf[0],0,nul,0,100,0));R(unread(pf[0]));
  R(SPLICE(zero,0,pf[1],0,5,0));n=S(0,pf[0],buf,100);R(n);R(buf[0]+buf[4]);
  /* A full pipe takes nothing from a socket that has data. */
  int one[2];pipe_of(one,0,4096);S(1,one[1],buf,4096);S(1,sv[1],"more",4);R(SPLICE(sv[0],0,one[1],0,4,2));
  R(SPLICE(sv[0],0,pf[1],0,100,0));S(0,pf[0],buf,100);
  /* The peer gone: a socket's end, and a send that raises SIGPIPE. */
  S(3,sv[1],0,0);R(SPLICE(sv[0],0,pf[1],0,100,0));
  int tv[2];call(53,1,1,0,(long)tv,0,0);S(3,tv[0],0,0);S(1,pf[1],"q",1);R(SPLICE(pf[0],0,tv[1],0,1,0));R(sigpipe_pending());R(unread(pf[0]));S(0,pf[0],buf,1);
  /* A splice that waits for a writer to come: the child writes after 50 ms. */
  long child=S(57,0,0,0);
  if(child==0){static long ts[2]={0,50000000};S(35,ts,0,0);S(1,pf[1],"late",4);S(60,0,0,0);}
  R(SPLICE(pf[0],0,o,0,100,0));int status=0;R(call(61,child,(long)&status,0,0,0,0)==child);R(status);
  /* Waiting for room: the child reads the full pipe after 50 ms. */
  child=S(57,0,0,0);
  if(child==0){static long ts[2]={0,50000000};S(35,ts,0,0);S(0,one[0],buf,4096);S(60,0,0,0);}
  a=0;R(SPLICE(fd,&a,one[1],0,10,0));R(call(61,child,(long)&status,0,0,0,0)==child);R(unread(one[0]));
  S(3,nul,0,0);S(3,zero,0,0);
 }
 /* What the output file holds. */
 long n=call(17,o,(long)buf,64,0,0,0);R(n);R(sum(buf,n));
 S(3,fd,0,0);S(3,o,0,0);S(87,p,0,0);S(87,q,0,0);S(87,big,0,0);S(87,fifo,0,0);
 S(1,1,results,x*8);S(60,0,0,0);
}
