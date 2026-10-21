/* Self-contained Linux x86-64 oracle. No libc, pthread or saved expectations. */
typedef unsigned long u64;
typedef unsigned int u32;
#define VM 0x100UL
#define FS 0x200UL
#define FILES 0x400UL
#define SIGHAND 0x800UL
#define THREAD 0x10000UL
#define SYSVSEM 0x40000UL
#define SETTLS 0x80000UL
#define PARENT_TID 0x100000UL
#define CLEAR_TID 0x200000UL
#define CHILD_TID 0x1000000UL
#define BASE (VM|FS|FILES|SIGHAND|THREAD|SYSVSEM)
static long sc(u64 n,u64 a,u64 b,u64 c,u64 d,u64 e,u64 f) {
 register u64 r10 __asm__("r10")=d,r8 __asm__("r8")=e,r9 __asm__("r9")=f;
 long r; __asm__ volatile("syscall":"=a"(r):"a"(n),"D"(a),"S"(b),"d"(c),"r"(r10),"r"(r8),"r"(r9):"rcx","r11","memory"); return r;
}
static void emit(long a,long b,long c) { long v[3]={a,b,c};sc(1,1,(u64)v,sizeof(v),0,0,0); }
static u32 word,done,ready,child_tid,parent_tid,seen_tid;
static u64 tls=0x123456789abcdefUL;
static char stack[65536] __attribute__((aligned(16)));
static long main_tid;
static long fut(u32 *p,u64 op,u64 val,u64 timeout,u64 mask) { return sc(202,(u64)p,op,val,timeout,0,mask); }
static u32 get(u32 *p) { return __atomic_load_n(p,__ATOMIC_SEQ_CST); }
static void put(u32 *p,u32 v) { __atomic_store_n(p,v,__ATOMIC_SEQ_CST); }
static void end(long code) { sc(60,code,0,0,0,0,0);__builtin_unreachable(); }
extern long spawn(u64 flags,void *sp,u32 *ptid,u32 *ctid,void *tls);
extern void restorer(void);
static volatile long signals;
static void handler(void) { ++signals;if(CASE==34||CASE==35)put(&word,1); }
struct action {u64 handler,flags,restorer,mask;};
static void pause_ns(long ns) {long t[2]={ns/1000000000,ns%1000000000};sc(35,(u64)t,0,0,0,0,0);}
static long now_ns(void) {long t[2];sc(228,1,(u64)t,0,0,0,0);return t[0]*1000000000+t[1];}
static void timer_us(long us) {long t[4]={0,0,us/1000000,us%1000000};sc(38,0,(u64)t,0,0,0,0);}
/* Keep all helpers referenced across compile-time cases without changing code. */
void child_main(void) {
 seen_tid=(u32)sc(186,0,0,0,0,0,0);
 if(CASE>=38) {
  if(CASE==39)timer_us(1000000);
  else if(CASE==40)for(unsigned i=0;i<4;i++){timer_us(1000000);timer_us(500000);timer_us(0);}
  else timer_us(0);
  /* Publish only after the timer syscall completed; parent waits on this. */
  put(&ready,1);put(&done,1);end(0);
 }
 if(CASE>=27) {
  while(!get(&ready)){}
  pause_ns(CASE>=36?150000000:50000000);
  if(CASE<=29)timer_us(CASE==29?0:50000);
  else {
   sc(234,sc(39,0,0,0,0,0,0),main_tid,10,0,0,0);
   if(CASE<36){pause_ns(50000000);fut(&word,CASE%2?138:129,1,0,1);}
  }
  put(&done,1);end(0);
 }
 if (CASE==12) {u64 got;__asm__ volatile("mov %%fs:0,%0":"=r"(got));put(&word,got==tls);}
 if (CASE==13) put(&word,get(&child_tid)==seen_tid);
 if (CASE==14) {put(&done,1);end(7);}
 if (CASE==15) {while(!get(&ready)){} emit(1,0,0);end(0);}
 if (CASE==16) {sc(231,17,0,0,0,0,0);__builtin_unreachable();}
 if (CASE==17 || CASE==18 || CASE==19 || CASE==20 || CASE==26) {
  put(&ready,1);
  long r=fut(&word,CASE==18?137:CASE==19?9:CASE==26?0:128,0,0,CASE==18||CASE==19?2:0);
  put(&done,r==0?1:2); end(0);
 }
 if (CASE==24) {for(unsigned i=0;i<10000;i++)__atomic_fetch_add(&word,1,__ATOMIC_SEQ_CST);}
 if (CASE==25) {
  for(unsigned i=0;i<100;i++) {while(get(&word)!=1){}put(&word,0);fut(&word,129,1,0,0);}
 }
 put(&done,1);end(0);
}
void test_main(void) {
 main_tid=sc(186,0,0,0,0,0,0);
 if(CASE>=38) {
  long start=now_ns();
  long tid=spawn(BASE|PARENT_TID|CHILD_TID|CLEAR_TID,stack+sizeof(stack),&parent_tid,&child_tid,0);
  if(tid<0){emit(tid,0,0);return;}
  while(!get(&ready)){}
  long t[2]={0,200000000},r;
  if(CASE==41){long deadline=now_ns()+200000000;t[0]=deadline/1000000000;t[1]=deadline%1000000000;r=sc(230,1,1,(u64)t,0,0,0);}
  else if(CASE==42)r=fut(&word,128,0,(u64)t,0);
  else r=sc(35,(u64)t,0,0,0,0,0);
  long elapsed=now_ns()-start;
  if(CASE==39)timer_us(0);
  while(!get(&done)){}
  while(get(&child_tid)){u32 value=get(&child_tid);if(value)fut(&child_tid,0,value,0,0);}
  emit(r,signals,elapsed>=150000000&&elapsed<600000000);return;
 }
 if(CASE>=27) {
  struct action a={(u64)handler,0x4000000|((CASE>=30&&CASE!=32&&CASE!=33)?0x10000000:0),(u64)restorer,0};
  sc(13,CASE<=29?14:10,(u64)&a,0,8,0,0);
  if(CASE==28)timer_us(1500000);
  if(CASE==29)timer_us(100000);
  long tid=spawn(BASE|PARENT_TID|CHILD_TID|CLEAR_TID,stack+sizeof(stack),&parent_tid,&child_tid,0);
  if(tid<0){emit(tid,0,0);return;}
  long start=now_ns(),r;
  put(&ready,1);
  if(CASE<=29){long t[2]={CASE==29?0:2,CASE==29?200000000:0};r=sc(35,(u64)t,0,0,0,0,0);}
  else {
   long t[2]={0,500000000};
   if(CASE==37){long deadline=start+500000000;t[0]=deadline/1000000000;t[1]=deadline%1000000000;}
   r=fut(&word,CASE%2?137:128,0,CASE>=36?(u64)t:0,1);
  }
  long elapsed=now_ns()-start;
  while(!get(&done)){}
  while(get(&child_tid)){u32 value=get(&child_tid);if(value)fut(&child_tid,0,value,0,0);}
  emit(r,signals,CASE<=28?elapsed<500000000:CASE==29?elapsed>=150000000:CASE>=36?(elapsed>=400000000&&elapsed<600000000):get(&word));
  return;
 }
 /* Invalid, finite futex cases determine error precedence directly. */
 if(CASE<=11) {
  long t[2]={0,1000000},bad[2]={0,1000000000};
  switch(CASE) {
  case 0:emit(fut(&word,128,1,0,0),0,0);break;
  case 1:emit(fut((u32*)0x60000000,128,0,0,0),0,0);break;
  case 2:emit(fut((u32*)((char*)&word+1),128,0,0,0),0,0);break;
  case 3:emit(fut(&word,137,0,0,0),0,0);break;
  case 4:emit(fut(&word,138,1,0,0),0,0);break;
  case 5:emit(fut(&word,128,0,(u64)bad,0),0,0);break;
  case 6:emit(fut(&word,128,0,(u64)t,0),0,0);break;
  case 7:emit(fut(&word,137,0,(u64)t,1),0,0);break;
  case 8:emit(fut(&word,393,0,(u64)t,1),0,0);break;
  case 9:emit(fut(&word,129,3,0,0),fut(&word,138,3,0,1),0);break;
  case 10:emit(fut(&word,128,0,0x60000000,0),0,0);break;
  case 11:emit(fut(&word,384,0,(u64)t,0),0,0);break;
  default:break;
  }
  return;
 }
 if(CASE==21) {
  struct action a={(u64)handler,0x4000000,(u64)restorer,0};long timer[4]={0,0,0,10000};
  sc(13,14,(u64)&a,0,8,0,0);sc(38,0,(u64)timer,0,0,0,0);
  long r=fut(&word,128,0,0,0);emit(r,signals,0);return;
 }
 if(CASE==22) {emit(spawn(VM|THREAD,stack+sizeof(stack),0,0,0),0,0);return;}
 if(CASE==23) {long r=spawn(BASE|PARENT_TID,stack+sizeof(stack),(u32*)0x60000000,0,0);if(r>0)while(!get(&done)){}emit(r>0?1:r,0,0);return;}
 u64 flags=BASE|PARENT_TID|CHILD_TID|CLEAR_TID;
 if(CASE==12)flags|=SETTLS;
 long tid=spawn(flags,stack+sizeof(stack),&parent_tid,&child_tid,&tls);
 if(tid<0){emit(tid,0,0);return;}
 if(CASE==15){put(&ready,1);end(0);}
 if(CASE==16){for(;;){}}
 if(CASE==17||CASE==18||CASE==19||CASE==20||CASE==26) {
  while(!get(&ready)){}
  if(CASE==18)emit(fut(&word,138,1,0,1),0,0);
  if(CASE==20) {sc(234,sc(39,0,0,0,0,0,0),tid,0,0,0,0);}
  long w=0;
  while(w==0)w=fut(&word,CASE==18?138:CASE==19?10:CASE==26?1:129,1,0,2);
  emit(w,0,0);
 }
 if(CASE==24)for(unsigned i=0;i<10000;i++)__atomic_fetch_add(&word,1,__ATOMIC_SEQ_CST);
 if(CASE==25)for(unsigned i=0;i<100;i++){put(&word,1);while(get(&word)==1){fut(&word,128,1,0,0);}}
 while(!get(&done)){}
 while(get(&child_tid)){u32 value=get(&child_tid);if(value)fut(&child_tid,0,value,0,0);}
 emit(tid!=main_tid,parent_tid==(u32)tid,seen_tid==(u32)tid);
 emit(get(&word),get(&done),get(&child_tid));
}
__asm__(".global spawn\nspawn:mov %rcx,%r10\nmov $56,%eax\nsyscall\ntest %rax,%rax\njnz 1f\nxor %ebp,%ebp\ncall child_main\nud2\n1:ret\n"
 ".global restorer\nrestorer:mov $15,%eax\nsyscall\n"
 ".global _start\n_start:xor %ebp,%ebp\nand $-16,%rsp\ncall test_main\nxor %edi,%edi\nmov $231,%eax\nsyscall\nud2\n");
