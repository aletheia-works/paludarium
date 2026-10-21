/* U6 finite raw Linux ABI observations; no libc/runtime startup. */
typedef unsigned long U;
typedef long I;
static I sc(I n,U a,U b,U c,U d,U e,U f) {
 register U r10 __asm__("r10")=d, r8 __asm__("r8")=e, r9 __asm__("r9")=f;
 I r; __asm__ volatile("syscall":"=a"(r):"a"(n),"D"(a),"S"(b),"d"(c),"r"(r10),"r"(r8),"r"(r9):"rcx","r11","memory");return r;
}
#define S(n,a,b,c) sc(n,(U)(a),(U)(b),(U)(c),0,0,0)
#define NB 0x800
#define CE 0x80000
#define ET 0x80000000U
#define ONE 0x40000000U
struct Ev { unsigned events; U data; } __attribute__((packed));
struct Poll { int fd; short events,revents; };
static volatile I signals;
static void handler(int sig) {(void)sig;signals++;}
__asm__(".global restorer\nrestorer: mov $15,%rax; syscall");
extern void restorer(void);
static void action(U h,U flags) {U a[4]={h,flags|0x4000000,(U)restorer,0};sc(13,14,(U)a,0,8,0,0);}
static void alarm_us(U us) {U a[4]={0,0,0,us};S(38,0,a,0);}
static U now(void) {U t[2];S(228,1,t,0);return t[0]*1000000000+t[1];}
static I event(U value,U flags){return S(290,value,flags,0);}
static I ep(void){return S(291,0,0,0);}
static I ctl(I e,I op,I fd,unsigned mask,U data) {struct Ev ev={mask,data};return sc(233,e,op,fd,(U)&ev,0,0);}
static I wait(I e,struct Ev *out,I max,I ms){return sc(232,e,(U)out,max,ms,0,0);}
static I put(I fd,U value){return S(1,fd,&value,8);}
static I get(I fd,U *value){return S(0,fd,value,8);}
static void closefd(I fd){S(3,fd,0,0);}
static char pressure_buffer[65536],pressure_stack[65536] __attribute__((aligned(16)));
static int pressure_fds[2];
static unsigned pressure_ready,pressure_tid;
static U pressure_drained;
extern I pressure_spawn(U flags,void *sp,unsigned *ptid,unsigned *ctid,void *tls);
void pressure_child(void) {
 while(!__atomic_load_n(&pressure_ready,__ATOMIC_SEQ_CST)){}
 for(unsigned i=0;i<2048;i++){I r=S(0,pressure_fds[1],pressure_buffer,sizeof(pressure_buffer));if(r<0)break;__atomic_fetch_add(&pressure_drained,(U)r,__ATOMIC_SEQ_CST);}
 S(60,0,0,0);__builtin_unreachable();
}
__asm__(".global pressure_spawn\npressure_spawn: mov %rcx,%r10; mov $56,%eax; syscall; test %rax,%rax; jnz 1f; xor %ebp,%ebp; call pressure_child; ud2; 1: ret");
static I fill_stream(int fd,I *partial,U *queued) {
 I last=0;*partial=0;*queued=0;
 for(unsigned i=0;i<1024;i++) {last=S(1,fd,pressure_buffer,sizeof(pressure_buffer));if(last<0)break;*queued+=(U)last;if((U)last<sizeof(pressure_buffer))*partial=1;}
 return last;
}
static I run(I *o) {
 U x=0;struct Ev out[4]={{0,0}};I fd=-1,e=-1,d=-1;int p[2]={-1,-1};char b[8]={0};int id=CASE;
 if(CASE>=79) {
  e=ep();
  if(CASE==79){fd=event(2,NB|1);ctl(e,1,fd,4|ET,79);o[0]=wait(e,out,1,0);get(fd,&x);o[1]=wait(e,out,1,0);o[2]=x;o[3]=wait(e,out,1,0);return 0;}
  sc(53,1,1|NB,0,(U)p,0,0);ctl(e,1,p[0],4|ET,80);o[0]=wait(e,out,1,0);
  S(1,p[0],"abc",3);
  if(CASE==80){o[1]=wait(e,out,1,0);S(0,p[1],b,1);o[2]=wait(e,out,1,0);S(0,p[1],b,2);o[3]=wait(e,out,1,0);return 0;}
  S(1,p[0],"de",2);wait(e,out,1,0);S(0,p[1],b,3);o[1]=wait(e,out,1,0);S(0,p[1],b,1);o[2]=wait(e,out,1,0);S(0,p[1],b,1);o[3]=wait(e,out,1,0);return 0;
 }
 if(CASE>=67) {
  e=ep();
  if(CASE<=69) {
   fd=event(0,NB);ctl(e,1,fd,1|ET|(CASE==69?ONE:0),67);
   put(fd,1);o[0]=wait(e,out,1,0);put(fd,1);o[1]=wait(e,out,1,0);
   if(CASE==67){get(fd,&x);o[2]=x;return 0;}
   if(CASE==68){get(fd,&x);o[2]=wait(e,out,1,0);put(fd,3);o[3]=wait(e,out,1,0);return 0;}
   ctl(e,3,fd,1|ET|ONE,69);o[2]=wait(e,out,1,0);o[3]=wait(e,out,1,0);return 0;
  }
  if(CASE<=72) {
   o[0]=sc(53,1,1|NB,0,(U)p,0,0);ctl(e,1,p[1],1|ET|(CASE==72?ONE:0),70);
   S(1,p[0],"ab",2);I first=wait(e,out,1,0);S(1,p[0],"c",1);I second=wait(e,out,1,0);
   if(CASE==70){o[1]=first;o[2]=second;o[3]=S(0,p[1],b,3);return 0;}
   o[0]=first;o[1]=second;
   if(CASE==71){S(0,p[1],b,3);o[2]=wait(e,out,1,0);S(1,p[0],"d",1);o[3]=wait(e,out,1,0);return 0;}
   ctl(e,3,p[1],1|ET|ONE,72);o[2]=wait(e,out,1,0);o[3]=wait(e,out,1,0);return 0;
  }
  /* Handler return must restore the original mask, not the temporary one.
     Timer arrival is bounded by the syscall deadline, not a scheduling sleep. */
  action((U)handler,0);U blocked=1UL<<13,mask=0,after=0;
  if(CASE!=74)sc(14,0,(U)&blocked,0,8,0,0);
  if(CASE==75)mask=blocked;
  if(CASE==76)action(1,0);
  if(CASE==77){fd=event(1,NB);ctl(e,1,fd,1,77);}
  if(CASE<=76)alarm_us(CASE==75||CASE==76?1000:20000);
  o[0]=sc(281,e,(U)out,CASE==78?0:1,CASE==75||CASE==76?20:500,(U)&mask,8);
  o[1]=signals;sc(14,2,0,(U)&after,8,0,0);o[2]=(after&blocked)!=0;
  alarm_us(0);return 0;
 }
 if(CASE>=64&&CASE<=66) {
  sc(53,1,1|NB,0,(U)pressure_fds,0,0);
  e=ep();ctl(e,1,pressure_fds[0],4|ET,77);
  I initially=wait(e,out,1,0),partial=0;U queued=0;
  I last=fill_stream(pressure_fds[0],&partial,&queued);
  if(CASE==64) {
   o[0]=last;o[1]=initially;o[2]=wait(e,out,1,0)==0;
   for(unsigned i=0;i<2048;i++){I r=S(0,pressure_fds[1],pressure_buffer,sizeof(pressure_buffer));if(r<0)break;}
   o[3]=wait(e,out,1,0);return 0;
  }
  if(CASE==65) {o[0]=last;o[1]=partial;o[2]=queued>0;o[3]=queued<67108864UL;return 0;}
  /* Native capacity is a host setting: compare completion and progress,
     never a fixed queue byte count or a timing guess. */
  S(72,pressure_fds[0],4,0);
  I tid=pressure_spawn(0x50f00UL|0x100000UL|0x1000000UL|0x200000UL,pressure_stack+sizeof(pressure_stack),&pressure_tid,&pressure_tid,0);
  if(tid<0){o[0]=tid;return 0;}
  __atomic_store_n(&pressure_ready,1,__ATOMIC_SEQ_CST);
  o[0]=last;o[1]=S(1,pressure_fds[0],pressure_buffer,32768)==32768;
  while(__atomic_load_n(&pressure_tid,__ATOMIC_SEQ_CST)){unsigned value=__atomic_load_n(&pressure_tid,__ATOMIC_SEQ_CST);if(value)sc(202,(U)&pressure_tid,0,value,0,0,0);}
  o[2]=__atomic_load_n(&pressure_drained,__ATOMIC_SEQ_CST)>0;o[3]=S(72,pressure_fds[0],3,0)==2;return 0;
 }
 if(CASE<16){
 fd=event(CASE==0?7:CASE==2?3:0,NB|(CASE==2?1:0));
 switch(id){
 case 0:o[0]=get(fd,&x);o[1]=x;break;
 case 1:o[0]=put(fd,2);o[1]=put(fd,3);o[2]=get(fd,&x);o[3]=x;break;
 case 2:o[0]=get(fd,&x);o[1]=x;o[2]=get(fd,&x);o[3]=x;break;
 case 3:o[0]=get(fd,&x);break;
 case 4:o[0]=put(fd,0);o[1]=get(fd,&x);break;
 case 5:o[0]=put(fd,~0UL);break;
 case 6:o[0]=put(fd,~0UL-1);o[1]=put(fd,1);o[2]=get(fd,&x);o[3]=x==~0UL-1;break;
 case 7:o[0]=S(0,fd,&x,7);break;
 case 8:o[0]=S(1,fd,&x,7);break;
 case 9:put(fd,1);o[0]=S(0,fd,1,8);break;
 case 10:o[0]=S(1,fd,1,8);break;
 case 11:o[0]=event(0,0x400000);break;
 case 12:d=S(32,fd,0,0);put(d,9);closefd(fd);o[0]=get(d,&x);o[1]=x;break;
 case 13:d=S(72,fd,0,30);S(72,d,4,0);o[0]=(S(72,fd,3,0)&NB)==0;o[1]=d>=30;break;
 case 14:d=event(0,NB|CE);o[0]=S(72,d,1,0);o[1]=(S(72,d,3,0)&NB)!=0;break;
 case 15:{struct Poll poll={(int)fd,5,0};o[0]=S(7,&poll,1,0);o[1]=poll.revents;put(fd,1);poll.revents=0;o[2]=S(7,&poll,1,0);o[3]=poll.revents;break;}
 }return 0;
 }
 if(CASE<36){
 fd=event(0,NB);e=ep();
 switch(id){
 case 16:o[0]=S(291,2,0,0);break;
 case 17:o[0]=S(213,0,0,0);break;
 case 18:o[0]=ctl(e,1,fd,1,17);put(fd,1);o[1]=wait(e,out,1,0);o[2]=out[0].events;o[3]=out[0].data;break;
 case 19:ctl(e,1,fd,1,1);put(fd,1);o[0]=wait(e,out,1,0);o[1]=wait(e,out,1,0);get(fd,&x);o[2]=wait(e,out,1,0);break;
 case 20:ctl(e,1,fd,1|ET,1);put(fd,1);o[0]=wait(e,out,1,0);o[1]=wait(e,out,1,0);get(fd,&x);put(fd,1);o[2]=wait(e,out,1,0);break;
 case 21:ctl(e,1,fd,1|ONE,1);put(fd,1);o[0]=wait(e,out,1,0);o[1]=wait(e,out,1,0);o[2]=ctl(e,3,fd,1|ONE,2);o[3]=wait(e,out,1,0);break;
 case 22:o[0]=ctl(e,1,fd,1,1);o[1]=ctl(e,1,fd,1,2);break;
 case 23:o[0]=ctl(e,3,fd,1,1);break;
 case 24:o[0]=ctl(e,2,fd,0,0);break;
 case 25:ctl(e,1,fd,1,1);o[0]=sc(233,e,2,fd,0,0,0);put(fd,1);o[1]=wait(e,out,1,0);break;
 case 26:o[0]=ctl(e,1,e,1,1);break;
 case 27:o[0]=ctl(e,1,9999,1,1);break;
 case 28:o[0]=wait(e,out,0,0);break;
 case 29:o[0]=wait(fd,out,1,0);break;
 case 30:ctl(e,1,fd,1,1);put(fd,1);o[0]=wait(e,(struct Ev*)1,1,0);break;
 case 31:d=S(32,fd,0,0);ctl(e,1,fd,1,11);closefd(fd);put(d,1);o[0]=wait(e,out,1,0);o[1]=out[0].data;closefd(d);o[2]=wait(e,out,1,0);break;
 case 32:d=S(32,fd,0,0);o[0]=ctl(e,1,fd,1,11);o[1]=ctl(e,1,d,1,22);put(fd,1);o[2]=wait(e,out,4,0);o[3]=(out[0].data+out[1].data);break;
 case 33:ctl(e,1,fd,1,11);closefd(fd);d=event(1,NB);o[0]=d==fd;o[1]=wait(e,out,1,0);o[2]=ctl(e,1,d,1,22);o[3]=wait(e,out,1,0);break;
 case 34:{I f2=event(1,NB);put(fd,1);ctl(e,1,fd,1,11);ctl(e,1,f2,1,22);o[0]=wait(e,out,1,0);U a=out[0].data;o[1]=wait(e,out,1,0);o[2]=a!=out[0].data;break;}
 case 35:{U start=now();o[0]=wait(e,out,1,20);U elapsed=now()-start;o[1]=elapsed>=15000000&&elapsed<1000000000;break;}
 }return 0;
 }
 if(CASE<48){
 o[0]=sc(53,1,1|NB|CE,0,(U)p,0,0);
 switch(id){
 case 36:o[1]=S(1,p[0],"abc",3);o[2]=S(0,p[1],b,8);o[3]=b[0]=='a'&&b[1]=='b'&&b[2]=='c';break;
 case 37:S(1,p[0],"a",1);S(1,p[1],"b",1);o[1]=S(0,p[0],b,1);o[2]=b[0];o[3]=S(0,p[1],b,1)*100;o[3]+=b[0];break;
 case 38:o[1]=S(0,p[0],b,1);break;
 case 39:S(1,p[0],"abcd",4);o[1]=S(0,p[1],b,2);o[2]=S(0,p[1],b+2,2);o[3]=b[0]=='a'&&b[3]=='d';break;
 case 40:closefd(p[0]);o[1]=S(0,p[1],b,1);break;
 case 41:{U a[4]={1,0x4000000,(U)restorer,0};sc(13,13,(U)a,0,8,0,0);closefd(p[0]);o[1]=S(1,p[1],"a",1);break;}
 case 42:o[1]=S(48,p[0],1,0);o[2]=S(0,p[1],b,1);break;
 case 43:o[1]=S(72,p[0],1,0);o[2]=(S(72,p[0],3,0)&NB)!=0;d=S(32,p[0],0,0);o[3]=S(72,d,1,0);break;
 case 44:o[1]=sc(44,p[0],(U)"xyz",3,0x4000,0,0);o[2]=sc(45,p[1],(U)b,8,0,0,0);o[3]=b[2]=='z';break;
 case 45:e=ep();ctl(e,1,p[1],1|0x2000,7);closefd(p[0]);o[1]=wait(e,out,1,0);o[2]=out[0].events;break;
 case 46:e=ep();ctl(e,1,p[1],1|ET,7);S(1,p[0],"ab",2);o[1]=wait(e,out,1,0);S(0,p[1],b,1);o[2]=wait(e,out,1,0);S(0,p[1],b,1);S(1,p[0],"c",1);o[3]=wait(e,out,1,0);break;
 case 47:S(1,p[0],"a",1);o[1]=S(0,p[1],1,1);o[2]=S(1,p[0],1,1);break;
 }return 0;
 }
 action((U)handler,0);e=ep();fd=event(0,NB);
 switch(id){
 case 48:alarm_us(20000);o[0]=wait(e,out,1,500);o[1]=signals;break;
 case 49:{U mask=1UL<<13;sc(14,0,(U)&mask,0,8,0,0);alarm_us(1000);o[0]=wait(e,out,1,20);o[1]=signals;alarm_us(0);break;}
 case 50:action(1,0);alarm_us(1000);o[0]=wait(e,out,1,20);o[1]=signals;break;
 case 51:{U mask=0;o[0]=sc(281,e,(U)out,1,0,(U)&mask,8);break;}
 case 52:d=S(41,2,1,0);o[0]=d<0?d:0;closefd(d);break;
 case 53:d=S(41,10,1,0);o[0]=d<0?d:0;closefd(d);break;
 case 54:o[0]=sc(53,2,1,0,(U)p,0,0);break;
 case 55:o[0]=sc(53,1,1,0,1,0,0);break;
 case 56:o[0]=sc(53,1,1|0x400000,0,(U)p,0,0);break;
 case 57:o[0]=ctl(e,9,fd,1,1);break;
 case 58:ctl(e,1,fd,1|ET,1);o[0]=ctl(e,3,fd,4|ET,2);o[1]=wait(e,out,1,0);o[2]=out[0].events;o[3]=out[0].data;break;
 case 59:fd=event(0,0);alarm_us(20000);o[0]=get(fd,&x);o[1]=signals;break;
 case 60:S(62,S(39,0,0,0),9,0);break;
 case 61:alarm_us(1000000);alarm_us(0);o[0]=wait(e,out,1,20);o[1]=signals;break;
 case 62:d=ep();ctl(d,1,fd,1,31);o[0]=ctl(e,1,d,1,32);put(fd,1);o[1]=wait(e,out,1,0);o[2]=out[0].events;o[3]=out[0].data;break;
 case 63:sc(53,1,1|NB,0,(U)p,0,0);closefd(p[0]);o[0]=sc(44,p[1],(U)"a",1,0x4000,0,0);break;
 }return 0;
}
void start(void){I out[4]={0};run(out);S(1,1,out,sizeof(out));S(231,0,0,0);__builtin_unreachable();}
__asm__(".global _start\n_start: and $-16,%rsp; call start");
