/* Raw Linux ABI: native result is regenerated before every comparison. */
static long call(long n,long a,long b,long c,long d,long e,long f) {
 register long r10 __asm__("r10")=d,r8 __asm__("r8")=e,r9 __asm__("r9")=f;
 long out; __asm__ volatile("syscall":"=a"(out):"a"(n),"D"(a),"S"(b),"d"(c),"r"(r10),"r"(r8),"r"(r9):"rcx","r11","memory"); return out;
}
#define S(n,a,b,c) call(n,(long)(a),(long)(b),(long)(c),0,0,0)
static char p[]="/tmp/paludarium-u7-fixture",q[]="/tmp/paludarium-u7-link",r[]="/tmp/paludarium-u7-renamed";
static char buf[4096]; static long results[16]; static unsigned char st[144];
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
 if(CASE==32){S(83,r,0755,0);S(88,r,q,0);results[x++]=S(84,"/tmp/paludarium-u7-link/",0,0);results[x++]=S(82,"/tmp/paludarium-u7-link/",p,0);results[x++]=S(87,"/tmp/paludarium-u7-link/",0,0);results[x++]=S(4,r,st,0);results[x++]=S(6,q,st,0);results[x++]=S(2,"/tmp/paludarium-u7-unused",64|65536,0600);results[x++]=S(4,"/tmp/paludarium-u7-unused",st,0);S(87,"/tmp/paludarium-u7-unused",0,0);S(87,q,0,0);S(84,r,0,0);}
 S(3,fd,0,0);S(87,p,0,0);S(87,q,0,0);S(87,r,0,0);
 }
 S(1,1,results,x*8);if(CASE==3||CASE==9)S(1,1,buf,3);if(CASE==23||CASE==24||CASE==27)S(1,1,buf,2);if(CASE==5||CASE==15)S(1,1,buf,sizeof(p)-1);S(60,0,0,0);
}




