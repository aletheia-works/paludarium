/* Native signal state oracle, confined to newly allocated fixture pages. */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <setjmp.h>
#include <sys/mman.h>
#include <ucontext.h>
struct u3_case { const char *name; void (*run)(void *, const void *, void *); const unsigned char *op,*end; int memory; };
#include "cases.h"
static sigjmp_buf jump;
static unsigned char captured[280];
static volatile sig_atomic_t caught;
static volatile intptr_t rip_delta;
static volatile sig_atomic_t caught_code;
static volatile uint64_t caught_trap,caught_error,caught_address;
static const unsigned char *instruction;
static void handler(int number,siginfo_t *info,void *context) {
    ucontext_t *u=context;
    const unsigned char *fp=(const unsigned char *)u->uc_mcontext.fpregs;
    /* Linux x86-64 signal fpstate begins with the architectural FXSAVE area. */
    memcpy(captured,fp+160,256);
    uint64_t value=(uint64_t)u->uc_mcontext.gregs[REG_RAX]; memcpy(captured+256,&value,8);
    value=(uint64_t)u->uc_mcontext.gregs[REG_EFL]; memcpy(captured+264,&value,8);
    memcpy(captured+272,fp+24,4);
    rip_delta=(intptr_t)u->uc_mcontext.gregs[REG_RIP]-(intptr_t)instruction;
    caught=number;
    caught_code=info->si_code;
    caught_trap=(uint64_t)u->uc_mcontext.gregs[REG_TRAPNO];
    caught_error=(uint64_t)u->uc_mcontext.gregs[REG_ERR];
    caught_address=(uint64_t)(uintptr_t)info->si_addr;
    siglongjmp(jump,1);
}
static void hex(const unsigned char *p,size_t n) { for(size_t i=0;i<n;i++) printf("%02x",p[i]); }
int main(void) {
    struct sigaction sa={0}; sa.sa_sigaction=handler; sa.sa_flags=SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    if(sigaction(SIGSEGV,&sa,0)||sigaction(SIGFPE,&sa,0)||sigaction(SIGILL,&sa,0)) return 2;
    unsigned char *pages=mmap(0,8192,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    if(pages==MAP_FAILED) return 3;
    for(volatile size_t i=0;i<sizeof(cases)/sizeof(cases[0]);i++) for(volatile unsigned scenario=0;scenario<10;scenario++) {
        if(scenario<4&&!cases[i].memory) continue;
        if(scenario==5&&strncmp(cases[i].name,"ldmxcsr",7)) continue;
        if(scenario==6&&strncmp(cases[i].name,"divsd",5)) continue;
        if((scenario==7||scenario==8)&&strncmp(cases[i].name,"mulsd",5)) continue;
        if(scenario==9&&strncmp(cases[i].name,"addsd",5)) continue;
        unsigned char input[512],before[512];
        for(unsigned k=0;k<sizeof(input);k++) input[k]=(unsigned char)(k*17+3);
        static const uint64_t special[]={0x7ff0000000000001ULL,0x3ff0000000000000ULL,1,0};
        if(scenario==4) for(unsigned k=0;k<32;k++) memcpy(input+k*8,&special[k%4],8);
        if(scenario>=6) {
            uint64_t left=scenario==7?0x7fefffffffffffffULL:scenario==8?0x0010000000000000ULL:0x3ff0000000000000ULL;
            uint64_t right=scenario==6?0:scenario==7?0x4000000000000000ULL:scenario==8?0x3fb999999999999aULL:0x3ca0000000000000ULL;
            for(unsigned k=0;k<32;k++) memcpy(input+k*8,(k/2)&1?&right:&left,8);
        }
        uint32_t mxcsr=scenario==4||scenario>=6?0:0x1f80; memcpy(input+256,&mxcsr,4);
        if(mprotect(pages,8192,PROT_READ|PROT_WRITE)) return 4;
        memset(pages,0x51,8192);
        unsigned offset=scenario==2?4096-24:scenario==3?1:0;
        unsigned char *memory=pages+offset;
        memcpy(memory,input,sizeof(input));
        if(scenario==5) { uint32_t invalid=0x10000; memcpy(memory+256,&invalid,4); }
        memcpy(before,memory,sizeof(before));
        if(scenario==0&&mprotect(pages,8192,PROT_NONE)) return 5;
        if(scenario==1&&mprotect(pages,8192,PROT_READ)) return 5;
        if(scenario==2&&mprotect(pages+4096,4096,PROT_NONE)) return 5;
        caught=0; caught_code=0; caught_trap=0; caught_error=0; caught_address=0;
        rip_delta=0; instruction=cases[i].op; memset(captured,0,sizeof(captured));
        if(!sigsetjmp(jump,1)) cases[i].run(captured,input,memory);
        if(mprotect(pages,8192,PROT_READ|PROT_WRITE)) return 6;
        printf("%s|%u|%d|%ld|%d|%llu|%llu|%lld|",cases[i].name,scenario,caught,(long)rip_delta,caught_code,
               (unsigned long long)caught_trap,(unsigned long long)caught_error,
               caught_address?(long long)(caught_address-(uintptr_t)(caught_trap==19||caught_trap==6?instruction:memory)):0LL);
        hex(cases[i].op,(size_t)(cases[i].end-cases[i].op)); putchar('|'); hex(input,sizeof(input)); putchar('|');
        hex(before,sizeof(before)); putchar('|'); hex(captured,sizeof(captured)); putchar('|'); hex(memory,512); putchar('\n');
    }
    if(munmap(pages,8192)) return 7;
    return ferror(stdout)?8:0;
}
