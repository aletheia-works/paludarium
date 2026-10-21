#define _GNU_SOURCE
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

/* Native-only pending-order observer; guest fork remains U5. */
static volatile sig_atomic_t count, numbers[4], codes[4];
static void observe(int number, siginfo_t *info, void *context) {
    (void)context;
    sig_atomic_t index=count;
    if(index<4){numbers[index]=number;codes[index]=info->si_code;count=index+1;}
}
int main(int argc,char **argv) {
    if(argc!=2)return 90;
    int mode=atoi(argv[1]);
    sigset_t mask;sigemptyset(&mask);
    sigaddset(&mask,10);sigaddset(&mask,35);sigaddset(&mask,36);
    if(mode==0){
        pid_t child=fork();if(child<0)return 91;
        if(child==0){
            if(sigprocmask(SIG_BLOCK,&mask,NULL))_exit(92);
            if(kill(getpid(),36)||kill(getpid(),35))_exit(93);
            if(sigprocmask(SIG_UNBLOCK,&mask,NULL))_exit(94);
            _exit(99);
        }
        int status;if(waitpid(child,&status,0)!=child)return 95;
        printf("default_signal=%d\n",WIFSIGNALED(status)?WTERMSIG(status):0);
        return 0;
    }
    if(mode<1||mode>8)return 96;
    struct sigaction action={0};action.sa_sigaction=observe;
    action.sa_flags=SA_SIGINFO;action.sa_mask=mask;
    if(sigaction(10,&action,NULL)||sigaction(35,&action,NULL)||sigaction(36,&action,NULL))return 97;
    if(sigprocmask(SIG_BLOCK,&mask,NULL))return 92;
    if(mode==1){if(kill(getpid(),36)||kill(getpid(),35))return 93;}
    if(mode==2){union sigval value={.sival_int=22};if(kill(getpid(),35)||sigqueue(getpid(),35,value))return 93;}
    if(mode==3){if(kill(getpid(),35)||kill(getpid(),10))return 93;}
    if(mode==4){if(kill(getpid(),35)||syscall(SYS_tkill,syscall(SYS_gettid),36))return 93;}
    if(mode==5){if(kill(getpid(),35)||syscall(SYS_tgkill,getpid(),syscall(SYS_gettid),36))return 93;}
    if(mode==6){if(kill(getpid(),35)||syscall(SYS_tkill,syscall(SYS_gettid),35))return 93;}
    if(mode==7){if(kill(getpid(),10)||kill(getpid(),10)||syscall(SYS_tkill,syscall(SYS_gettid),10)||syscall(SYS_tkill,syscall(SYS_gettid),10))return 93;}
    if(mode==8){siginfo_t info={0};info.si_signo=35;info.si_code=SI_QUEUE;info.si_pid=getpid();info.si_uid=getuid();info.si_value.sival_int=22;if(syscall(SYS_tkill,syscall(SYS_gettid),35)||syscall(SYS_rt_tgsigqueueinfo,getpid(),syscall(SYS_gettid),35,&info))return 93;}
    if(sigprocmask(SIG_UNBLOCK,&mask,NULL))return 94;
    if(count!=2)return 98;
    printf("order=%d:%d,%d:%d\n",numbers[0],codes[0],numbers[1],codes[1]);
    return 0;
}
