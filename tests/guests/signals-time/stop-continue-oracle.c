#define _GNU_SOURCE
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>

/* Native-only parent/child observer. Guest clone remains U5. */
int main(int argc, char **argv) {
    if(argc!=2)return 90;
    int mode=atoi(argv[1]), stop=(mode==1||mode==4)?SIGTSTP:SIGSTOP;
    pid_t child=fork();
    if(child<0)return 91;
    if(child==0){
        /* Keep the child group non-orphaned: parent is in the same session. */
        if(setpgid(0,0))_exit(92);
        if(mode==2){sigset_t mask;sigemptyset(&mask);sigaddset(&mask,SIGCONT);if(sigprocmask(SIG_BLOCK,&mask,NULL))_exit(93);}
        if(mode==4){sigset_t mask;sigemptyset(&mask);sigaddset(&mask,SIGTSTP);if(sigprocmask(SIG_BLOCK,&mask,NULL))_exit(93);}
        raise(stop);_exit(7);
    }
    int state;
    if(waitpid(child,&state,WUNTRACED)!=child)return 94;
    if(mode==4&&WIFEXITED(state)){printf("stopped=0 exit=%d signal=0\n",WEXITSTATUS(state));return 0;}
    if(!WIFSTOPPED(state)){kill(child,SIGKILL);waitpid(child,NULL,0);return 94;}
    printf("stopped=%d ",WSTOPSIG(state));
    if(mode>=5){for(int i=0;i<2048;i++)if(kill(child,SIGRTMIN))return 97;}
    if(kill(child,(mode==3||mode>=5)?SIGKILL:SIGCONT))return 95;
    if(mode==6&&kill(child,SIGCONT)&&errno!=ESRCH)return 98;
    if(waitpid(child,&state,0)!=child)return 96;
    printf("exit=%d signal=%d\n",WIFEXITED(state)?WEXITSTATUS(state):-1,WIFSIGNALED(state)?WTERMSIG(state):0);
    return 0;
}
