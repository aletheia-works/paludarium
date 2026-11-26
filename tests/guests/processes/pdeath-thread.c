/* PR_SET_PDEATHSIG is each thread's (a task's `pdeath_signal`), and comes
 * as the parent's thread that made the child exits, as Linux's
 * `forget_original_parent` sends it, even though the parent goes on: once
 * as that thread ends, and again as the parent's last thread does, which
 * the child is then a child of. Each of the child's threads that set one
 * sends its own to the child's process, from the exiting thread. */
#define _GNU_SOURCE
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>

static int ready[2], seen[2];
static pid_t parent;
static sigset_t both;
static volatile int thread_set;

static int death(void) {
    int value = -1;
    prctl(PR_GET_PDEATHSIG, &value);
    return value;
}
/* The two signals that came, lowest first, as `sigwaitinfo` takes them. */
static void took(const char *when) {
    printf("%s:", when);
    siginfo_t info;
    for (int i = 0; i < 2; i++) {
        if (sigwaitinfo(&both, &info) < 0) {
            perror("sigwaitinfo");
            _exit(1);
        }
        printf(" %d/%d/%s/%s", info.si_signo, info.si_code,
               info.si_pid == parent ? "parent" : "other",
               info.si_uid == getuid() ? "uid" : "other uid");
    }
    printf("\n");
    fflush(stdout);
}
static void *child_thread(void *arg) {
    (void)arg;
    printf("child thread before %d\n", death());
    prctl(PR_SET_PDEATHSIG, SIGUSR2);
    printf("child thread after %d\n", death());
    fflush(stdout);
    thread_set = 1;
    for (;;) pause();
    return NULL;
}
static void child(void) {
    prctl(PR_SET_PDEATHSIG, SIGUSR1);
    pthread_t made;
    pthread_create(&made, NULL, child_thread, NULL);
    while (!thread_set) usleep(1000);
    printf("child leader %d\n", death());
    fflush(stdout);
    if (write(ready[1], "r", 1) != 1) _exit(1);
    took("maker exited");
    if (write(seen[1], "s", 1) != 1) _exit(1);
    took("parent exited");
    _exit(0);
}
/* The parent's thread that makes the child, then ends. */
static void *maker(void *arg) {
    (void)arg;
    if (fork() == 0) child();
    char byte;
    if (read(ready[0], &byte, 1) != 1) exit(1);
    return NULL;
}
static void parent_process(void) {
    parent = getpid();
    pthread_t made;
    pthread_create(&made, NULL, maker, NULL);
    pthread_join(made, NULL);
    char byte;
    if (read(seen[0], &byte, 1) != 1) exit(1);
    printf("parent: exits\n");
    fflush(stdout);
    exit(0);
}

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    /* The child ends up this process's, which waits for it. */
    prctl(PR_SET_CHILD_SUBREAPER, 1);
    sigemptyset(&both);
    sigaddset(&both, SIGUSR1);
    sigaddset(&both, SIGUSR2);
    sigprocmask(SIG_BLOCK, &both, NULL);
    if (pipe(ready) || pipe(seen)) return 1;
    pid_t pid = fork();
    if (pid == 0) {
        parent = getpid();
        parent_process();
    }
    parent = pid;
    /* Both statuses after both waits: the child's lines come as the
     * parent's exit is told, which this wait races with. */
    int status, child_status;
    waitpid(pid, &status, 0);
    pid_t other = wait(&child_status);
    printf("parent: status %x\n", status);
    printf("child: %s status %x\n", other > 0 ? "reaped" : "missing", child_status);
    return 0;
}
