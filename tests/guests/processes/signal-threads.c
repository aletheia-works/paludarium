#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* Which thread takes a signal sent to the process (`complete_signal`): thread 0
 * is the leader, and 1 to 3 are made in that order and wait in ppoll, but for
 * what they are told to do. Each case is a process of its own, and each step
 * waits for the one before, with a watchdog only so that nothing hangs. */
static struct shared {
    volatile int taken[65][4], loops[4], job[4], done[4], gone, vforked;
    volatile pid_t tids[4];
} *s;
static int count, pair[2];
static pid_t target;
static void ms(long n) {
    struct timespec t = {n / 1000, n % 1000 * 1000000};
    while (nanosleep(&t, &t) && errno == EINTR) {}
}
#define UNTIL(condition) \
    for (int turn = 0; turn < 2000 && !(condition); turn++) ms(5)
static void took(int number) {
    pid_t tid = (pid_t)syscall(SYS_gettid);
    for (int i = 0; i < 4; i++)
        if (s->tids[i] == tid) s->taken[number][i]++;
}
static int total(int number) {
    int n = 0;
    for (int i = 0; i < 4; i++) n += s->taken[number][i];
    return n;
}
static void mask(int how, int number) {
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, number);
    syscall(SYS_rt_sigprocmask, (long)how, &set, NULL, 8L);
}
static void handle(int number, int flags) {
    struct sigaction action = {.sa_handler = took, .sa_flags = flags};
    sigaction(number, &action, NULL);
}
/* The state letter of a thread of the target. */
static char state(pid_t tid) {
    char path[64], text[256] = "";
    snprintf(path, sizeof path, "/proc/%d/task/%d/stat", target, tid);
    int fd = open(path, O_RDONLY);
    if (fd >= 0) {
        read(fd, text, sizeof text - 1);
        close(fd);
    }
    char *end = strrchr(text, ')');
    return end ? end[2] : '?';
}
static int vforked(void *arg) {
    (void)arg;
    s->vforked = 1;
    UNTIL(total(SIGUSR2));
    _exit(0);
}
static void *thread(void *arg) {
    long i = (long)arg;
    static char stacks[4][16384] __attribute__((aligned(16)));
    s->tids[i] = (pid_t)syscall(SYS_gettid);
    for (;;) {
        int todo = s->job[i];
        if (todo) {
            s->job[i] = 0;
            switch (todo) {
            case 1: kill(getpid(), SIGUSR1); break;
            case 2: write(pair[1], "x", 1); break;
            case 3: mask(SIG_BLOCK, SIGUSR1); break;
            case 4: mask(SIG_UNBLOCK, SIGUSR1); break;
            case 5: clone(vforked, stacks[i] + sizeof stacks[i], CLONE_VM | CLONE_VFORK, NULL); break;
            case 6: /* a child that ends once fork's own blocking of signals is over */
                if (!fork()) {
                    int now = s->loops[i];
                    UNTIL(s->loops[i] > now + 2);
                    _exit(0);
                }
                break;
            case 7: /* and one that ends once this thread did */
                if (!fork()) {
                    UNTIL(syscall(SYS_tgkill, target, s->tids[i], 0) < 0);
                    _exit(0);
                }
                s->done[i]++;
                s->gone = 1;
                return NULL;
            case 8:
                while (!total(SIGPROF)) {}
                write(pair[1], "x", 1);
                break;
            case 9: mask(SIG_BLOCK, SIGUSR2); break;
            }
            s->done[i]++;
        }
        s->loops[i]++;
        syscall(SYS_ppoll, NULL, 0L, &(struct timespec){0, 5000000}, NULL, 0L);
    }
}
/* Every thread has gone round since, so that none runs a handler. */
static void settle(void) {
    for (int i = 1; i <= count; i++) {
        int now = s->loops[i];
        UNTIL(s->loops[i] > now + 2 || s->gone);
    }
}
/* Thread i does `todo`, which is then over. */
static void tell(int i, int todo) {
    int before = s->done[i];
    s->job[i] = todo;
    UNTIL(s->done[i] != before);
    settle();
}
static void start(int n) {
    count = n;
    s->tids[0] = (pid_t)syscall(SYS_gettid);
    pthread_t made;
    for (long i = 1; i <= n; i++) {
        pthread_create(&made, NULL, thread, (void *)i);
        UNTIL(s->tids[i]);
    }
    settle();
}
static void show(const char *name, int number) {
    printf("%s: %d %d %d %d\n", name, s->taken[number][0], s->taken[number][1], s->taken[number][2],
           s->taken[number][3]);
}
/* Waits for `n` of the signal in all, and for the handlers to be over. */
static void expect(int number, int n) {
    UNTIL(total(number) >= n);
    settle();
}
/* Another process sends the signal, or queues it, once fork has returned
 * here: until then fork blocks every signal, so the child's SIGCHLD would be
 * kept, and wake another thread to take the shared signals. */
static void from(pid_t to, int number, int queued) {
    int go[2];
    pipe(go);
    pid_t pid = fork();
    if (!pid) {
        char byte;
        close(go[1]);
        read(go[0], &byte, 1);
        if (queued) sigqueue(to, number, (union sigval){7});
        else kill(to, number);
        _exit(0);
    }
    close(go[0]);
    write(go[1], "x", 1);
    close(go[1]);
    waitpid(pid, NULL, 0);
}
static int pending(int number) {
    uint64_t set = 0;
    syscall(SYS_rt_sigpending, &set, 8L);
    return (int)(set >> (number - 1) & 1);
}
static void one(int n) {
    target = getpid();
    handle(SIGUSR1, SA_RESTART);
    handle(SIGUSR2, SA_RESTART);
    switch (n) {
    case 0: /* a thread sends to its own process */
        start(2);
        s->job[1] = 1;
        expect(SIGUSR1, 1);
        show("own kill", SIGUSR1);
        break;
    case 1: /* another process does */
        start(2);
        from(target, SIGUSR1, 0);
        expect(SIGUSR1, 1);
        show("kill", SIGUSR1);
        from(target, SIGUSR2, 1);
        expect(SIGUSR2, 1);
        show("sigqueue", SIGUSR2);
        break;
    case 2: { /* SIGIO for what a thread wrote */
        handle(SIGIO, SA_RESTART);
        socketpair(AF_UNIX, SOCK_STREAM, 0, pair);
        fcntl(pair[0], F_SETOWN, getpid());
        fcntl(pair[0], F_SETFL, O_ASYNC);
        start(2);
        s->job[2] = 2;
        expect(SIGIO, 1);
        show("SIGIO", SIGIO);
        break;
    }
    case 3: /* ITIMER_REAL */
        handle(SIGALRM, SA_RESTART);
        start(2);
        setitimer(ITIMER_REAL, &(struct itimerval){{0, 0}, {0, 100000}}, NULL);
        expect(SIGALRM, 1);
        show("ITIMER_REAL", SIGALRM);
        break;
    case 4: /* the leader blocks it: from the one last chosen on */
        start(3);
        mask(SIG_BLOCK, SIGUSR1);
        from(target, SIGUSR1, 0);
        expect(SIGUSR1, 1);
        from(target, SIGUSR1, 0);
        expect(SIGUSR1, 2);
        show("leader blocks", SIGUSR1);
        tell(1, 3);
        from(target, SIGUSR1, 0);
        expect(SIGUSR1, 3);
        show("thread 1 too", SIGUSR1);
        tell(1, 4);
        from(target, SIGUSR1, 0);
        expect(SIGUSR1, 4);
        show("thread 1 no more", SIGUSR1);
        tell(2, 3);
        tell(1, 3);
        from(target, SIGUSR1, 0);
        expect(SIGUSR1, 5);
        show("only thread 3", SIGUSR1);
        break;
    case 5: /* all block it, then one does not */
        start(3);
        mask(SIG_BLOCK, SIGUSR1);
        for (int i = 1; i <= 3; i++) tell(i, 3);
        from(target, SIGUSR1, 0);
        settle();
        show("all block", SIGUSR1);
        printf("pending %d\n", pending(SIGUSR1));
        tell(2, 4);
        expect(SIGUSR1, 1);
        show("thread 2 unblocks", SIGUSR1);
        printf("pending %d\n", pending(SIGUSR1));
        break;
    case 6: /* a thread's ID names that thread first */
        start(3);
        from(s->tids[2], SIGUSR1, 0);
        expect(SIGUSR1, 1);
        show("kill of a thread's ID", SIGUSR1);
        break;
    case 7: /* SIGCHLD goes to the thread that forked, or the first left */
        handle(SIGCHLD, SA_NOCLDSTOP | SA_RESTART);
        start(3);
        tell(2, 6);
        expect(SIGCHLD, 1);
        show("SIGCHLD", SIGCHLD);
        s->job[3] = 7;
        expect(SIGCHLD, 2);
        show("SIGCHLD of an exited thread's child", SIGCHLD);
        break;
    case 8: /* a thread in a vfork has the first one pending, and sleeps on */
        start(2);
        mask(SIG_BLOCK, SIGUSR1);
        mask(SIG_BLOCK, SIGUSR2);
        s->job[1] = 5;
        UNTIL(s->vforked && state(s->tids[1]) != 'R');
        from(target, SIGUSR1, 0);
        from(target, SIGUSR2, 0);
        UNTIL(total(SIGUSR1) && total(SIGUSR2));
        settle();
        show("vfork, first", SIGUSR1);
        show("vfork, second", SIGUSR2);
        break;
    case 9: { /* the leader in a ptrace stop */
        start(2);
        prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0);
        pid_t pid = fork();
        if (!pid) {
            int status;
            if (!ptrace(PTRACE_SEIZE, target, 0, 0) && !ptrace(PTRACE_INTERRUPT, target, 0, 0))
                waitpid(target, &status, __WALL);
            kill(target, SIGUSR1);
            UNTIL(total(SIGUSR1));
            ptrace(PTRACE_DETACH, target, 0, 0);
            _exit(0);
        }
        waitpid(pid, NULL, 0);
        show("leader traced and stopped", SIGUSR1);
        break;
    }
    case 10: /* an ignored signal is dropped as it is sent */
        signal(SIGUSR1, SIG_IGN);
        start(2);
        tell(1, 3);
        kill(getpid(), SIGUSR1);
        kill(getpid(), SIGWINCH);
        syscall(SYS_tgkill, getpid(), s->tids[2], SIGUSR1);
        handle(SIGUSR1, SA_RESTART);
        handle(SIGWINCH, SA_RESTART);
        printf("ignored: pending %d %d\n", pending(SIGUSR1), pending(SIGWINCH));
        settle();
        show("ignored", SIGUSR1);
        show("SIGWINCH", SIGWINCH);
        /* but not one its thread blocks */
        signal(SIGUSR1, SIG_IGN);
        syscall(SYS_tgkill, getpid(), s->tids[1], SIGUSR1);
        handle(SIGUSR1, SA_RESTART);
        tell(1, 4);
        expect(SIGUSR1, 1);
        show("ignored and blocked", SIGUSR1);
        signal(SIGUSR2, SIG_IGN);
        tell(1, 9);
        tell(2, 9);
        mask(SIG_BLOCK, SIGUSR2);
        kill(getpid(), SIGUSR2);
        printf("pending %d\n", pending(SIGUSR2));
        handle(SIGUSR2, SA_RESTART);
        mask(SIG_UNBLOCK, SIGUSR2);
        show("handled since", SIGUSR2);
        break;
    case 11: { /* SIGPROF goes to the thread that runs, as the others sleep */
        char byte;
        handle(SIGPROF, SA_RESTART);
        pipe(pair);
        start(1);
        setitimer(ITIMER_PROF, &(struct itimerval){{0, 0}, {0, 100000}}, NULL);
        s->job[1] = 8;
        read(pair[0], &byte, 1);
        show("ITIMER_PROF", SIGPROF);
        break;
    }
    case 12: { /* a thread that waits for it takes it */
        sigset_t set;
        sigemptyset(&set);
        sigaddset(&set, SIGUSR1);
        mask(SIG_BLOCK, SIGUSR1);
        start(1);
        tell(1, 3);
        from(target, SIGUSR1, 0);
        printf("sigtimedwait %d\n", sigtimedwait(&set, NULL, &(struct timespec){10, 0}));
        show("sigtimedwait", SIGUSR1);
        break;
    }
    case 13: /* a real-time signal */
        handle(SIGRTMIN + 3, SA_RESTART);
        start(2);
        mask(SIG_BLOCK, SIGRTMIN + 3);
        from(target, SIGRTMIN + 3, 1);
        expect(SIGRTMIN + 3, 1);
        from(target, SIGRTMIN + 3, 1);
        expect(SIGRTMIN + 3, 2);
        show("real-time", SIGRTMIN + 3);
        break;
    }
}
int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    for (int n = 0; n < 14; n++) {
        s = mmap(NULL, sizeof *s, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        pid_t pid = fork();
        if (!pid) {
            one(n);
            fflush(stdout);
            _exit(0);
        }
        int status;
        waitpid(pid, &status, 0);
        if (!WIFEXITED(status)) printf("case %d: status %x\n", n, status);
        munmap(s, sizeof *s);
    }
    return 0;
}
