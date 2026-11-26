/* What execve keeps of the signals pending and of their actions: the
 * thread's own pending signals and the process's (`de_thread` frees only the
 * other threads, with theirs), and the actions as `flush_signal_handlers`
 * leaves them, which `CLONE_CLEAR_SIGHAND` does too. The signals each new
 * image then takes are listed by number, not in the order they come. */
#define _GNU_SOURCE
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define RT1 (SIGRTMIN + 1)
#define RT2 (SIGRTMIN + 2)
#define RT3 (SIGRTMIN + 3)
#define CLONE_CLEAR_SIGHAND 0x100000000ULL

static const char *self;
static volatile int numbers_taken[16], values_taken[16], codes_taken[16], taken;

static void ms(int n) { nanosleep(&(struct timespec){0, n * 1000000L}, NULL); }
static void mask(int how, const int *numbers) {
    sigset_t set;
    sigemptyset(&set);
    for (; *numbers; numbers++) sigaddset(&set, *numbers);
    sigprocmask(how, &set, NULL);
}
static void pending(const char *name) {
    uint64_t set = 0;
    syscall(SYS_rt_sigpending, &set, 8L);
    printf("%s pending:", name);
    for (int n = 1; n <= 64; n++)
        if (set >> (n - 1) & 1) printf(" %d", n);
    printf("\n");
}
struct kaction {
    unsigned long handler, flags, restorer;
    uint64_t mask;
};
/* The kernel's own record of an action, which libc does not rewrite. */
static void action(const char *name, int number) {
    struct kaction old = {0};
    syscall(SYS_rt_sigaction, number, NULL, &old, 8L);
    printf("%s action %d: handler %s flags %lx mask %llx\n", name, number,
           old.handler == 0 ? "default" : old.handler == 1 ? "ignored" : "handled", old.flags,
           (unsigned long long)old.mask);
}
static void took(int number, siginfo_t *info, void *context) {
    (void)context;
    int at = taken++;
    numbers_taken[at] = number;
    codes_taken[at] = info->si_code;
    values_taken[at] = info->si_value.sival_int;
}
static void handle(int number) {
    struct sigaction a = {.sa_sigaction = took, .sa_flags = SA_SIGINFO | SA_RESTART};
    sigaction(number, &a, NULL);
}
/* SIGINT ignored, with SA_RESTART and SIGTERM in its mask, and SIGHUP handled. */
static void set_actions(void) {
    struct kaction ignore = {.handler = 1, .flags = 0x10000000, .mask = 1ull << (SIGTERM - 1)};
    syscall(SYS_rt_sigaction, SIGINT, &ignore, NULL, 8L);
    handle(SIGHUP);
}
static void queue(pid_t to, int number, int value) {
    syscall(SYS_rt_sigqueueinfo, to, number,
            &(siginfo_t){.si_signo = number, .si_code = SI_QUEUE, .si_value.sival_int = value});
}
static void tqueue(pid_t tid, int number, int value) {
    syscall(SYS_rt_tgsigqueueinfo, getpid(), tid, number,
            &(siginfo_t){.si_signo = number, .si_code = SI_QUEUE, .si_value.sival_int = value});
}
/* The new image, as `#name`. */
static void run(const char *name) {
    char arg[32];
    snprintf(arg, sizeof arg, "#%s", name);
    fflush(stdout);
    execl(self, self, arg, self, (char *)NULL);
    perror("execl");
    _exit(1);
}

/* In the new image: what is pending, the actions, and what then comes. */
static void after(const char *name) {
    pending(name);
    action(name, SIGINT);
    action(name, SIGHUP);
    int numbers[] = {SIGUSR1, SIGUSR2, SIGCHLD, RT1, RT2, RT3, 0};
    for (int *n = numbers; *n; n++) handle(*n);
    int all[] = {SIGUSR1, SIGUSR2, SIGCHLD, SIGURG, RT1, RT2, RT3, 0};
    mask(SIG_UNBLOCK, all);
    /* By number, then value. */
    for (int i = 0; i < taken; i++)
        for (int j = i + 1; j < taken; j++)
            if (numbers_taken[j] < numbers_taken[i] ||
                (numbers_taken[j] == numbers_taken[i] && values_taken[j] < values_taken[i])) {
                int n = numbers_taken[i], v = values_taken[i], c = codes_taken[i];
                numbers_taken[i] = numbers_taken[j], values_taken[i] = values_taken[j];
                codes_taken[i] = codes_taken[j];
                numbers_taken[j] = n, values_taken[j] = v, codes_taken[j] = c;
            }
    printf("%s took:", name);
    for (int i = 0; i < taken; i++)
        printf(" %d/%d/%d", numbers_taken[i], codes_taken[i], values_taken[i]);
    printf("\n");
    pending(name);
    while (wait(NULL) > 0) {}
    exit(0);
}

/* One thread: what it blocks stays pending, its own and the process's, and
 * an ignored signal too, which it then drops as it unblocks it. */
static void single(void) {
    int numbers[] = {SIGUSR1, SIGUSR2, SIGCHLD, SIGURG, SIGHUP, RT1, RT2, 0};
    mask(SIG_BLOCK, numbers);
    set_actions();
    signal(SIGURG, SIG_IGN);
    syscall(SYS_tgkill, getpid(), gettid(), SIGUSR1);
    kill(getpid(), SIGUSR2);
    queue(getpid(), RT1, 11);
    queue(getpid(), RT1, 12);
    tqueue(gettid(), RT2, 21);
    kill(getpid(), SIGURG);
    kill(getpid(), SIGHUP);
    pid_t child = fork();
    if (!child) _exit(3);
    siginfo_t info;
    waitid(P_PID, child, &info, WEXITED | WNOWAIT);
    action("single before", SIGINT);
    pending("single before");
    run("single");
}

/* With threads: the leader's or another thread's own pending signals go
 * with that thread, as the process's and the execing thread's stay. */
static volatile pid_t tids[3];
static volatile int stage;
static void *worker(void *arg) {
    long i = (long)arg;
    tids[i] = gettid();
    while (stage != (int)i) ms(1);
    tqueue(gettid(), RT3, 30 + (int)i);
    run("thread");
    return NULL;
}
static void threads(int execer) {
    int numbers[] = {SIGUSR1, SIGUSR2, RT1, RT2, RT3, 0};
    mask(SIG_BLOCK, numbers);
    pthread_t made;
    for (long i = 1; i <= 2; i++) {
        pthread_create(&made, NULL, worker, (void *)i);
        while (!tids[i]) ms(1);
    }
    syscall(SYS_tgkill, getpid(), gettid(), SIGUSR1);
    tqueue(tids[2], RT2, 22);
    syscall(SYS_tgkill, getpid(), tids[2], SIGUSR2);
    queue(getpid(), RT1, 13);
    if (execer == 0) {
        tqueue(gettid(), RT3, 30);
        run("leader");
    }
    stage = execer;
    for (;;) pause();
}

/* CLONE_CLEAR_SIGHAND: the child's actions, as an exec leaves them. */
static void clear_sighand(void) {
    set_actions();
    struct {
        uint64_t flags, pidfd, child_tid, parent_tid, exit_signal, stack, stack_size, tls;
    } args = {.flags = CLONE_CLEAR_SIGHAND, .exit_signal = SIGCHLD};
    long pid = syscall(SYS_clone3, &args, sizeof args);
    if (pid == 0) {
        action("clear-sighand child", SIGINT);
        action("clear-sighand child", SIGHUP);
        fflush(stdout);
        _exit(0);
    }
    waitpid((pid_t)pid, NULL, 0);
    action("clear-sighand parent", SIGINT);
    action("clear-sighand parent", SIGHUP);
    exit(0);
}

int main(int argc, char **argv) {
    self = argc > 2 ? argv[2] : argv[0];
    setvbuf(stdout, NULL, _IOLBF, 0);
    const char *mode = argc > 1 ? argv[1] : "";
    if (mode[0] == '#') after(mode + 1);
    if (!strcmp(mode, "@single")) single();
    if (!strcmp(mode, "@leader")) threads(0);
    if (!strcmp(mode, "@thread")) threads(1);
    if (!strcmp(mode, "@clear-sighand")) clear_sighand();
    const char *cases[] = {"@single", "@leader", "@thread", "@clear-sighand"};
    for (int i = 0; i < 4; i++) {
        pid_t pid = fork();
        if (!pid) {
            execl(self, self, cases[i], self, (char *)NULL);
            _exit(1);
        }
        int status;
        waitpid(pid, &status, 0);
        printf("%s: status %x\n", cases[i] + 1, status);
    }
    return 0;
}
