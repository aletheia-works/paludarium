/* signalfd, compared with Linux: the calls' errors, the records a read
   gives, poll, select and epoll on the file, the thread whose signals it
   reads, a fork's, and the waits of a blocking read.

   Outputs are booleans, counts, signal numbers and errno values, never
   process IDs or descriptors. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/select.h>
#include <sys/signalfd.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

static void say(const char *format, ...) {
    va_list list;
    va_start(list, format);
    vprintf(format, list);
    va_end(list);
    putchar('\n');
    fflush(stdout);
}

/* The result of a call that fails with errno: the value, or -errno. */
#define TRY(call) ({ long try_result = (call); try_result < 0 ? -errno : try_result; })

static sigset_t set_of(int count, ...) {
    sigset_t set;
    sigemptyset(&set);
    va_list list;
    va_start(list, count);
    for (int i = 0; i < count; i++) sigaddset(&set, va_arg(list, int));
    va_end(list);
    return set;
}

static void block(sigset_t set) { sigprocmask(SIG_BLOCK, &set, NULL); }

/* The raw call, which takes any size of mask. */
static long raw_signalfd4(int fd, const void *mask, size_t size, int flags) {
    long result = syscall(SYS_signalfd4, fd, mask, size, flags);
    return result < 0 ? -errno : result;
}

static int readable(int fd, int timeout) {
    struct pollfd p = {fd, POLLIN, 0};
    int n = poll(&p, 1, timeout);
    return n < 0 ? -errno : n == 1 ? p.revents : 0;
}

/* Reads up to `count` records and prints each one's fields that do not
   name a process. */
static int records(int fd, int count, pid_t expected) {
    struct signalfd_siginfo info[4];
    ssize_t n = read(fd, info, sizeof info[0] * count);
    if (n < 0) {
        say("read %d", -errno);
        return -errno;
    }
    say("read %zd bytes", n);
    for (int i = 0; i < n / (ssize_t)sizeof info[0]; i++) {
        struct signalfd_siginfo *s = &info[i];
        say("  signo %u errno %d code %d pid-match %d uid-match %d status %d int %d tid %u overrun %u",
            s->ssi_signo, s->ssi_errno, s->ssi_code, s->ssi_pid == (uint32_t)expected,
            s->ssi_uid == getuid(), s->ssi_status, s->ssi_int, s->ssi_tid, s->ssi_overrun);
    }
    return (int)n;
}

static int case_calls(void) {
    sigset_t usr1 = set_of(1, SIGUSR1);
    say("size 4 %ld", raw_signalfd4(-1, &usr1, 4, 0));
    say("size 16 %ld", raw_signalfd4(-1, &usr1, 16, 0));
    say("fault %ld", raw_signalfd4(-1, NULL, 8, 0));
    say("flags %ld", raw_signalfd4(-1, &usr1, 8, 1));
    say("bad fd %ld", raw_signalfd4(999, &usr1, 8, 0));
    int other = open("/dev/null", O_RDONLY);
    say("other file %ld", raw_signalfd4(other, &usr1, 8, 0));
    say("fd -2 %ld", raw_signalfd4(-2, &usr1, 8, 0));
    close(other);

    int fd = signalfd(-1, &usr1, SFD_NONBLOCK | SFD_CLOEXEC);
    say("created %d", fd >= 0);
    say("flags nonblock %d cloexec %d", (fcntl(fd, F_GETFL) & O_NONBLOCK) != 0,
        (fcntl(fd, F_GETFD) & FD_CLOEXEC) != 0);
    say("access %d", fcntl(fd, F_GETFL) & O_ACCMODE);
    char buffer[256];
    say("empty read %ld", TRY(read(fd, buffer, sizeof buffer)));
    say("short read %ld", TRY(read(fd, buffer, 127)));
    say("zero read %ld", TRY(read(fd, buffer, 0)));
    say("write %ld", TRY(write(fd, buffer, 128)));
    say("lseek %ld", TRY(lseek(fd, 0, SEEK_SET)));
    say("pread %ld", TRY(pread(fd, buffer, 128, 0)));
    say("pwrite %ld", TRY(pwrite(fd, buffer, 128, 0)));
    say("lseek end %ld", TRY(lseek(fd, 5, SEEK_END)));
    struct stat st;
    fstat(fd, &st);
    say("mode %o", st.st_mode);
    char path[64], link[64];
    snprintf(path, sizeof path, "/proc/self/fd/%d", fd);
    ssize_t length = readlink(path, link, sizeof link - 1);
    link[length < 0 ? 0 : length] = 0;
    say("link %s", link);
    /* Opening the link is EACCES for a user other than root, which Linux
       checks before the anonymous inode's ENXIO; paludarium opens it as for
       root (see the features page), so the case does not open it. */
    say("poll empty %d", readable(fd, 0));

    /* A pending signal that is not blocked is delivered, not read; a
       blocked one waits for the file. */
    block(usr1);
    kill(getpid(), SIGUSR1);
    say("poll pending %d", readable(fd, 0));
    records(fd, 2, getpid());
    say("poll taken %d", readable(fd, 0));
    sigset_t pending;
    sigpending(&pending);
    say("still pending %d", sigismember(&pending, SIGUSR1));

    /* A new mask for the same file, which SIGKILL and SIGSTOP leave. */
    sigset_t next = set_of(4, SIGUSR2, SIGRTMIN + 1, SIGKILL, SIGSTOP);
    block(next);
    say("same fd %d", signalfd(fd, &next, 0) == fd);
    kill(getpid(), SIGUSR1);
    say("poll other %d", readable(fd, 0));
    union sigval value = {.sival_int = 7};
    sigqueue(getpid(), SIGRTMIN + 1, value);
    value.sival_int = 8;
    sigqueue(getpid(), SIGRTMIN + 1, value);
    kill(getpid(), SIGUSR2);
    records(fd, 4, getpid());
    sigpending(&pending);
    say("usr1 left %d", sigismember(&pending, SIGUSR1));
    /* SIGUSR1 is not in the mask, so another file takes it. */
    int second = signalfd(-1, &usr1, SFD_NONBLOCK);
    records(second, 1, getpid());
    close(second);
    close(fd);
    return 0;
}

static int case_child(void) {
    sigset_t chld = set_of(1, SIGCHLD);
    block(chld);
    int fd = signalfd(-1, &chld, 0);
    pid_t child = fork();
    if (child == 0) _exit(3);
    say("poll %d", readable(fd, 5000));
    records(fd, 1, child);
    int status;
    say("reaped %d status %d", waitpid(child, &status, 0) == child, WEXITSTATUS(status));

    /* A blocking read waits for the child. */
    child = fork();
    if (child == 0) {
        usleep(50000);
        _exit(4);
    }
    records(fd, 1, child);
    waitpid(child, &status, 0);

    /* Killed by a signal, and seen through select. */
    child = fork();
    if (child == 0) {
        pause();
        _exit(0);
    }
    kill(child, SIGTERM);
    fd_set in;
    FD_ZERO(&in);
    FD_SET(fd, &in);
    struct timeval limit = {5, 0};
    say("select %d set %d", select(fd + 1, &in, NULL, NULL, &limit), FD_ISSET(fd, &in) != 0);
    records(fd, 1, child);
    waitpid(child, &status, 0);
    close(fd);
    return 0;
}

static int case_epoll(void) {
    sigset_t set = set_of(2, SIGUSR1, SIGUSR2);
    block(set);
    int fd = signalfd(-1, &set, SFD_NONBLOCK);
    int level = epoll_create1(0), edge = epoll_create1(0);
    struct epoll_event event = {.events = EPOLLIN, .data.u32 = 1};
    epoll_ctl(level, EPOLL_CTL_ADD, fd, &event);
    event.events = EPOLLIN | EPOLLET;
    epoll_ctl(edge, EPOLL_CTL_ADD, fd, &event);
    struct epoll_event out[2];
    say("level empty %d", epoll_wait(level, out, 2, 0));
    say("edge empty %d", epoll_wait(edge, out, 2, 0));
    kill(getpid(), SIGUSR1);
    say("level %d events %x", epoll_wait(level, out, 2, 0), out[0].events);
    say("level again %d", epoll_wait(level, out, 2, 0));
    say("edge %d", epoll_wait(edge, out, 2, 0));
    say("edge again %d", epoll_wait(edge, out, 2, 0));
    kill(getpid(), SIGUSR2);
    say("edge new signal %d", epoll_wait(edge, out, 2, 0));
    records(fd, 4, getpid());
    say("level taken %d", epoll_wait(level, out, 2, 0));

    /* A signal from a child wakes a wait. */
    pid_t child = fork();
    if (child == 0) {
        usleep(50000);
        kill(getppid(), SIGUSR2);
        _exit(0);
    }
    say("level woken %d", epoll_wait(level, out, 2, 5000));
    records(fd, 1, child);
    waitpid(child, NULL, 0);
    return 0;
}

/* Edge-triggered epoll gets an edge for each signal queued to the process,
   as Linux's signalfd_notify wakes the file: one of the file's again, a
   real-time signal while one of its number waits, or another signal while
   one of the file's waits; and for a new mask. A signal already pending, or
   one ignored, queues nothing. */
static int case_edges(void) {
    int rt = SIGRTMIN + 1;
    sigset_t set = set_of(2, SIGUSR1, rt);
    block(set_of(4, SIGUSR1, SIGUSR2, rt, SIGCHLD));
    int fd = signalfd(-1, &set, SFD_NONBLOCK);
    int edge = epoll_create1(0);
    struct epoll_event event = {.events = EPOLLIN | EPOLLET, .data.u32 = 1};
    epoll_ctl(edge, EPOLL_CTL_ADD, fd, &event);
    struct epoll_event out[2];
    say("empty %d", epoll_wait(edge, out, 2, 0));
    kill(getpid(), SIGUSR2);
    say("other signal alone %d", epoll_wait(edge, out, 2, 0));
    kill(getpid(), SIGUSR1);
    say("signal %d", epoll_wait(edge, out, 2, 0));
    say("again %d", epoll_wait(edge, out, 2, 0));
    kill(getpid(), SIGUSR1);
    say("already pending %d", epoll_wait(edge, out, 2, 0));
    kill(getpid(), SIGUSR2);
    say("already pending other %d", epoll_wait(edge, out, 2, 0));
    signal(SIGURG, SIG_DFL);
    kill(getpid(), SIGURG);
    say("ignored %d", epoll_wait(edge, out, 2, 0));
    signal(SIGPIPE, SIG_IGN);
    kill(getpid(), SIGPIPE);
    say("ignored by handler %d", epoll_wait(edge, out, 2, 0));
    kill(getpid(), SIGCHLD);
    say("blocked default-ignored %d", epoll_wait(edge, out, 2, 0));
    sigqueue(getpid(), rt, (union sigval){0});
    say("real-time %d", epoll_wait(edge, out, 2, 0));
    sigqueue(getpid(), rt, (union sigval){0});
    say("real-time again %d", epoll_wait(edge, out, 2, 0));
    say("quiet %d", epoll_wait(edge, out, 2, 0));
    say("new mask %d", TRY(signalfd(fd, &set, 0)) == fd);
    say("after new mask %d", epoll_wait(edge, out, 2, 0));
    /* The thread's own signal counts as the process's does. */
    syscall(SYS_tgkill, getpid(), gettid(), rt);
    say("thread signal %d", epoll_wait(edge, out, 2, 0));
    struct signalfd_siginfo info[8];
    say("read %ld", TRY(read(fd, info, sizeof info)) / (long)sizeof *info);
    say("taken %d", epoll_wait(edge, out, 2, 0));
    return 0;
}

static int thread_fd;
static pid_t thread_id;
static volatile int thread_go;

static void *thread_main(void *unused) {
    (void)unused;
    thread_id = (pid_t)syscall(SYS_gettid);
    __atomic_store_n(&thread_go, 1, __ATOMIC_SEQ_CST);
    while (__atomic_load_n(&thread_go, __ATOMIC_SEQ_CST) != 2) usleep(1000);
    say("thread poll %d", readable(thread_fd, 0));
    records(thread_fd, 2, getpid());
    say("thread poll taken %d", readable(thread_fd, 0));
    return NULL;
}

static int case_threads(void) {
    sigset_t set = set_of(2, SIGUSR1, SIGUSR2);
    block(set);
    thread_fd = signalfd(-1, &set, SFD_NONBLOCK);
    pthread_t thread;
    pthread_create(&thread, NULL, thread_main, NULL);
    while (!__atomic_load_n(&thread_go, __ATOMIC_SEQ_CST)) usleep(1000);
    /* A thread's own signal is its file's alone; the process's is every
       thread's. */
    syscall(SYS_tgkill, getpid(), thread_id, SIGUSR1);
    usleep(20000);
    say("main poll %d", readable(thread_fd, 0));
    say("main read %d", records(thread_fd, 1, getpid()));
    kill(getpid(), SIGUSR2);
    __atomic_store_n(&thread_go, 2, __ATOMIC_SEQ_CST);
    pthread_join(thread, NULL);
    say("main poll after %d", readable(thread_fd, 0));
    return 0;
}

static int case_fork(void) {
    sigset_t set = set_of(2, SIGUSR1, SIGUSR2);
    block(set);
    int fd = signalfd(-1, &set, SFD_NONBLOCK);
    kill(getpid(), SIGUSR1);
    pid_t child = fork();
    if (child == 0) {
        /* A child starts with nothing pending; the inherited file reads
           the child's own signals. */
        say("child poll %d", readable(fd, 0));
        say("child empty %d", records(fd, 1, getpid()));
        kill(getpid(), SIGUSR2);
        records(fd, 2, getpid());
        _exit(0);
    }
    waitpid(child, NULL, 0);
    records(fd, 2, getpid());
    return 0;
}

static volatile int alarms;
static void on_alarm(int number) {
    (void)number;
    alarms++;
    if (alarms == 2) kill(getpid(), SIGUSR2);
}

static int case_interrupt(void) {
    sigset_t set = set_of(1, SIGUSR2);
    block(set);
    int fd = signalfd(-1, &set, 0);
    struct sigaction action = {.sa_handler = on_alarm};
    sigaction(SIGALRM, &action, NULL);
    struct itimerval once = {{0, 0}, {0, 30000}};
    setitimer(ITIMER_REAL, &once, NULL);
    /* Without SA_RESTART, the handler ends the read. */
    records(fd, 1, getpid());
    say("alarms %d", alarms);
    /* With it, the read goes on and takes the signal the handler sends. */
    action.sa_flags = SA_RESTART;
    sigaction(SIGALRM, &action, NULL);
    setitimer(ITIMER_REAL, &once, NULL);
    records(fd, 1, getpid());
    say("alarms %d", alarms);
    /* A signal of the mask that is not blocked is delivered instead. */
    signal(SIGUSR2, SIG_IGN);
    sigprocmask(SIG_UNBLOCK, &set, NULL);
    kill(getpid(), SIGUSR2);
    say("poll ignored %d", readable(fd, 0));
    return 0;
}

int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "";
    alarm(20);
    if (!strcmp(mode, "signalfd-calls")) return case_calls();
    if (!strcmp(mode, "signalfd-child")) return case_child();
    if (!strcmp(mode, "signalfd-epoll")) return case_epoll();
    if (!strcmp(mode, "signalfd-threads")) return case_threads();
    if (!strcmp(mode, "signalfd-fork")) return case_fork();
    if (!strcmp(mode, "signalfd-interrupt")) return case_interrupt();
    if (!strcmp(mode, "signalfd-edges")) return case_edges();
    return 2;
}
