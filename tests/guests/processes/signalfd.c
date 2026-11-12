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
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/file.h>
#include <sys/select.h>
#include <sys/signalfd.h>
#include <sys/sysmacros.h>
#include <sys/timerfd.h>
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

/* Waits, its signals blocked, until a byte comes: a wait without a
   timeout, which the harness's virtual clock does not run through. */
static int edge_thread_pipe[2];
static void *edge_thread(void *unused) {
    (void)unused;
    sigset_t all;
    sigfillset(&all);
    pthread_sigmask(SIG_BLOCK, &all, NULL);
    char byte;
    read(edge_thread_pipe[0], &byte, 1);
    return NULL;
}

/* Edge-triggered epoll gets an edge for each signal queued to the process,
   as Linux's signalfd_notify wakes the file: one of the file's again, a
   real-time signal while one of its number waits, or another signal, even
   another thread's, while one of the file's waits; and for a new mask. A signal already pending, or
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
    /* Another thread's signal wakes the file too, and the waiter sees its
       own pending signals again. */
    pthread_t other;
    pipe(edge_thread_pipe);
    pthread_create(&other, NULL, edge_thread, NULL);
    usleep(50000);
    pthread_kill(other, SIGUSR2);
    say("other thread's signal %d", epoll_wait(edge, out, 2, 1000));
    say("other thread quiet %d", epoll_wait(edge, out, 2, 200));
    write(edge_thread_pipe[1], "x", 1);
    pthread_join(other, NULL);
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

/* /proc/self/fdinfo of the other files whose kinds add lines: an eventfd's
 * count, an epoll's targets, a signalfd's mask, a timerfd's settings, and
 * the flock and record locks set through a description. Numbers the system picks
 * (eventfd-id, inodes, devices, process IDs) are compared, not printed. */
static FILE *fdinfo(int fd) {
    char path[64];
    snprintf(path, sizeof path, "/proc/self/fdinfo/%d", fd);
    return fopen(path, "r");
}
/* The lines after the four every descriptor has. */
static int by_tfd(const void *a, const void *b) {
    return atoi(*(char *const *)a + 6) - atoi(*(char *const *)b + 6);
}
static void show_extra(const char *label, int fd) {
    FILE *f = fdinfo(fd);
    char line[256];
    int n = 0;
    /* An epoll's files, which Linux lists by their addresses: by descriptor. */
    char *targets[16];
    int count = 0;
    printf("%s:\n", label);
    while (f && fgets(line, sizeof line, f)) {
        if (n++ < 4) continue;
        unsigned id;
        if (sscanf(line, "eventfd-id: %u", &id) == 1) {
            printf("  eventfd-id number\n");
            continue;
        }
        int tfd;
        unsigned events, sdev;
        unsigned long long data, ino;
        long long pos;
        if (sscanf(line, "tfd: %d events: %x data: %llx pos:%lli ino:%llx sdev:%x", &tfd, &events, &data, &pos, &ino, &sdev) == 6) {
            struct stat st;
            fstat(tfd, &st);
            char *shown = malloc(160);
            snprintf(shown, 160, "  tfd=%d events=%#x data=%#llx pos=%lld ino=%s sdev=%s\n", tfd, events, data, pos,
                     ino == st.st_ino ? "fstat" : "other",
                     sdev == (major(st.st_dev) << 20 | minor(st.st_dev)) ? "fstat" : "other");
            if (count < 16) targets[count++] = shown;
            continue;
        }
        unsigned long long sec, nsec;
        if (sscanf(line, "it_value: (%llu, %llu)", &sec, &nsec) == 2) {
            printf("  it_value sec=%llu zero=%d\n", sec, sec == 0 && nsec == 0);
            continue;
        }
        int lid, pid;
        char what[16], adv[16], kind[16], end[32];
        unsigned maj, min;
        unsigned long lino;
        long long start;
        if (sscanf(line, "lock:\t%d: %15s %15s %15s %d %x:%x:%lu %lld %31s", &lid, what, adv, kind, &pid, &maj, &min, &lino, &start, end) == 10) {
            struct stat st;
            fstat(fd, &st);
            printf("  lock %d %s %s %s pid=%s dev=%s ino=%s %lld %s\n", lid, what, adv, kind,
                   pid == getpid() ? "own" : pid == -1 ? "-1" : "other",
                   maj == major(st.st_dev) && min == minor(st.st_dev) ? "fstat" : "other",
                   lino == st.st_ino ? "fstat" : "other", start, end);
            continue;
        }
        printf("  %s", line);
    }
    if (f) fclose(f);
    qsort(targets, count, sizeof targets[0], by_tfd);
    for (int i = 0; i < count; i++) {
        fputs(targets[i], stdout);
        free(targets[i]);
    }
}
static int lock_range(int fd, int cmd, short type, off_t start, off_t len) {
    struct flock l = {.l_type = type, .l_whence = SEEK_SET, .l_start = start, .l_len = len};
    return TRY(fcntl(fd, cmd, &l));
}
static int case_fdinfo(void) {
    int counter = eventfd(5, EFD_SEMAPHORE | EFD_NONBLOCK);
    show_extra("eventfd", counter);
    uint64_t more = 0x123456789;
    say("write=%ld", (long)write(counter, &more, sizeof more));
    show_extra("eventfd-more", counter);
    int plain = eventfd(0, 0);
    show_extra("eventfd-plain", plain);

    sigset_t mask = set_of(3, SIGUSR1, SIGRTMIN + 1, SIGKILL);
    int sig = signalfd(-1, &mask, SFD_NONBLOCK);
    show_extra("signalfd", sig);

    int timer = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    show_extra("timerfd", timer);
    struct itimerspec spec = {.it_interval = {2, 500}, .it_value = {0, 1}};
    say("settime=%d", TRY(timerfd_settime(timer, 0, &spec, NULL)));
    usleep(20000);
    show_extra("timerfd-expired", timer);
    struct timespec now;
    clock_gettime(CLOCK_REALTIME, &now);
    int real = timerfd_create(CLOCK_REALTIME, 0);
    struct itimerspec at = {.it_interval = {0, 0}, .it_value = {now.tv_sec + 1000, 0}};
    say("settime abs=%d", TRY(timerfd_settime(real, TFD_TIMER_ABSTIME | TFD_TIMER_CANCEL_ON_SET, &at, NULL)));
    FILE *f = fdinfo(real);
    char line[256];
    while (f && fgets(line, sizeof line, f)) {
        unsigned long long sec, nsec;
        if (sscanf(line, "it_value: (%llu, %llu)", &sec, &nsec) == 2)
            printf("  it_value near=%d\n", sec >= 998 && sec <= 1000);
        else if (!strncmp(line, "clockid", 7) || !strncmp(line, "settime", 7) || !strncmp(line, "ticks", 5) || !strncmp(line, "it_interval", 11))
            printf("  %s", line);
    }
    if (f) fclose(f);

    int ep = epoll_create1(0);
    int pipes[2];
    if (pipe(pipes)) return 92;
    struct epoll_event ev = {.events = EPOLLIN | EPOLLET, .data.u64 = 0xfeedface12345678ULL};
    say("add=%d", TRY(epoll_ctl(ep, EPOLL_CTL_ADD, counter, &ev)));
    ev.events = EPOLLOUT;
    ev.data.u64 = 7;
    say("add=%d", TRY(epoll_ctl(ep, EPOLL_CTL_ADD, pipes[1], &ev)));
    show_extra("epoll", ep);
    ev.events = EPOLLOUT | EPOLLONESHOT;
    say("mod=%d", TRY(epoll_ctl(ep, EPOLL_CTL_MOD, pipes[1], &ev)));
    say("del=%d", TRY(epoll_ctl(ep, EPOLL_CTL_DEL, counter, NULL)));
    show_extra("epoll-changed", ep);
    struct epoll_event got;
    say("fired=%d", TRY(epoll_wait(ep, &got, 1, 0)));
    show_extra("epoll-fired", ep);

    char path[] = "/tmp/fdinfo-locks-XXXXXX";
    int file = mkstemp(path);
    if (file < 0) return 93;
    unlink(path);
    int same = dup(file);
    say("setlk=%d %d", lock_range(file, F_SETLK, F_WRLCK, 0, 10), lock_range(file, F_SETLK, F_RDLCK, 20, 30));
    show_extra("locks", file);
    show_extra("locks-dup", same);
    char again[64];
    snprintf(again, sizeof again, "/proc/self/fd/%d", file);
    int second = open(again, O_RDWR);
    say("setlk second=%d", lock_range(second, F_SETLK, F_WRLCK, 10, 5));
    show_extra("locks-merged", file);
    show_extra("locks-second", second);
    say("ofd=%d", lock_range(second, F_OFD_SETLK, F_WRLCK, 100, 1));
    show_extra("locks-ofd", second);
    say("unlock=%d", lock_range(file, F_SETLK, F_UNLCK, 2, 3));
    show_extra("locks-split", file);

    /* A description's flock lock comes before its record locks. Asking
       again for the kind it has keeps it; a change of kind that conflicts
       drops it; a child's lock on a shared description shows its own pid. */
    say("flock=%d", TRY(flock(file, LOCK_SH)));
    show_extra("flock", file);
    show_extra("flock-dup", same);
    say("flock second=%d again=%d", TRY(flock(second, LOCK_SH | LOCK_NB)), TRY(flock(file, LOCK_SH)));
    show_extra("flock-shared", second);
    say("flock upgrade=%d", TRY(flock(file, LOCK_EX | LOCK_NB)));
    show_extra("flock-dropped", file);
    say("flock unlock=%d", TRY(flock(second, LOCK_UN)));
    pid_t child = fork();
    if (child == 0) _exit(flock(second, LOCK_EX | LOCK_NB) == 0 ? 0 : 1);
    int status;
    waitpid(child, &status, 0);
    say("flock child=%d", WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    show_extra("flock-child", second);
    return 0;
}

/* POSIX record locks belong to the descriptor table: a child cloned with
 * CLONE_FILES alone sets them for its parent too. The parent never conflicts
 * with them, another process does (seeing the child's pid), the child's exit
 * leaves them, and the parent's close of the file drops them. */
static int getlk_from_other(const char *path, short type) {
    int ready[2];
    pipe(ready);
    pid_t other = fork();
    if (other == 0) {
        int fd = open(path, O_RDWR);
        struct flock l = {.l_type = type, .l_whence = SEEK_SET, .l_start = 0, .l_len = 10};
        int r = fcntl(fd, F_GETLK, &l);
        int out[2] = {r < 0 ? -errno : l.l_type, l.l_pid};
        write(ready[1], out, sizeof out);
        _exit(0);
    }
    int got[2] = {-1, -1};
    read(ready[0], got, sizeof got);
    waitpid(other, NULL, 0);
    close(ready[0]);
    close(ready[1]);
    return got[0] == F_UNLCK ? 0 : got[0] < 0 ? got[0] : got[1];
}
static int case_shared_locks(void) {
    char path[] = "/tmp/shared-locks-XXXXXX";
    int file = mkstemp(path);
    if (file < 0) return 93;
    int done[2];
    pipe(done);
    pid_t child = syscall(SYS_clone, CLONE_FILES | SIGCHLD, 0, 0, 0, 0);
    if (child == 0) {
        int r = lock_range(file, F_SETLK, F_WRLCK, 0, 10);
        write(done[1], &r, sizeof r);
        _exit(0);
    }
    int set = -1;
    read(done[0], &set, sizeof set);
    say("child setlk=%d", set);
    /* The parent's table holds it: no conflict for the parent. */
    struct flock l = {.l_type = F_WRLCK, .l_whence = SEEK_SET, .l_start = 0, .l_len = 10};
    long getlk = TRY(fcntl(file, F_GETLK, &l));
    say("parent getlk=%ld type=%s", getlk, l.l_type == F_UNLCK ? "unlocked" : "locked");
    int pid = getlk_from_other(path, F_RDLCK);
    say("other sees child=%d", pid == child);
    show_extra("shared-locks", file);
    int status;
    waitpid(child, &status, 0);
    say("child exited=%d", WIFEXITED(status));
    pid = getlk_from_other(path, F_RDLCK);
    say("after exit other sees child=%d", pid == child);
    /* The parent changes the same lock, as its owner. */
    say("parent setlk read=%d", lock_range(file, F_SETLK, F_RDLCK, 0, 5));
    show_extra("shared-locks-changed", file);
    /* Closing any descriptor of the file drops the table's locks. */
    int again = open(path, O_RDWR);
    close(again);
    say("after close other sees=%d", getlk_from_other(path, F_WRLCK));
    unlink(path);
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
    if (!strcmp(mode, "signalfd-fdinfo")) return case_fdinfo();
    if (!strcmp(mode, "signalfd-shared-locks")) return case_shared_locks();
    return 2;
}
