#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/fanotify.h>
#include <sys/file.h>
#include <sys/inotify.h>
#include <sys/ioctl.h>
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/msg.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <sys/sem.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/timerfd.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* linux/userfaultfd.h, linux/filter.h and linux/seccomp.h. */
#define UFFDIO_API 0xc018aa3fUL
#define UFFDIO_REGISTER 0xc020aa00UL
#define UFFDIO_ZEROPAGE 0xc020aa04UL
#define SECCOMP_IOCTL_NOTIF_RECV 0xc0502100UL
#define SECCOMP_IOCTL_NOTIF_SEND 0xc0182101UL
struct filter {
    uint16_t code;
    uint8_t jt, jf;
    uint32_t k;
};
struct program {
    uint16_t length;
    struct filter *filter;
};
struct answer {
    uint64_t id;
    int64_t value;
    int32_t error;
    uint32_t flags;
};

/* The process's real-time timer expires in each kind of wait: its handler set
 * without SA_RESTART (plain), with it (restart), or not at all (default).
 * Nothing else ends a wait the timer is to end: what would is held back until
 * the waiter is done, and only a watchdog ends it before, which `ended` tells.
 * A wait that runs again (restart) ends once the handler ran. One that no
 * handler ends (a vfork's, and those only a fatal signal ends) is ended 1.5
 * seconds after the timer is set, which by then has expired, so its `ended` is
 * 1. The timer goes on every 300 ms, for a waiter that is late to its wait. */
#define WAITS 33
#define VFORK 29
#define UFFD 30
#define FANOTIFY 31
#define SECCOMP 32
static const char *const names[WAITS] = {
    "waitpid", "waitid", "pause", "sigsuspend", "nanosleep", "clock_nanosleep", "poll", "select",
    "epoll_wait", "pipe-read", "pipe-write", "futex", "futex-timeout", "flock", "F_SETLKW",
    "F_OFD_SETLKW", "semop", "msgrcv", "sigtimedwait", "recv", "accept", "eventfd", "timerfd",
    "inotify", "signalfd", "fifo-open", "splice", "semtimedop", "ppoll", "vfork",
    "userfaultfd-read", "fanotify-open", "seccomp-killable"};
struct slot {
    char line[160];
    volatile int ended, word, ready, armed, fired, told, sent;
};
static struct slot *slot;
static int in[2], full[2], pair[2], listener, event, timer, file, sem, queue, watch, signals, poller;
static int notify = -1;
static char *page;
static char path[64], fifo[64];
static void alarmed(int sig) { (void)sig; slot->fired = 1; }
static void other(int sig) { (void)sig; }
static void ms(long n) {
    struct timespec t = {n / 1000, n % 1000 * 1000000};
    while (nanosleep(&t, &t) && errno == EINTR) {}
}
static int way, kind;
static int killable(int what) { return what >= VFORK; }
/* Waits for what ends the wait, or for the waiter to be done with it. */
static void until(void) {
    int n = 0;
    while (!slot->armed) ms(1);
    for (; !slot->told && n < 2400; n++) {
        if (killable(kind) && way < 2 && n == 300) break;
        if (!killable(kind) && way == 1 && slot->fired) return;
        if (kind == VFORK && way == SIGQUIT && slot->sent) {
            ms(300);
            break;
        }
        ms(5);
    }
    if (slot->told) _exit(0);
    slot->ended = 1;
}
static int vforked(void *arg) {
    (void)arg;
    until();
    _exit(0);
}
static void set_up(int what, int n) {
    snprintf(path, sizeof path, "/tmp/timer-waits-%d-%d", getpid(), n);
    snprintf(fifo, sizeof fifo, "/tmp/timer-waits-%d-%d.fifo", getpid(), n);
    pipe(in);
    pipe(full);
    fcntl(full[1], F_SETPIPE_SZ, 4096);
    char bytes[4096] = {0};
    if (what == 10) write(full[1], bytes, sizeof bytes);
    socketpair(AF_UNIX, SOCK_STREAM, 0, pair);
    struct sockaddr_un any = {.sun_family = AF_UNIX};
    listener = socket(AF_UNIX, SOCK_STREAM, 0);
    bind(listener, (void *)&any, sizeof(sa_family_t));
    listen(listener, 1);
    event = eventfd(0, 0);
    timer = timerfd_create(CLOCK_MONOTONIC, 0);
    file = open(path, O_RDWR | O_CREAT, 0600);
    mkfifo(fifo, 0600);
    sem = semget(IPC_PRIVATE, 1, 0600);
    queue = msgget(IPC_PRIVATE, 0600);
    watch = inotify_init1(0);
    inotify_add_watch(watch, path, IN_OPEN);
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGUSR2);
    sigprocmask(SIG_BLOCK, &set, NULL);
    signals = signalfd(-1, &set, 0);
    poller = epoll_create1(0);
    epoll_ctl(poller, EPOLL_CTL_ADD, in[0], &(struct epoll_event){.events = EPOLLIN});
    if (what == SECCOMP) {
        /* getppid waits for the listener (SECCOMP_RET_USER_NOTIF). */
        struct filter code[] = {
            {0x20, 0, 0, 0}, {0x15, 0, 1, SYS_getppid}, {0x06, 0, 0, 0x7fc00000}, {0x06, 0, 0, 0x7fff0000}};
        struct program program = {4, code};
        prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
        /* SECCOMP_FILTER_FLAG_NEW_LISTENER and _WAIT_KILLABLE_RECV. */
        notify = (int)syscall(SYS_seccomp, 1L, 8L | 32L, &program);
        if (notify < 0) puts("no seccomp listener");
    }
}
/* A page the kernel's copy waits for, registered by the waiter itself, as a
 * fork does not keep the registration. */
static void register_page(void) {
    page = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    notify = (int)syscall(SYS_userfaultfd, 0L);
    uint64_t api[3] = {0xaa}, range[4] = {(uintptr_t)page, 4096, 1};
    if (ioctl(notify, UFFDIO_API, api) || ioctl(notify, UFFDIO_REGISTER, range)) puts("no userfaultfd");
    write(in[1], "x", 1);
}
static void clean_up(void) {
    semctl(sem, 0, IPC_RMID);
    msgctl(queue, IPC_RMID, NULL);
    unlink(path);
    unlink(fifo);
}
static long wait_in(int what) {
    char byte = 0, bytes[512];
    int status;
    siginfo_t info;
    uint64_t value;
    struct timespec part = {20, 0}, two = {20, 0};
    sigset_t set;
    struct flock lock = {.l_type = F_WRLCK};
    struct sembuf op = {0, -1, 0};
    struct {
        long type;
        char text[8];
    } message;
    struct pollfd p = {in[0], POLLIN, 0};
    struct epoll_event ready;
    fd_set fds;
    static char stack[65536] __attribute__((aligned(16)));
    sigemptyset(&set);
    switch (what) {
    case 0: return waitpid(-1, &status, 0) > 0 ? 1 : -1;
    case 1: return waitid(P_ALL, 0, &info, WEXITED);
    case 2: return syscall(SYS_pause);
    case 3: return syscall(SYS_rt_sigsuspend, &set, 8L);
    case 4: return syscall(SYS_nanosleep, &part, NULL);
    case 5: return syscall(SYS_clock_nanosleep, (long)CLOCK_MONOTONIC, 0L, &part, NULL);
    case 6: return poll(&p, 1, 20000);
    case 7:
        FD_ZERO(&fds);
        FD_SET(in[0], &fds);
        return select(in[0] + 1, &fds, NULL, NULL, NULL);
    case 8: return epoll_wait(poller, &ready, 1, -1);
    case 9: return read(in[0], &byte, 1);
    case 10: return write(full[1], &byte, 1);
    case 11: return syscall(SYS_futex, &slot->word, 0L, 0L, NULL, NULL, 0L);
    case 12: return syscall(SYS_futex, &slot->word, 0L, 0L, &two, NULL, 0L);
    case 13: return flock(file, LOCK_EX);
    case 14: return fcntl(file, F_SETLKW, &lock);
    case 15: return fcntl(file, 38, &lock);
    case 16: return semop(sem, &op, 1);
    case 17: return msgrcv(queue, &message, 8, 1, 0) >= 0 ? 0 : -1;
    case 18:
        sigaddset(&set, SIGUSR2);
        return syscall(SYS_rt_sigtimedwait, &set, NULL, NULL, 8L);
    case 19: return recv(pair[0], &byte, 1, 0);
    case 20: return accept(listener, NULL, NULL) >= 0 ? 0 : -1;
    case 21: return read(event, &value, 8);
    case 22: return read(timer, &value, 8);
    case 23: return read(watch, bytes, sizeof bytes) > 0 ? 1 : -1;
    case 24: return read(signals, bytes, sizeof bytes);
    case 25: return open(fifo, O_RDONLY) >= 0 ? 0 : -1;
    case 26: return syscall(SYS_splice, in[0], NULL, full[1], NULL, 1L, 0L);
    case 27: return syscall(SYS_semtimedop, sem, &op, 1L, &two);
    case 28: return syscall(SYS_ppoll, &p, 1L, &two, NULL, 0L);
    case VFORK:
        return clone(vforked, stack + sizeof stack, CLONE_VM | CLONE_VFORK | SIGCHLD, NULL) > 0 ? 1 : -1;
    case UFFD: return read(in[0], page, 1);
    case FANOTIFY: return open(path, O_RDONLY) >= 0 ? 0 : -1;
    case SECCOMP: return syscall(SYS_getppid);
    }
    return 0;
}
/* The helper: what holds the wait, then what ends it. */
static void help(int what, pid_t waiter) {
    struct flock lock = {.l_type = F_WRLCK};
    struct sembuf op = {0, 1, 0};
    struct {
        long type;
        char text[8];
    } message = {1, "x"};
    uint64_t one = 1;
    struct sockaddr_un name;
    socklen_t length = sizeof name;
    char bytes[4096];
    int fd = -1;
    uint64_t got[10] = {0};
    if (what == 13) flock(open(path, O_RDWR), LOCK_EX);
    if (what == 14 || what == 15) fcntl(open(path, O_RDWR), F_SETLK, &lock);
    if (what == FANOTIFY) {
        fd = fanotify_init(FAN_CLASS_CONTENT, O_RDONLY);
        if (fanotify_mark(fd, FAN_MARK_ADD, FAN_OPEN_PERM, AT_FDCWD, path)) puts("no fanotify");
    }
    slot->ready = 1;
    if (what == SECCOMP) ioctl(notify, SECCOMP_IOCTL_NOTIF_RECV, got);
    if (what == VFORK) _exit(0);
    until();
    switch (what) {
    case 2: case 3: kill(waiter, SIGUSR1); break;
    case 6: case 7: case 8: case 9: case 26: case 28: write(in[1], "x", 1); break;
    case 10: read(full[0], bytes, sizeof bytes); break;
    case 11: case 12:
        /* Wakes the wait once one sleeps in it: after the handler, that is the
         * one run again. The word stays 0, as one changed before that wait
         * reads it would end the wait with EAGAIN instead. It tries as long as
         * until() waits. */
        for (int n = 0; !slot->told && n < 2400; n++) {
            if (syscall(SYS_futex, &slot->word, 1L, 1L, NULL, NULL, 0L) > 0) break;
            ms(5);
        }
        break;
    case 16: case 27: semop(sem, &op, 1); break;
    case 17: msgsnd(queue, &message, 8, 0); break;
    case 18: case 24: kill(waiter, SIGUSR2); break;
    case 19: write(pair[1], "x", 1); break;
    case 20:
        getsockname(listener, (void *)&name, &length);
        connect(socket(AF_UNIX, SOCK_STREAM, 0), (void *)&name, length);
        break;
    case 21: write(event, &one, 8); break;
    case 22: timerfd_settime(timer, 0, &(struct itimerspec){{0, 0}, {0, 1}}, NULL); break;
    case 23: close(open(path, O_WRONLY)); break;
    case 25: close(open(fifo, O_WRONLY)); break;
    case UFFD: {
        uint64_t zero[4] = {(uintptr_t)page, 4096};
        ioctl(notify, UFFDIO_ZEROPAGE, zero);
        break;
    }
    case SECCOMP: {
        struct answer answer = {got[0], 7, 0, 0};
        ioctl(notify, SECCOMP_IOCTL_NOTIF_SEND, &answer);
        break;
    }
    }
    _exit(0);
}
/* way: 0 plain, 1 restart, 2 default; another is a signal sent instead. */
static void run(int what, int n) {
    const char *const ways[] = {"plain", "restart", "default"};
    char sent[16];
    snprintf(sent, sizeof sent, "signal-%d", way);
    const char *how = way < 3 ? ways[way] : sent;
    kind = what;
    set_up(what, n);
    pid_t waiter = fork();
    if (!waiter) {
        struct rlimit none = {0, 0};
        setrlimit(RLIMIT_CORE, &none);
        if (what == UFFD) register_page();
        pid_t self = getpid();
        if (!fork()) help(what, self);
        while (!slot->ready) ms(1);
        if (what == SECCOMP) close(notify);
        struct sigaction action = {.sa_handler = other};
        sigaction(SIGUSR1, &action, NULL);
        action.sa_handler = alarmed;
        action.sa_flags = way == 1 ? SA_RESTART : 0;
        if (way < 2) sigaction(SIGALRM, &action, NULL);
        if (what == 22) timerfd_settime(timer, 0, &(struct itimerspec){{0, 0}, {20, 0}}, NULL);
        if (way < 3) {
            setitimer(ITIMER_REAL, &(struct itimerval){{0, 300000}, {0, 600000}}, NULL);
        } else if (!fork()) {
            ms(600);
            kill(self, way);
            slot->sent = 1;
            _exit(0);
        }
        slot->armed = 1;
        long r = wait_in(what);
        int error = errno;
        snprintf(slot->line, sizeof slot->line, "%s %s: r=%ld errno=%d fired=%d ended=%d\n", names[what],
                 how, r, r < 0 ? error : 0, slot->fired, slot->ended);
        slot->told = 1;
        _exit(0);
    }
    int status;
    waitpid(waiter, &status, 0);
    int ended = slot->ended;
    slot->told = 1;
    if (WIFSIGNALED(status))
        snprintf(slot->line, sizeof slot->line, "%s %s: killed by %d ended=%d\n", names[what], how,
                 WTERMSIG(status), ended);
    clean_up();
}
int main(int argc, char **argv) {
    /* timer-waits-plain, -restart or -default. */
    const char *mode = argc > 1 ? argv[1] : "";
    way = strstr(mode, "restart") ? 1 : strstr(mode, "default") ? 2 : 0;
    int count = way == 2 ? WAITS + 2 : WAITS;
    struct slot *slots = mmap(NULL, count * sizeof *slots, PROT_READ | PROT_WRITE,
                              MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    setvbuf(stdout, NULL, _IOLBF, 0);
    for (int at = 0; at < count;) {
        int end = at + 18;
        for (; at < count && at < end; at++) {
            slot = &slots[at];
            if (!fork()) {
                /* A fatal signal ends a vfork's wait, but not one that dumps core. */
                if (at >= WAITS) way = at == WAITS ? SIGTERM : SIGQUIT;
                run(at < WAITS ? at : VFORK, at);
                _exit(0);
            }
        }
        while (wait(NULL) > 0) {}
    }
    for (int at = 0; at < count; at++) fputs(slots[at].line, stdout);
    return 0;
}
