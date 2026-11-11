/* POSIX message queues, compared with Linux: mq_open, mq_unlink,
   mq_timedsend, mq_timedreceive, mq_notify and mq_getsetattr, their errors
   in Linux's order, priorities, O_NONBLOCK and timeouts, the default and
   unprivileged limits and the /proc/sys/fs/mqueue files that set them, poll, select and epoll on a queue, notifications by
   signal, by nothing and by netlink cookie, and queues shared across fork.

   Each case runs as root (through sudo) in IPC and network namespaces of
   its own, so that its queues, counts and limits are a new namespace's
   defaults whatever the host's sysctls; the unprivileged checks run in a
   child that becomes user 2000. Outputs are counts, flags, texts and errno
   values, never process IDs or descriptors. */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <mqueue.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define BAD ((void *)8)

/* The result of a call that fails with errno: the value, or -errno. */
#define TRY(call) ({ long try_result = (long)(call); try_result < 0 ? -errno : try_result; })

/* One labelled value of a line, so that the calls of a line run in the
   order written (a call's arguments run in any order). */
static void put(const char *label, long value) { printf(" %s=%ld", label, value); }

static void say(const char *format, ...) {
    va_list list;
    va_start(list, format);
    vprintf(format, list);
    va_end(list);
    putchar('\n');
    fflush(stdout);
}

/* The raw calls, which take names without the C library's leading '/'. */
static long q_open(const char *name, int flags, int mode, const struct mq_attr *attr) {
    return TRY(syscall(SYS_mq_open, name, flags, mode, attr));
}
static long q_unlink(const char *name) { return TRY(syscall(SYS_mq_unlink, name)); }
static long q_send(long fd, const char *text, size_t len, unsigned prio, const struct timespec *t) {
    return TRY(syscall(SYS_mq_timedsend, fd, text, len, prio, t));
}
static char q_text[65536];
static unsigned q_prio;
static long q_receive(long fd, size_t len, const struct timespec *t) {
    memset(q_text, 0, sizeof q_text);
    q_prio = 99;
    return TRY(syscall(SYS_mq_timedreceive, fd, q_text, len, &q_prio, t));
}
static long q_notify(long fd, const struct sigevent *event) { return TRY(syscall(SYS_mq_notify, fd, event)); }
static long q_attr(long fd, const struct mq_attr *new, struct mq_attr *old) {
    return TRY(syscall(SYS_mq_getsetattr, fd, new, old));
}

/* A receive's result, priority and text. */
static void show_receive(const char *label, long fd, size_t len, const struct timespec *t) {
    long r = q_receive(fd, len, t);
    if (r < 0)
        printf(" %s=%ld", label, r);
    else
        printf(" %s=%ld:%u:%.*s", label, r, q_prio, (int)r, q_text);
}

static void show_attr(const char *label, long fd) {
    struct mq_attr a;
    memset(&a, 0x55, sizeof a);
    long r = q_attr(fd, NULL, &a);
    say("%s: getattr=%ld flags=%ld maxmsg=%ld msgsize=%ld curmsgs=%ld reserved=%ld", label, r, a.mq_flags,
        a.mq_maxmsg, a.mq_msgsize, a.mq_curmsgs, a.__unused[0] | a.__unused[1] | a.__unused[2] | a.__unused[3]);
}

/* The state line a read of the queue gives, with the registered process
   shown as whether it is `owner`. */
static void show_line(const char *label, long fd, pid_t owner) {
    char line[200] = {0};
    if (lseek(fd, 0, SEEK_SET) != 0) {
        say("%s: lseek=%d", label, -errno);
        return;
    }
    long n = TRY(read(fd, line, sizeof line - 1));
    char *pid = strstr(line, "NOTIFY_PID:");
    int owned = -1;
    if (pid) {
        owned = atoi(pid + 11) == owner;
        pid[11] = 0;
    }
    char *end = strchr(line, '\n');
    if (end) *end = '|';
    say("%s: read=%ld [%s] owner=%d", label, n, line, owned);
}

/* What the descriptor's link in /proc/self/fd reads. */
static void show_link(const char *label, long fd) {
    char path[64], target[300] = {0};
    snprintf(path, sizeof path, "/proc/self/fd/%ld", fd);
    long n = TRY(readlink(path, target, sizeof target - 1));
    say("%s: readlink=%ld [%s]", label, n, n > 0 ? target : "");
}

static struct timespec from_now(long millis) {
    struct timespec t;
    clock_gettime(CLOCK_REALTIME, &t);
    t.tv_sec += millis / 1000;
    t.tv_nsec += (millis % 1000) * 1000000;
    if (t.tv_nsec >= 1000000000) {
        t.tv_sec++;
        t.tv_nsec -= 1000000000;
    }
    if (t.tv_nsec < 0) {
        t.tv_sec--;
        t.tv_nsec += 1000000000;
    }
    return t;
}

static long elapsed_ms(struct timespec start) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (now.tv_sec - start.tv_sec) * 1000 + (now.tv_nsec - start.tv_nsec) / 1000000;
}

static struct timespec monotonic(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t;
}

static void pause_ms(long millis) {
    struct timespec t = {millis / 1000, (millis % 1000) * 1000000};
    while (nanosleep(&t, &t) && errno == EINTR) {
    }
}

static int wait_child(pid_t pid) {
    int status = 0;
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {
    }
    return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
}

static pid_t child(void) {
    fflush(stdout);
    return fork();
}

/* Becomes user 2000, without capabilities. */
static int unprivileged(void) {
    return syscall(SYS_setresgid, 2000, 2000, 2000) || syscall(SYS_setgroups, 0, NULL) ||
           syscall(SYS_setresuid, 2000, 2000, 2000);
}

static int isolate(void) {
    if (unshare(CLONE_NEWIPC | CLONE_NEWNET)) {
        say("unshare=%d", -errno);
        return 1;
    }
    return 0;
}

static int calls_case(void) {
    if (isolate()) return 10;
    /* Room for the largest queues root may make. */
    struct rlimit room = {64 << 20, 64 << 20};
    if (setrlimit(RLIMIT_MSGQUEUE, &room)) return 12;
    char long_name[300];
    memset(long_name, 'n', sizeof long_name);
    long_name[256] = 0;
    char longest[256];
    memset(longest, 'n', 255);
    longest[255] = 0;
    struct mq_attr none = {.mq_maxmsg = 0, .mq_msgsize = 8};
    struct mq_attr negative = {.mq_maxmsg = 2, .mq_msgsize = -1};
    say("open: missing=%ld empty=%ld slash=%ld dot=%ld dotdot=%ld long=%ld longest=%ld fault=%ld",
        q_open("missing", O_RDWR, 0, NULL), q_open("", O_RDWR | O_CREAT, 0600, NULL),
        q_open("a/b", O_RDWR | O_CREAT, 0600, NULL), q_open(".", O_RDWR | O_CREAT, 0600, NULL),
        q_open("..", O_RDONLY, 0, NULL), q_open(long_name, O_RDWR | O_CREAT, 0600, NULL),
        q_open(longest, O_RDWR, 0, NULL), q_open(BAD, O_RDWR | O_CREAT, 0600, NULL));
    /* The attributes are read first, whatever the name and flags. */
    say("open: attr-fault=%ld attr-fault-bad-name=%ld no-messages=%ld negative-size=%ld",
        q_open("q", O_RDWR | O_CREAT, 0600, BAD), q_open(BAD, O_RDWR, 0, BAD),
        q_open("q", O_RDWR | O_CREAT, 0600, &none), q_open("q", O_RDWR | O_CREAT, 0600, &negative));
    /* As root, CAP_SYS_RESOURCE allows up to 65536 messages of 16 MiB. */
    struct mq_attr many = {.mq_maxmsg = 65536, .mq_msgsize = 1};
    struct mq_attr too_many = {.mq_maxmsg = 65537, .mq_msgsize = 1};
    struct mq_attr huge = {.mq_maxmsg = 1, .mq_msgsize = 16 << 20};
    struct mq_attr too_huge = {.mq_maxmsg = 1, .mq_msgsize = (16 << 20) + 1};
    long m = q_open("many", O_RDWR | O_CREAT, 0600, &many);
    long h = q_open("huge", O_RDWR | O_CREAT, 0600, &huge);
    say("root: many=%d too-many=%ld huge=%d too-huge=%ld", m >= 0, q_open("x", O_RDWR | O_CREAT, 0600, &too_many),
        h >= 0, q_open("x", O_RDWR | O_CREAT, 0600, &too_huge));
    show_attr("many", m);
    close(m);
    close(h);
    q_unlink("many");
    q_unlink("huge");

    /* The defaults, the descriptor and its file. */
    umask(027);
    long d = q_open("default", O_WRONLY | O_CREAT | O_NONBLOCK, 07666, NULL);
    umask(022);
    show_attr("default", d);
    struct stat st;
    long stated = TRY(fstat(d, &st));
    say("default: cloexec=%d flags=%o stat=%ld mode=%o size=%ld links=%ld uid=%d", fcntl(d, F_GETFD),
        fcntl(d, F_GETFL) & (O_ACCMODE | O_NONBLOCK), stated, st.st_mode, (long)st.st_size, (long)st.st_nlink,
        st.st_uid);
    show_link("default", d);
    printf("default:");
    put("fchmod", TRY(fchmod(d, 0604)));
    put("fchown", TRY(fchown(d, 5, 6)));
    stated = TRY(fstat(d, &st));
    say(" stat=%ld mode=%o uid=%d gid=%d", stated, st.st_mode, st.st_uid, st.st_gid);
    say("default: exclusive=%ld both-modes=%ld again=%d", q_open("default", O_RDWR | O_CREAT | O_EXCL, 0600, NULL),
        q_open("default", O_RDWR | 3, 0, NULL), q_open("default", O_RDONLY | O_CREAT, 0600, &none) >= 0);
    close(d);

    /* Priorities: highest first, the order sent within one. */
    struct mq_attr small = {.mq_maxmsg = 4, .mq_msgsize = 16};
    long q = q_open("q", O_RDWR | O_CREAT, 0640, &small);
    long r = q_open("q", O_RDONLY, 0, NULL);
    long w = q_open("q", O_WRONLY, 0, NULL);
    printf("send");
    const char *texts[] = {"one", "five", "uno", "zero"};
    unsigned prios[] = {1, 5, 1, 0};
    for (int i = 0; i < 4; i++) printf(" %ld", q_send(w, texts[i], strlen(texts[i]), prios[i], NULL));
    say("");
    show_attr("four", q);
    show_line("four", q, 0);
    struct timespec past = {0, 0};
    say("full: timed-out=%ld", q_send(w, "x", 1, 0, &past));
    struct mq_attr nonblocking = {.mq_flags = O_NONBLOCK};
    struct mq_attr old;
    long set = q_attr(w, &nonblocking, &old);
    say("setattr=%ld old-flags=%ld fcntl=%o", set, old.mq_flags, fcntl(w, F_GETFL) & O_NONBLOCK);
    say("full: nonblocking=%ld", q_send(w, "x", 1, 0, NULL));
    printf("receive");
    for (int i = 0; i < 4; i++) show_receive("got", r, 16, NULL);
    show_receive("empty-past", r, 16, &past);
    say("");
    say("empty: nonblocking=%ld", (q_attr(r, &nonblocking, NULL), q_receive(r, 16, NULL)));

    /* Sends' checks, in order: the timeout, the priority, the queue, its
       mode, the size, the message. */
    struct timespec bad_nanos = {0, 1000000000};
    struct timespec negative_time = {-1, 0};
    int p[2];
    if (pipe(p)) return 11;
    say("send: timeout-fault=%ld bad-nanos=%ld negative=%ld prio=%ld prio-bad-fd=%ld pipe=%ld closed=%ld",
        q_send(-1, "x", 1, 32768, BAD), q_send(-1, "x", 1, 32768, &bad_nanos), q_send(-1, "x", 1, 0, &negative_time),
        q_send(w, "x", 1, 32768, NULL), q_send(-1, "x", 1, 32768, NULL), q_send(p[0], "x", 1, 0, NULL),
        q_send(-1, "x", 1, 0, NULL));
    say("send: read-only=%ld read-only-big=%ld big=%ld fault=%ld largest=%ld top-prio=%ld",
        q_send(r, "x", 1, 0, NULL), q_send(r, "x", 17, 0, NULL), q_send(w, q_text, 17, 0, NULL),
        q_send(w, BAD, 16, 0, NULL), q_send(w, "0123456789abcdef", 16, 0, NULL), q_send(w, "", 0, 32767, NULL));
    say("receive: timeout-fault=%ld pipe=%ld write-only=%ld small=%ld",
        TRY(syscall(SYS_mq_timedreceive, -1, q_text, 16, NULL, BAD)), q_receive(p[0], 16, NULL),
        q_receive(w, 16, NULL), q_receive(r, 15, NULL));
    /* A bad priority or buffer loses the message. */
    printf("receive:");
    put("prio-fault", TRY(syscall(SYS_mq_timedreceive, r, q_text, 16, BAD, NULL)));
    put("text-fault", TRY(syscall(SYS_mq_timedreceive, r, BAD, 16, &q_prio, NULL)));
    put("none-left", TRY(syscall(SYS_mq_timedreceive, r, q_text, 16, NULL, NULL)));
    say("");
    show_attr("drained", q);

    /* The file: read shows the state line from the position; it has no
       write. */
    char buf[8];
    lseek(q, 0, SEEK_SET);
    long first = TRY(read(q, buf, 6));
    printf("file: first=%ld [%.6s]", first, buf);
    put("rest", TRY(read(q, q_text, 200)));
    put("end", TRY(read(q, buf, 8)));
    put("seek-end", TRY(lseek(q, 0, SEEK_END)));
    put("write", TRY(write(q, "x", 1)));
    put("read-wo", TRY(read(w, buf, 8)));
    put("write-ro", TRY(write(r, "x", 1)));
    say("");

    /* getsetattr's checks: the new flags, then the queue. */
    struct mq_attr bad_flags = {.mq_flags = 1};
    say("attr: bad-flags=%ld bad-flags-bad-fd=%ld new-fault=%ld old-fault=%ld pipe=%ld",
        q_attr(q, &bad_flags, NULL), q_attr(-1, &bad_flags, NULL), q_attr(q, BAD, NULL), q_attr(q, NULL, BAD),
        q_attr(p[0], NULL, NULL));

    /* No access mode: made all the same, but neither sends nor receives. */
    long neither = q_open("neither", 3 | O_CREAT, 0600, &small);
    say("no-mode: open=%d send=%ld receive=%ld", neither >= 0, q_send(neither, "x", 1, 0, NULL),
        q_receive(neither, 16, NULL));
    close(neither);
    q_unlink("neither");

    /* Unlinked, the queue lasts while open. */
    printf("unlink:");
    put("first", q_unlink("q"));
    put("again", q_unlink("q"));
    put("reopen", q_open("q", O_RDWR, 0, NULL));
    put("bad", q_unlink(BAD));
    put("empty", q_unlink(""));
    put("slash", q_unlink("a/b"));
    put("long", q_unlink(long_name));
    say("");
    show_link("unlinked", r);
    say("unlinked: send=%ld", q_send(w, "late", 4, 3, NULL));
    printf("unlinked");
    show_receive("got", r, 16, NULL);
    say("");
    close(q);
    close(r);
    close(w);

    /* Through the C library, whose names start with '/'. */
    mqd_t lib = mq_open("/library", O_RDWR | O_CREAT | O_EXCL, 0600, NULL);
    unsigned prio = 0;
    char text[8192];
    long sent = mq_send(lib, "hi", 2, 7) ? -errno : 0;
    long got = mq_receive(lib, text, sizeof text, &prio);
    printf("library: open=%d send=%ld receive=%ld prio=%u", lib >= 0, sent, got, prio);
    put("close", mq_close(lib));
    put("unlink", mq_unlink("/library"));
    put("unlink-again", mq_unlink("/library") ? -errno : 0);
    put("no-slash", mq_open("library", O_RDONLY) < 0 ? -errno : 0);
    say("");
    q_unlink("default");
    close(p[0]);
    close(p[1]);
    return 0;
}

/* What user 2000 may do: the limits without CAP_SYS_RESOURCE, the
   permissions of root's queue, and RLIMIT_MSGQUEUE. */
static int limits_case(void) {
    if (isolate()) return 10;
    struct mq_attr one = {.mq_maxmsg = 1, .mq_msgsize = 1};
    long mine = q_open("roots", O_RDWR | O_CREAT, 0600, &one);
    long open_one = q_open("open", O_RDWR | O_CREAT, 0644, &one);
    if (mine < 0 || open_one < 0) return 11;
    /* RLIMIT_MSGQUEUE's default, whatever sudo was started with. */
    struct rlimit standard = {819200, 819200};
    if (setrlimit(RLIMIT_MSGQUEUE, &standard)) return 12;
    pid_t pid = child();
    if (pid == 0) {
        if (unprivileged()) _exit(90);
        struct mq_attr eleven = {.mq_maxmsg = 11, .mq_msgsize = 8};
        struct mq_attr large = {.mq_maxmsg = 1, .mq_msgsize = 8193};
        struct mq_attr ten = {.mq_maxmsg = 10, .mq_msgsize = 8192};
        long t = q_open("ten", O_RDWR | O_CREAT, 0600, &ten);
        say("user: eleven=%ld large=%ld ten=%d", q_open("x", O_RDWR | O_CREAT, 0600, &eleven),
            q_open("x", O_RDWR | O_CREAT, 0600, &large), t >= 0);
        close(t);
        q_unlink("ten");
        say("user: read-roots=%ld write-open=%ld read-open=%d unlink-roots=%ld", q_open("roots", O_RDONLY, 0, NULL),
            q_open("open", O_WRONLY, 0, NULL), q_open("open", O_RDONLY, 0, NULL) >= 0, q_unlink("roots"));
        /* The default queue charges 10 * (8192 + 48 + 48) bytes, of
           RLIMIT_MSGQUEUE's 819200. */
        long fds[300];
        int made = 0;
        long error = 0;
        char name[32];
        for (; made < 20; made++) {
            snprintf(name, sizeof name, "d%d", made);
            fds[made] = q_open(name, O_RDWR | O_CREAT, 0600, NULL);
            if (fds[made] < 0) {
                error = fds[made];
                break;
            }
        }
        say("user: default-queues=%d then=%ld", made, error);
        /* An unlinked queue charges until it is closed. */
        q_unlink("d0");
        say("user: after-unlink=%ld", q_open("again", O_RDWR | O_CREAT, 0600, NULL));
        close(fds[0]);
        long again = q_open("again", O_RDWR | O_CREAT, 0600, NULL);
        say("user: after-close=%d", again >= 0);
        close(again);
        q_unlink("again");
        for (int i = 1; i < made; i++) {
            snprintf(name, sizeof name, "d%d", i);
            close(fds[i]);
            q_unlink(name);
        }
        /* A smaller limit: 97 bytes a queue of one 1-byte message. */
        struct rlimit limit = {1000, 1000};
        say("user: setrlimit=%ld", TRY(setrlimit(RLIMIT_MSGQUEUE, &limit)));
        for (made = 0; made < 20; made++) {
            snprintf(name, sizeof name, "s%d", made);
            fds[made] = q_open(name, O_RDWR | O_CREAT, 0600, &one);
            if (fds[made] < 0) {
                error = fds[made];
                break;
            }
        }
        say("user: small-queues=%d then=%ld", made, error);
        for (int i = 0; i < made; i++) {
            snprintf(name, sizeof name, "s%d", i);
            close(fds[i]);
            q_unlink(name);
        }
        _exit(0);
    }
    int status = wait_child(pid);
    say("user: status=%d", status);
    /* queues_max: 256 queues in the namespace, counting root's two, then
       ENOSPC for user 2000 but not for root. */
    pid = child();
    if (pid == 0) {
        if (unprivileged()) _exit(90);
        char name[32];
        int made = 0;
        long error = 0;
        for (; made < 300; made++) {
            snprintf(name, sizeof name, "m%d", made);
            long fd = q_open(name, O_RDWR | O_CREAT, 0600, &one);
            if (fd < 0) {
                error = fd;
                break;
            }
            close(fd);
        }
        say("queues: user-made=%d then=%ld", made, error);
        _exit(0);
    }
    status = wait_child(pid);
    long beyond = q_open("beyond", O_RDWR | O_CREAT, 0600, &one);
    say("queues: status=%d root-beyond=%d", status, beyond >= 0);
    return 0;
}

static volatile sig_atomic_t caught;
static void handler(int signal) {
    (void)signal;
    caught++;
}

/* Blocking sends and receives across processes, their timeouts and
   signals. */
static int wait_case(void) {
    if (isolate()) return 10;
    struct mq_attr two = {.mq_maxmsg = 2, .mq_msgsize = 16};
    long q = q_open("w", O_RDWR | O_CREAT, 0600, &two);
    if (q < 0) return 11;
    int ready[2];
    if (pipe(ready)) return 12;
    char byte;

    /* A waiting receiver takes the message as it is sent. */
    pid_t pid = child();
    if (pid == 0) {
        if (write(ready[1], "r", 1) != 1) _exit(90);
        printf("receiver");
        show_receive("got", q, 16, NULL);
        say("");
        _exit(0);
    }
    if (read(ready[0], &byte, 1) != 1) return 13;
    pause_ms(100);
    /* The parent prints only after the child, whose line comes first. */
    long direct = q_send(q, "direct", 6, 2, NULL);
    int direct_status = wait_child(pid);
    say("to-receiver: send=%ld status=%d", direct, direct_status);
    show_attr("to-receiver", q);

    /* A waiting sender's message goes into the room a receive makes. */
    q_send(q, "a", 1, 1, NULL);
    q_send(q, "b", 1, 1, NULL);
    pid = child();
    if (pid == 0) {
        if (write(ready[1], "s", 1) != 1) _exit(90);
        say("sender: send=%ld", q_send(q, "top", 3, 9, NULL));
        _exit(0);
    }
    if (read(ready[0], &byte, 1) != 1) return 14;
    pause_ms(100);
    long first = q_receive(q, 16, NULL);
    char first_text[17] = {0};
    unsigned first_prio = q_prio;
    if (first > 0) memcpy(first_text, q_text, (size_t)first);
    int sender_status = wait_child(pid);
    printf("from-sender: first=%ld:%u:%s status=%d", first, first_prio, first_text, sender_status);
    show_receive("next", q, 16, NULL);
    show_receive("last", q, 16, NULL);
    say("");

    /* Timeouts at an absolute realtime: one passed, one 150 ms on. */
    struct timespec start = monotonic();
    struct timespec soon = from_now(150);
    long timed = q_receive(q, 16, &soon);
    say("timeout: receive=%ld waited=%d", timed, elapsed_ms(start) >= 140);
    q_send(q, "1", 1, 0, NULL);
    q_send(q, "2", 1, 0, NULL);
    start = monotonic();
    soon = from_now(150);
    timed = q_send(q, "3", 1, 0, &soon);
    say("timeout: send=%ld waited=%d", timed, elapsed_ms(start) >= 140);
    struct timespec past = from_now(-1000);
    say("timeout: past-with-room=%ld", (q_receive(q, 16, NULL), q_send(q, "3", 1, 0, &past)));
    q_receive(q, 16, NULL);
    q_receive(q, 16, NULL);

    /* A handled signal ends a wait with EINTR, unless SA_RESTART, which
       goes on waiting; one that runs no handler (a stop and continue)
       restarts it. */
    for (int restart = 0; restart < 3; restart++) {
        pid = child();
        if (pid == 0) {
            struct sigaction action = {0};
            action.sa_handler = handler;
            action.sa_flags = restart == 1 ? SA_RESTART : 0;
            sigaction(SIGUSR1, &action, NULL);
            if (write(ready[1], "i", 1) != 1) _exit(90);
            printf("interrupt-%d", restart);
            show_receive("got", q, 16, NULL);
            say(" caught=%d", caught);
            _exit(0);
        }
        if (read(ready[0], &byte, 1) != 1) return 15;
        /* Long enough for the child to be waiting. */
        pause_ms(300);
        if (restart == 2) {
            kill(pid, SIGSTOP);
            pause_ms(50);
            kill(pid, SIGCONT);
        } else {
            kill(pid, SIGUSR1);
        }
        pause_ms(100);
        q_send(q, "late", 4, 1, NULL);
        say("interrupt-%d: status=%d", restart, wait_child(pid));
        /* What no one took. */
        printf("interrupt-%d: left", restart);
        show_receive("left", q, 16, &past);
        say("");
    }

    /* Two waiting receivers each take one message. */
    int got[2];
    if (pipe(got)) return 16;
    pid_t receivers[2];
    for (int i = 0; i < 2; i++) {
        receivers[i] = child();
        if (receivers[i] == 0) {
            if (write(ready[1], "x", 1) != 1) _exit(90);
            long r = q_receive(q, 16, NULL);
            if (r > 0 && write(got[1], q_text, 1) != 1) _exit(91);
            _exit(0);
        }
        if (read(ready[0], &byte, 1) != 1) return 17;
    }
    pause_ms(100);
    q_send(q, "A", 1, 0, NULL);
    q_send(q, "B", 1, 0, NULL);
    int statuses = wait_child(receivers[0]) + wait_child(receivers[1]);
    char taken[3] = {0};
    if (read(got[0], taken, 2) != 2) return 18;
    say("receivers: status=%d taken=%d", statuses, (taken[0] == 'A' && taken[1] == 'B') || (taken[0] == 'B' && taken[1] == 'A'));
    show_attr("end", q);
    q_unlink("w");
    return 0;
}

/* poll, select and epoll on a queue. */
static int poll_case(void) {
    if (isolate()) return 10;
    struct mq_attr two = {.mq_maxmsg = 2, .mq_msgsize = 8};
    long q = q_open("p", O_RDWR | O_CREAT, 0600, &two);
    long ro = q_open("p", O_RDONLY, 0, NULL);
    if (q < 0 || ro < 0) return 11;
    struct pollfd fds[2] = {{(int)q, POLLIN | POLLOUT, 0}, {(int)ro, POLLIN | POLLOUT, 0}};
    for (int round = 0; round < 3; round++) {
        long n = TRY(poll(fds, 2, 0));
        fd_set in, out;
        FD_ZERO(&in);
        FD_ZERO(&out);
        FD_SET(q, &in);
        FD_SET(q, &out);
        struct timeval zero = {0, 0};
        long s = TRY(select((int)q + 1, &in, &out, NULL, &zero));
        say("poll-%d: n=%ld revents=%x,%x select=%ld in=%d out=%d", round, n, fds[0].revents, fds[1].revents, s,
            FD_ISSET(q, &in) != 0, FD_ISSET(q, &out) != 0);
        if (round < 2) q_send(q, "m", 1, 0, NULL);
    }
    q_receive(q, 8, NULL);
    q_receive(q, 8, NULL);

    /* epoll, level- and edge-triggered: each send wakes the edge again. */
    int level = epoll_create1(EPOLL_CLOEXEC);
    int edge = epoll_create1(EPOLL_CLOEXEC);
    struct epoll_event e = {.events = EPOLLIN, .data.u64 = 1};
    long added = TRY(epoll_ctl(level, EPOLL_CTL_ADD, (int)q, &e));
    e.events = EPOLLIN | EPOLLET;
    long added_edge = TRY(epoll_ctl(edge, EPOLL_CTL_ADD, (int)q, &e));
    struct epoll_event out[4];
    say("epoll: add=%ld,%ld empty=%d,%d", added, added_edge, epoll_wait(level, out, 4, 0), epoll_wait(edge, out, 4, 0));
    q_send(q, "1", 1, 0, NULL);
    int l1 = epoll_wait(level, out, 4, 0);
    unsigned events = l1 > 0 ? out[0].events : 0;
    int e1 = epoll_wait(edge, out, 4, 0);
    int e2 = epoll_wait(edge, out, 4, 0);
    q_send(q, "2", 1, 0, NULL);
    int e3 = epoll_wait(edge, out, 4, 0);
    say("epoll: level=%d events=%x level-again=%d edge=%d,%d,%d", l1, events, epoll_wait(level, out, 4, 0), e1, e2, e3);
    q_receive(q, 8, NULL);
    q_receive(q, 8, NULL);
    say("epoll: drained=%d,%d", epoll_wait(level, out, 4, 0), epoll_wait(edge, out, 4, 0));

    /* A blocking poll and epoll_wait wake when another process sends. */
    pid_t pid = child();
    if (pid == 0) {
        pause_ms(100);
        q_send(q, "x", 1, 0, NULL);
        pause_ms(100);
        q_send(q, "y", 1, 0, NULL);
        _exit(0);
    }
    struct pollfd in = {(int)q, POLLIN, 0};
    long woke = TRY(poll(&in, 1, 5000));
    q_receive(q, 8, NULL);
    int edge_woke = epoll_wait(edge, out, 4, 5000);
    say("wake: poll=%ld revents=%x epoll=%d status=%d", woke, in.revents, edge_woke, wait_child(pid));
    q_unlink("p");
    return 0;
}

static int cookie_thread_value = -1;
static int notified[2];
static void thread_notified(union sigval value) {
    cookie_thread_value = value.sival_int;
    if (write(notified[1], "t", 1) != 1) _exit(92);
}

/* mq_notify: its checks, a signal, nothing, and netlink cookies. */
static int notify_case(void) {
    if (isolate()) return 10;
    struct mq_attr four = {.mq_maxmsg = 4, .mq_msgsize = 8};
    long q = q_open("n", O_RDWR | O_CREAT, 0600, &four);
    if (q < 0) return 11;
    pid_t self = getpid();
    sigset_t usr1;
    sigemptyset(&usr1);
    sigaddset(&usr1, SIGUSR1);
    sigprocmask(SIG_BLOCK, &usr1, NULL);
    struct timespec none = {0, 0};
    siginfo_t info;

    /* The checks: the notification, then the queue. */
    struct sigevent bad_kind = {.sigev_notify = 3};
    struct sigevent bad_signal = {.sigev_notify = SIGEV_SIGNAL, .sigev_signo = 65};
    struct sigevent no_signal = {.sigev_notify = SIGEV_SIGNAL, .sigev_signo = 0};
    int p[2];
    if (pipe(p)) return 12;
    int unix_socket = socket(AF_UNIX, SOCK_DGRAM, 0);
    static const char zeros[32];
    struct sigevent to_pipe = {.sigev_notify = SIGEV_THREAD, .sigev_signo = p[0], .sigev_value.sival_ptr = (void *)zeros};
    struct sigevent to_unix = to_pipe, to_nothing = to_pipe, bad_cookie = to_pipe;
    to_unix.sigev_signo = unix_socket;
    to_nothing.sigev_signo = 999;
    bad_cookie.sigev_value.sival_ptr = BAD;
    say("checks: kind=%ld kind-bad-fd=%ld signal=%ld fault=%ld bad-fd=%ld pipe=%ld",
        q_notify(q, &bad_kind), q_notify(-1, &bad_kind), q_notify(q, &bad_signal), q_notify(q, BAD),
        q_notify(-1, NULL), q_notify(p[0], NULL));
    say("checks: thread-pipe=%ld thread-unix=%ld thread-no-fd=%ld cookie-fault=%ld", q_notify(q, &to_pipe),
        q_notify(q, &to_unix), q_notify(q, &to_nothing), q_notify(q, &bad_cookie));
    printf("checks:");
    put("signal-zero", q_notify(q, &no_signal));
    put("busy", q_notify(q, &no_signal));
    put("unregister", q_notify(q, NULL));
    put("unregister-again", q_notify(q, NULL));
    say("");

    /* SIGEV_SIGNAL: a message to the empty queue sends it, once. */
    struct sigevent by_signal = {.sigev_notify = SIGEV_SIGNAL, .sigev_signo = SIGUSR1, .sigev_value.sival_int = 4242};
    say("signal: register=%ld", q_notify(q, &by_signal));
    show_line("signal-registered", q, self);
    q_send(q, "hello", 5, 3, NULL);
    memset(&info, 0, sizeof info);
    long number = TRY(sigtimedwait(&usr1, &info, &none));
    say("signal: number=%ld code=%d value=%d pid=%d uid=%d errno=%d", number, info.si_code, info.si_value.sival_int,
        info.si_pid == self, info.si_uid, info.si_errno);
    show_line("signal-sent", q, self);
    /* A message to a queue that is not empty tells no one. */
    say("signal: again=%ld", q_notify(q, &by_signal));
    q_send(q, "more", 4, 3, NULL);
    say("signal: not-empty=%ld", TRY(sigtimedwait(&usr1, &info, &none)));
    q_receive(q, 8, NULL);
    q_receive(q, 8, NULL);

    /* Another process is EBUSY, and its unregistering does nothing. */
    pid_t pid = child();
    if (pid == 0) {
        show_line("child-sees", q, getppid());
        printf("child:");
        put("busy", q_notify(q, &by_signal));
        put("unregister", q_notify(q, NULL));
        put("busy-still", q_notify(q, &by_signal));
        say("");
        _exit(0);
    }
    say("child: status=%d", wait_child(pid));

    /* A message straight to a waiting receiver tells no one either. */
    int waiting[2];
    if (pipe(waiting)) return 16;
    pid = child();
    if (pid == 0) {
        if (write(waiting[1], "w", 1) != 1) _exit(90);
        printf("waiting-receiver");
        show_receive("got", q, 8, NULL);
        say("");
        _exit(0);
    }
    char ready_byte;
    if (read(waiting[0], &ready_byte, 1) != 1) return 17;
    pause_ms(300);
    q_send(q, "direct", 6, 0, NULL);
    int receiver_status = wait_child(pid);
    say("receiver: status=%d signal=%ld", receiver_status, TRY(sigtimedwait(&usr1, &info, &none)));
    show_line("receiver", q, self);

    /* Closing any descriptor of the queue drops the owner's registration. */
    long copy = TRY(dup((int)q));
    close((int)copy);
    show_line("closed-dup", q, self);

    /* A child's registration ends with it. */
    pid = child();
    if (pid == 0) {
        long registered = q_notify(q, &by_signal);
        _exit(registered == 0 ? 0 : 1);
    }
    int exited = wait_child(pid);
    say("exited: status=%d register=%ld", exited, q_notify(q, &by_signal));
    q_notify(q, NULL);

    /* A child's registration signals the child, from its parent. */
    int ready[2];
    if (pipe(ready)) return 13;
    pid = child();
    if (pid == 0) {
        long registered = q_notify(q, &by_signal);
        if (write(ready[1], "r", 1) != 1) _exit(90);
        struct timespec wait = {5, 0};
        memset(&info, 0, sizeof info);
        long got = TRY(sigtimedwait(&usr1, &info, &wait));
        say("child-signal: register=%ld number=%ld code=%d parent=%d", registered, got, info.si_code,
            info.si_pid == getppid());
        _exit(0);
    }
    char byte;
    if (read(ready[0], &byte, 1) != 1) return 14;
    q_send(q, "to-child", 8, 0, NULL);
    say("child-signal: status=%d", wait_child(pid));
    q_receive(q, 8, NULL);

    /* SIGEV_NONE registers, and the message only ends it. */
    struct sigevent by_nothing = {.sigev_notify = SIGEV_NONE};
    say("none: register=%ld", q_notify(q, &by_nothing));
    show_line("none-registered", q, self);
    q_send(q, "n", 1, 0, NULL);
    show_line("none-sent", q, self);
    long none_signal = TRY(sigtimedwait(&usr1, &info, &none));
    say("none: signal=%ld again=%ld", none_signal, q_notify(q, &by_nothing));
    q_notify(q, NULL);
    q_receive(q, 8, NULL);

    /* SIGEV_THREAD by hand: the cookie goes to the netlink socket, its last
       byte 1 for a message and 2 when the registration is dropped. */
    int nl = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, 0);
    char cookie[32];
    memset(cookie, 'c', sizeof cookie);
    struct sigevent by_cookie = {.sigev_notify = SIGEV_THREAD, .sigev_signo = nl, .sigev_value.sival_ptr = cookie};
    say("cookie: socket=%d register=%ld", nl >= 0, q_notify(q, &by_cookie));
    show_line("cookie-registered", q, self);
    memset(cookie, 0, sizeof cookie);
    q_send(q, "c", 1, 0, NULL);
    unsigned char got[64] = {0};
    long n = TRY(recv(nl, got, sizeof got, MSG_DONTWAIT));
    say("cookie: received=%ld first=%c last=%d", n, got[0], got[31]);
    q_receive(q, 8, NULL);
    memset(cookie, 'd', sizeof cookie);
    q_notify(q, &by_cookie);
    say("cookie: unregister=%ld", q_notify(q, NULL));
    memset(got, 0, sizeof got);
    n = TRY(recv(nl, got, sizeof got, MSG_DONTWAIT));
    printf("cookie: received=%ld first=%c last=%d", n, got[0], got[31]);
    put("empty", TRY(recv(nl, got, sizeof got, MSG_DONTWAIT)));
    say("");

    /* A child's registration ends as it ends, and the socket it shares with
       its parent hears NOTIFY_REMOVED at once. */
    pid = child();
    if (pid == 0) {
        memset(cookie, 'e', sizeof cookie);
        _exit(q_notify(q, &by_cookie) == 0 ? 0 : 1);
    }
    int ended = wait_child(pid);
    memset(got, 0, sizeof got);
    n = TRY(recv(nl, got, sizeof got, MSG_DONTWAIT));
    say("cookie: child-status=%d on-exit=%ld first=%c last=%d", ended, n, got[0], got[31]);

    /* Through the C library, whose helper thread reads the cookie and
       runs the function. */
    if (pipe(notified)) return 15;
    struct sigevent by_thread = {.sigev_notify = SIGEV_THREAD, .sigev_notify_function = thread_notified,
                                 .sigev_value.sival_int = 77};
    say("thread: register=%d", mq_notify((mqd_t)q, &by_thread) == 0 ? 0 : -errno);
    q_send(q, "t", 1, 0, NULL);
    struct pollfd wake = {notified[0], POLLIN, 0};
    long woke = TRY(poll(&wake, 1, 5000));
    say("thread: woke=%ld value=%d", woke, cookie_thread_value);
    q_unlink("n");
    return 0;
}

/* A queue across fork: one open file description, shared. */
static int fork_case(void) {
    if (isolate()) return 10;
    struct mq_attr three = {.mq_maxmsg = 3, .mq_msgsize = 8};
    long q = q_open("f", O_RDWR | O_CREAT, 0600, &three);
    if (q < 0) return 11;
    q_send(q, "parent", 6, 1, NULL);
    pid_t pid = child();
    if (pid == 0) {
        printf("child");
        show_receive("got", q, 8, NULL);
        say(" send=%ld", q_send(q, "child", 5, 2, NULL));
        struct mq_attr nonblocking = {.mq_flags = O_NONBLOCK};
        say("child: setattr=%ld", q_attr(q, &nonblocking, NULL));
        long again = q_open("f", O_WRONLY, 0, NULL);
        long named = q_send(again, "named", 5, 3, NULL);
        say("child: by-name=%ld unlink=%ld", named, q_unlink("f"));
        _exit(0);
    }
    say("child: status=%d", wait_child(pid));
    show_attr("parent", q);
    printf("parent");
    show_receive("first", q, 8, NULL);
    show_receive("second", q, 8, NULL);
    show_receive("empty", q, 8, NULL);
    say("");
    say("parent: reopen=%ld", q_open("f", O_RDWR, 0, NULL));
    /* exec closes the queue's descriptor, which is close-on-exec. */
    say("cloexec=%d", fcntl(q, F_GETFD));
    return 0;
}

/* /proc/sys/fs/mqueue: a namespace's limits, how a write sets them, and
   what they change. */
static long sysctl_open(const char *name, int flags) {
    char path[96];
    snprintf(path, sizeof path, "/proc/sys/fs/mqueue/%s", name);
    return TRY(open(path, flags | O_CLOEXEC));
}
static long sysctl_value(const char *name) {
    char text[64] = {0};
    long fd = sysctl_open(name, O_RDONLY);
    if (fd < 0) return fd;
    long n = TRY(read((int)fd, text, sizeof text - 1));
    close((int)fd);
    return n < 0 ? n : strtol(text, NULL, 10);
}
/* A write of `text` to a newly opened file: its result, or the open's. */
static long sysctl_write(const char *name, const char *text) {
    long fd = sysctl_open(name, O_WRONLY);
    if (fd < 0) return fd;
    long n = TRY(write((int)fd, text, strlen(text)));
    close((int)fd);
    return n;
}
static void show_limits(const char *label) {
    printf("%s:", label);
    const char *names[] = {"queues_max", "msg_max", "msgsize_max", "msg_default", "msgsize_default"};
    for (int i = 0; i < 5; i++) put(names[i], sysctl_value(names[i]));
    say("");
}
static int name_order(const void *a, const void *b) { return strcmp(*(char *const *)a, *(char *const *)b); }
static void show_directory(const char *label, const char *path) {
    DIR *dir = opendir(path);
    if (!dir) {
        say("%s: opendir=%d", label, -errno);
        return;
    }
    char *names[32];
    int count = 0;
    struct dirent *e;
    while ((e = readdir(dir)) && count < 32) names[count++] = strdup(e->d_name);
    closedir(dir);
    qsort(names, count, sizeof *names, name_order);
    printf("%s:", label);
    for (int i = 0; i < count; i++) {
        printf(" %s", names[i]);
        free(names[i]);
    }
    say("");
}
/* Whether directory `path` lists `name` as a directory (1), as something
   else (2) or not at all (0); Linux lists more beside it. */
static int lists_directory(const char *path, const char *name) {
    DIR *dir = opendir(path);
    if (!dir) return -errno;
    int found = 0;
    struct dirent *e;
    while ((e = readdir(dir)))
        if (!strcmp(e->d_name, name)) found = e->d_type == DT_DIR ? 1 : 2;
    closedir(dir);
    return found;
}

static int sysctl_case(void) {
    if (isolate()) return 10;
    show_limits("defaults");
    show_directory("mqueue-dir", "/proc/sys/fs/mqueue");
    struct stat st;
    long stated = TRY(stat("/proc/sys/fs/mqueue/msg_max", &st));
    printf("stat: file=%ld mode=%o uid=%d gid=%d", stated, st.st_mode, st.st_uid, st.st_gid);
    stated = TRY(stat("/proc/sys/fs/mqueue", &st));
    say(" dir=%ld directory=%d perms=%o", stated, S_ISDIR(st.st_mode), st.st_mode & 07777);
    printf("open:");
    put("dir-write", TRY(open("/proc/sys/fs/mqueue", O_WRONLY)));
    put("missing", sysctl_open("missing", O_RDONLY));
    put("proc-lists-sys", lists_directory("/proc", "sys"));
    put("sys-lists-fs", lists_directory("/proc/sys", "fs"));
    put("fs-lists-mqueue", lists_directory("/proc/sys/fs", "mqueue"));
    say("");

    /* What a write takes, and what it consumes. */
    printf("msg_max:");
    put("set", sysctl_write("msg_max", "20\n"));
    put("now", sysctl_value("msg_max"));
    const char *bad[] = {"0", "65537", "-1", "abc", "5x", "09", "0x", " \n", "2147483648",
                         "99999999999999999999999", "000000000000000000001"};
    for (unsigned i = 0; i < sizeof bad / sizeof *bad; i++) put(bad[i][0] == ' ' ? "spaces" : bad[i],
                                                                 sysctl_write("msg_max", bad[i]));
    put("still", sysctl_value("msg_max"));
    say("");
    printf("msg_max:");
    put("padded", sysctl_write("msg_max", "  30  \n"));
    put("now", sysctl_value("msg_max"));
    put("two", sysctl_write("msg_max", "5 6\n"));
    put("now", sysctl_value("msg_max"));
    put("hex", sysctl_write("msg_max", "0x10"));
    put("now", sysctl_value("msg_max"));
    put("octal", sysctl_write("msg_max", "010"));
    put("now", sysctl_value("msg_max"));
    put("empty", sysctl_write("msg_max", ""));
    put("highest", sysctl_write("msg_max", "65536"));
    put("now", sysctl_value("msg_max"));
    say("");
    /* A second write goes past the start, and changes nothing; a read past
       the start gives nothing. */
    long fd = sysctl_open("msg_default", O_RDWR);
    printf("position:");
    put("first", TRY(write((int)fd, "7", 1)));
    put("second", TRY(write((int)fd, "9", 1)));
    lseek((int)fd, 0, SEEK_SET);
    char text[8] = {0};
    put("read-one", TRY(read((int)fd, text, 1)));
    printf(" [%s]", text);
    put("read-rest", TRY(read((int)fd, text, sizeof text)));
    put("seek-end", TRY(lseek((int)fd, 0, SEEK_END)));
    say("");
    close((int)fd);
    printf("msgsize_max:");
    put("below", sysctl_write("msgsize_max", "127"));
    put("least", sysctl_write("msgsize_max", "128"));
    put("above", sysctl_write("msgsize_max", "16777217"));
    put("highest", sysctl_write("msgsize_max", "16777216"));
    say("");
    printf("queues_max:");
    put("negative", sysctl_write("queues_max", "-5"));
    put("now", sysctl_value("queues_max"));
    put("huge", sysctl_write("queues_max", "2147483647"));
    put("now", sysctl_value("queues_max"));
    say("");

    /* What the limits change: the defaults a queue without attributes
       takes, the smaller of each default and its limit. */
    sysctl_write("msg_max", "20");
    sysctl_write("msgsize_max", "1000");
    sysctl_write("msg_default", "5");
    sysctl_write("msgsize_default", "300");
    show_limits("set");
    long q = q_open("d", O_RDWR | O_CREAT, 0600, NULL);
    show_attr("defaults-5-300", q);
    close((int)q);
    q_unlink("d");
    sysctl_write("msg_default", "30");
    sysctl_write("msgsize_default", "5000");
    q = q_open("d", O_RDWR | O_CREAT, 0600, NULL);
    show_attr("defaults-above-limits", q);
    close((int)q);
    q_unlink("d");
    /* Root passes the limits up to the hard ones. */
    struct mq_attr above = {.mq_maxmsg = 21, .mq_msgsize = 1001};
    q = q_open("root", O_RDWR | O_CREAT, 0600, &above);
    say("root: above-limits=%d", q >= 0);
    close((int)q);
    q_unlink("root");
    sysctl_write("queues_max", "3");

    pid_t pid = child();
    if (pid == 0) {
        if (unprivileged()) _exit(90);
        struct mq_attr most = {.mq_maxmsg = 20, .mq_msgsize = 1000};
        struct mq_attr more = {.mq_maxmsg = 21, .mq_msgsize = 1000};
        struct mq_attr larger = {.mq_maxmsg = 20, .mq_msgsize = 1001};
        printf("user:");
        put("open-write", sysctl_open("msg_max", O_WRONLY));
        put("open-read-write", sysctl_open("msg_max", O_RDWR));
        put("read", sysctl_value("msg_max"));
        long m = q_open("most", O_RDWR | O_CREAT, 0600, &most);
        put("most", m >= 0);
        put("more", q_open("x", O_RDWR | O_CREAT, 0600, &more));
        put("larger", q_open("x", O_RDWR | O_CREAT, 0600, &larger));
        close((int)m);
        q_unlink("most");
        char name[16];
        int made = 0;
        long error = 0;
        struct mq_attr one = {.mq_maxmsg = 1, .mq_msgsize = 1};
        for (; made < 10; made++) {
            snprintf(name, sizeof name, "u%d", made);
            long fd = q_open(name, O_RDWR | O_CREAT, 0600, &one);
            if (fd < 0) {
                error = fd;
                break;
            }
            close((int)fd);
        }
        put("made", made);
        put("then", error);
        say("");
        _exit(0);
    }
    say("user: status=%d", wait_child(pid));
    /* A new IPC namespace starts from the defaults again. */
    pid = child();
    if (pid == 0) {
        if (unshare(CLONE_NEWIPC)) _exit(90);
        show_limits("new-namespace");
        _exit(0);
    }
    say("new-namespace: status=%d", wait_child(pid));
    show_limits("this-namespace");
    return 0;
}

/* RLIMIT_MSGQUEUE in a user namespace: a queue charges its user there
   against its own limit, and the namespace's owner in the parent against
   the limit the owner had when it made the namespace. */
static long make_tiny_queues(const char *prefix, int most) {
    struct mq_attr one = {.mq_maxmsg = 1, .mq_msgsize = 1};
    char name[32];
    for (int made = 0; made < most; made++) {
        snprintf(name, sizeof name, "%s%d", prefix, made);
        long fd = q_open(name, O_RDWR | O_CREAT, 0600, &one);
        if (fd < 0) {
            printf(" made=%d then=%ld", made, fd);
            return made;
        }
    }
    printf(" made=%d", most);
    return most;
}
static void unlink_tiny_queues(const char *prefix, int count) {
    char name[32];
    for (int i = 0; i < count; i++) {
        snprintf(name, sizeof name, "%s%d", prefix, i);
        q_unlink(name);
    }
}
static int accounts_case(void) {
    if (isolate()) return 10;
    struct rlimit standard = {819200, 819200};
    if (setrlimit(RLIMIT_MSGQUEUE, &standard)) return 11;
    /* Root charges 30 queues of 97 bytes to itself. */
    printf("root:");
    long rooted = make_tiny_queues("r", 30);
    say("");
    for (int round = 0; round < 2; round++) {
        pid_t pid = child();
        if (pid == 0) {
            /* Round 0 makes the namespace with a large limit, then lowers
               its own; round 1 makes it with a small one, then raises its
               own back. */
            struct rlimit before = {round == 0 ? 100000 : 3000, 819200};
            struct rlimit after = {round == 0 ? 1000 : 819200, 819200};
            if (setrlimit(RLIMIT_MSGQUEUE, &before)) _exit(90);
            if (unshare(CLONE_NEWUSER)) _exit(91);
            if (setrlimit(RLIMIT_MSGQUEUE, &after)) _exit(92);
            printf("nested-%d:", round);
            long made = make_tiny_queues(round == 0 ? "a" : "b", 40);
            say("");
            unlink_tiny_queues(round == 0 ? "a" : "b", (int)made);
            _exit(0);
        }
        say("nested-%d: status=%d", round, wait_child(pid));
    }
    /* What the nested users made is given back. */
    printf("root-again:");
    long more = make_tiny_queues("s", 5);
    say("");
    unlink_tiny_queues("s", (int)more);
    unlink_tiny_queues("r", (int)rooted);
    return 0;
}

/* Sleeps into the next second of the realtime clock, 100 ms past its
   start, so that what a call stamps after it is later than anything stamped
   before; returns that second. */
static long long next_second(void) {
    struct timespec now;
    clock_gettime(CLOCK_REALTIME, &now);
    pause_ms((1000000000 - now.tv_nsec) / 1000000 + 100);
    clock_gettime(CLOCK_REALTIME, &now);
    return now.tv_sec;
}
static long long this_second(void) {
    struct timespec now;
    clock_gettime(CLOCK_REALTIME, &now);
    return now.tv_sec;
}
/* Whether `stamp` is a whole second from `from` to `to`, as a call made
   between reading them stamps it, however long it took. */
static int stamped_between(long long stamp, long long from, long long to) {
    return stamp % 1000000000LL == 0 && stamp >= from * 1000000000LL && stamp <= to * 1000000000LL;
}
static long long mtime_of(long fd) {
    struct stat st;
    if (fstat((int)fd, &st)) return -errno;
    return (long long)st.st_mtim.tv_sec * 1000000000LL + st.st_mtim.tv_nsec;
}
static int write_text(const char *path, const char *text) {
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0) return -errno;
    long n = write(fd, text, strlen(text));
    int error = n < 0 ? -errno : 0;
    close(fd);
    return error;
}
/* A queue's file: its modification time, which a send and a receive set
   and nothing else changes, to the second, as the mqueue filesystem keeps
   its times, and the mqueue root, which belongs to whoever made the
   IPC namespace and lets them unlink anyone's queue. */
static int files_case(void) {
    if (isolate()) return 10;
    struct mq_attr one = {.mq_maxmsg = 1, .mq_msgsize = 8};
    long long second = next_second();
    long q = q_open("t", O_RDWR | O_CREAT | O_NONBLOCK, 0600, &one);
    if (q < 0) return 11;
    long long made = mtime_of(q);
    printf("mtime:");
    put("made-stamped", stamped_between(made, second, this_second()));
    next_second();
    struct mq_attr old;
    q_attr(q, NULL, &old);
    struct sigevent none = {.sigev_notify = SIGEV_NONE};
    q_notify(q, &none);
    q_notify(q, NULL);
    fchmod((int)q, 0640);
    char line[100];
    lseek((int)q, 0, SEEK_SET);
    if (read((int)q, line, sizeof line) < 0) return 12;
    put("attr-notify-chmod-read-keep", mtime_of(q) == made);
    second = next_second();
    q_send(q, "a", 1, 0, NULL);
    long long sent = mtime_of(q);
    put("send-stamps", stamped_between(sent, second, this_second()));
    next_second();
    put("full", q_send(q, "b", 1, 0, NULL));
    put("failed-send-keeps", mtime_of(q) == sent);
    second = next_second();
    q_receive(q, 8, NULL);
    long long received = mtime_of(q);
    put("receive-stamps", stamped_between(received, second, this_second()));
    next_second();
    put("empty", q_receive(q, 8, NULL));
    put("failed-receive-keeps", mtime_of(q) == received);
    say("");
    close((int)q);
    q_unlink("t");

    /* A child in a user namespace whose 0, 1 and 2 are users 2000 to 2002
       makes an IPC namespace as its 0; its 1 makes a queue there, which
       its 2 may not unlink and its 0, without capabilities, may. */
    int ready[2], mapped[2];
    if (pipe(ready) || pipe(mapped)) return 13;
    pid_t pid = child();
    if (pid == 0) {
        char byte;
        if (unshare(CLONE_NEWUSER)) _exit(90);
        if (write(ready[1], "u", 1) != 1) _exit(91);
        if (read(mapped[0], &byte, 1) != 1) _exit(92);
        if (syscall(SYS_setresgid, 0, 0, 0) || syscall(SYS_setresuid, 0, 0, 0)) _exit(93);
        if (unshare(CLONE_NEWIPC)) _exit(94);
        for (int user = 1; user <= 2; user++) {
            pid_t other = fork();
            if (other == 0) {
                if (syscall(SYS_setresgid, user, user, user) || syscall(SYS_setresuid, user, user, user)) _exit(90);
                if (user == 1) {
                    long fd = q_open("theirs", O_RDWR | O_CREAT, 0600, &one);
                    _exit(fd >= 0 ? 0 : 1);
                }
                _exit(q_unlink("theirs") == -EPERM ? 0 : 1);
            }
            say("namespace: user-%d status=%d", user, wait_child(other));
        }
        /* No capabilities left, so only owning the root lets it. */
        struct {
            unsigned version;
            int pid;
        } header = {0x20080522, 0};
        unsigned data[6] = {0};
        if (syscall(SYS_capset, &header, data)) _exit(95);
        printf("namespace:");
        put("root-owner-unlinks", q_unlink("theirs"));
        put("again", q_unlink("theirs"));
        say("");
        _exit(0);
    }
    char byte;
    if (read(ready[0], &byte, 1) != 1) return 14;
    char path[64];
    snprintf(path, sizeof path, "/proc/%d/uid_map", pid);
    int uid_map = write_text(path, "0 2000 3");
    snprintf(path, sizeof path, "/proc/%d/gid_map", pid);
    int gid_map = write_text(path, "0 2000 3");
    say("maps: uid=%d gid=%d", uid_map, gid_map);
    if (write(mapped[1], "m", 1) != 1) return 15;
    say("namespace: status=%d", wait_child(pid));
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) return 2;
    const char *mode = argv[1];
    if (!strcmp(mode, "mqueue-calls")) return calls_case();
    if (!strcmp(mode, "mqueue-limits")) return limits_case();
    if (!strcmp(mode, "mqueue-wait")) return wait_case();
    if (!strcmp(mode, "mqueue-poll")) return poll_case();
    if (!strcmp(mode, "mqueue-notify")) return notify_case();
    if (!strcmp(mode, "mqueue-fork")) return fork_case();
    if (!strcmp(mode, "mqueue-sysctl")) return sysctl_case();
    if (!strcmp(mode, "mqueue-accounts")) return accounts_case();
    if (!strcmp(mode, "mqueue-files")) return files_case();
    return 3;
}
