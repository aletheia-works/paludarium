/* POSIX message queues, compared with Linux: mq_open, mq_unlink,
   mq_timedsend, mq_timedreceive, mq_notify and mq_getsetattr, their errors
   in Linux's order, priorities, O_NONBLOCK and timeouts, the default and
   unprivileged limits and the /proc/sys/fs/mqueue files that set them, poll, select and epoll on a queue, notifications by
   signal, by nothing and by netlink cookie, and queues shared across fork;
   the queues' files, and /dev/mqueue with the calls on its paths (chmod,
   chown, the times, truncate and statfs).

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
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/sysmacros.h>
#include <sys/syscall.h>
#include <sys/time.h>
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

/* /dev/mqueue, where the first IPC namespace's queues are mounted, as
   systemd mounts them: what it lists, what its files are, and opening,
   making and unlinking queues through it. It runs in the first namespace,
   which on Linux is the host's, so it looks only at its own names. */
#define DEV_NAME "paludarium-mqueue-dev"
static int listed_type(const char *name) {
    DIR *dir = opendir("/dev/mqueue");
    if (!dir) return -errno;
    int found = 0;
    struct dirent *e;
    while ((e = readdir(dir)))
        if (!strcmp(e->d_name, name)) found = e->d_type;
    closedir(dir);
    return found;
}
static void show_dev_link(const char *label, long fd) {
    char path[64], target[300] = {0};
    snprintf(path, sizeof path, "/proc/self/fd/%ld", fd);
    long n = TRY(readlink(path, target, sizeof target - 1));
    say("%s: readlink=%ld [%s]", label, n, n > 0 ? target : "");
}
static long long stat_mtime(const char *path) {
    struct stat st;
    if (stat(path, &st)) return -errno;
    return (long long)st.st_mtim.tv_sec * 1000000000LL + st.st_mtim.tv_nsec;
}
static long stat_size(const char *path) {
    struct stat st;
    if (stat(path, &st)) return -errno;
    return (long)st.st_size;
}
static long fd_size(long fd) {
    struct stat st;
    if (fstat((int)fd, &st)) return -errno;
    return (long)st.st_size;
}
static void show_file(const char *label, const char *path) {
    struct stat st = {0};
    long stated = TRY(stat(path, &st));
    say("%s: stat=%ld mode=%o uid=%d gid=%d size=%ld", label, stated, st.st_mode, st.st_uid, st.st_gid,
        (long)st.st_size);
}
static void show_statfs(const char *label, long result, const struct statfs *s) {
    say("%s: statfs=%ld type=%lx bsize=%ld namelen=%ld frsize=%ld blocks=%ld bfree=%ld files=%ld", label, result,
        (long)s->f_type, (long)s->f_bsize, (long)s->f_namelen, (long)s->f_frsize, (long)s->f_blocks,
        (long)s->f_bfree, (long)s->f_files);
}
#define ATTRS_NAME DEV_NAME "-attrs"
#define ATTRS_PATH "/dev/mqueue/" ATTRS_NAME
#define DEV_PATH(suffix) "/dev/mqueue/" DEV_NAME suffix
/* Making and moving names in /dev/mqueue, whose root has only the
   operations to look up, make (a queue) and unlink: mkdir, symlink and
   mknod of anything but a regular file are EPERM once the name is free,
   mknod of a regular file makes a queue, and link and rename are EXDEV
   to or from another mount and EPERM within it. ATTRS_PATH is a queue. */
static int dev_names(void) {
    const char *made[] = {"-dir", "-sym", "-fifo", "-chr", "-node", "-zero", "-link", "-moved", "-in", "-fresh"};
    for (unsigned i = 0; i < sizeof made / sizeof *made; i++) {
        char name[128];
        snprintf(name, sizeof name, DEV_NAME "%s", made[i]);
        q_unlink(name);
    }
    printf("make:");
    put("mkdir", TRY(mkdir(DEV_PATH("-dir"), 0700)));
    put("mkdir-there", TRY(mkdir(ATTRS_PATH, 0700)));
    put("mkdir-root", TRY(mkdir("/dev/mqueue", 0700)));
    put("symlink-root", TRY(symlink("target", "/dev/mqueue")));
    put("mknod-root", TRY(mknod("/dev/mqueue", S_IFREG | 0600, 0)));
    put("symlink", TRY(symlink("target", DEV_PATH("-sym"))));
    put("symlink-there", TRY(symlink("target", ATTRS_PATH)));
    put("fifo", TRY(mknod(DEV_PATH("-fifo"), S_IFIFO | 0600, 0)));
    put("chr", TRY(mknod(DEV_PATH("-chr"), S_IFCHR | 0600, makedev(1, 3))));
    put("dir", TRY(mknod(DEV_PATH("-dir"), S_IFDIR | 0700, 0)));
    put("bad-type", TRY(mknod(DEV_PATH("-dir"), 0170000 | 0700, 0)));
    put("fifo-there", TRY(mknod(ATTRS_PATH, S_IFIFO | 0600, 0)));
    put("listed", listed_type(DEV_NAME "-dir") + listed_type(DEV_NAME "-sym") + listed_type(DEV_NAME "-fifo") +
                      listed_type(DEV_NAME "-chr"));
    say("");
    mode_t mask = umask(027);
    printf("mknod:");
    put("regular", TRY(mknod(DEV_PATH("-node"), S_IFREG | 0666, 0)));
    put("type", listed_type(DEV_NAME "-node"));
    struct stat st = {0};
    put("stat", TRY(stat(DEV_PATH("-node"), &st)));
    printf(" mode=%o", st.st_mode);
    put("zero-type", TRY(mknod(DEV_PATH("-zero"), 0600, 0)));
    put("again", TRY(mknod(DEV_PATH("-node"), S_IFREG | 0600, 0)));
    say("");
    umask(mask);
    long node = q_open(DEV_NAME "-node", O_RDONLY, 0, NULL);
    show_attr("node", node);
    close((int)node);

    char dir[] = "/tmp/mqueue-dev-XXXXXX";
    if (!mkdtemp(dir)) return 1;
    char file[64], other[64], none[64];
    snprintf(file, sizeof file, "%s/file", dir);
    snprintf(other, sizeof other, "%s/other", dir);
    snprintf(none, sizeof none, "%s/none/x", dir);
    int fd = open(file, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0) return 2;
    close(fd);
    printf("link:");
    put("inside", TRY(link(ATTRS_PATH, DEV_PATH("-link"))));
    put("onto", TRY(link(ATTRS_PATH, DEV_PATH("-node"))));
    put("missing", TRY(link(DEV_PATH("-none"), DEV_PATH("-link"))));
    put("follow", TRY(linkat(AT_FDCWD, ATTRS_PATH, AT_FDCWD, DEV_PATH("-link"), AT_SYMLINK_FOLLOW)));
    put("out", TRY(link(ATTRS_PATH, other)));
    put("out-onto", TRY(link(ATTRS_PATH, file)));
    put("in", TRY(link(file, DEV_PATH("-in"))));
    put("in-missing", TRY(link(other, DEV_PATH("-in"))));
    put("in-onto", TRY(link(file, ATTRS_PATH)));
    long by_name = q_open(ATTRS_NAME, O_RDONLY, 0, NULL);
    long by_path = TRY(open(ATTRS_PATH, O_RDONLY | O_CLOEXEC));
    put("empty-mq_open", TRY(linkat((int)by_name, "", AT_FDCWD, DEV_PATH("-link"), AT_EMPTY_PATH)));
    put("empty-opened", TRY(linkat((int)by_path, "", AT_FDCWD, DEV_PATH("-link"), AT_EMPTY_PATH)));
    put("empty-onto", TRY(linkat((int)by_path, "", AT_FDCWD, DEV_PATH("-node"), AT_EMPTY_PATH)));
    close((int)by_name);
    close((int)by_path);
    put("listed", listed_type(DEV_NAME "-link") + listed_type(DEV_NAME "-in"));
    say("");
    printf("rename:");
    put("inside", TRY(rename(ATTRS_PATH, DEV_PATH("-moved"))));
    put("onto", TRY(rename(ATTRS_PATH, DEV_PATH("-node"))));
    put("itself", TRY(rename(ATTRS_PATH, ATTRS_PATH)));
    put("missing", TRY(rename(DEV_PATH("-none"), DEV_PATH("-moved"))));
    put("noreplace", TRY(syscall(SYS_renameat2, AT_FDCWD, ATTRS_PATH, AT_FDCWD, DEV_PATH("-node"), 1)));
    put("noreplace-itself", TRY(syscall(SYS_renameat2, AT_FDCWD, ATTRS_PATH, AT_FDCWD, ATTRS_PATH, 1)));
    put("exchange-missing", TRY(syscall(SYS_renameat2, AT_FDCWD, ATTRS_PATH, AT_FDCWD, DEV_PATH("-none"), 2)));
    put("exchange", TRY(syscall(SYS_renameat2, AT_FDCWD, ATTRS_PATH, AT_FDCWD, DEV_PATH("-node"), 2)));
    put("out", TRY(rename(ATTRS_PATH, other)));
    put("out-missing", TRY(rename(DEV_PATH("-none"), other)));
    put("in", TRY(rename(file, DEV_PATH("-in"))));
    put("in-no-directory", TRY(rename(none, DEV_PATH("-in"))));
    put("listed", listed_type(DEV_NAME "-moved") + listed_type(DEV_NAME "-in"));
    put("kept", listed_type(ATTRS_NAME));
    say("");
    /* Under a Landlock domain that handles making and removing regular
       files and allows them nowhere, Landlock refuses a link, a rename
       (onto itself too), a mknod and an unlink within the root (EACCES)
       before the root's own EPERM; a link out of it is EXDEV first. */
    pid_t pid = child();
    if (pid == 0) {
        unsigned long long handled = (1ULL << 8) | (1ULL << 5);
        long ruleset = syscall(444, &handled, sizeof handled, 0);
        if (ruleset < 0) _exit(90);
        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) || syscall(446, ruleset, 0)) _exit(91);
        printf("landlock:");
        put("link", TRY(link(ATTRS_PATH, DEV_PATH("-link"))));
        put("rename", TRY(rename(ATTRS_PATH, DEV_PATH("-moved"))));
        put("rename-itself", TRY(rename(ATTRS_PATH, ATTRS_PATH)));
        put("link-out", TRY(link(ATTRS_PATH, other)));
        put("mkdir", TRY(mkdir(DEV_PATH("-dir"), 0700)));
        put("mknod", TRY(mknod(DEV_PATH("-fresh"), S_IFREG | 0600, 0)));
        put("unlink", TRY(unlink(DEV_PATH("-node"))));
        say("");
        _exit(0);
    }
    say("landlock: status=%d", wait_child(pid));
    unlink(file);
    rmdir(dir);
    q_unlink(DEV_NAME "-node");
    q_unlink(DEV_NAME "-zero");
    return 0;
}

/* What an unprivileged user (2000) may do in /dev/mqueue, which it may
   search, read and write as the root's mode says. */
static void as_user(const char *label) {
    pid_t pid = child();
    if (pid == 0) {
        if (unprivileged()) _exit(90);
        printf("%s:", label);
        struct stat st;
        put("stat", TRY(stat(DEV_PATH("-root"), &st)));
        long d = TRY(open("/dev/mqueue", O_RDONLY | O_DIRECTORY | O_CLOEXEC));
        put("open-dir", d < 0 ? d : 0);
        long q = q_open(DEV_NAME "-root", O_RDONLY, 0, NULL);
        put("mq_open", q < 0 ? q : 0);
        long made = q_open(DEV_NAME "-theirs", O_RDWR | O_CREAT, 0600, NULL);
        put("create", made < 0 ? made : 0);
        put("open-create", TRY(open(DEV_PATH("-theirs2"), O_RDWR | O_CREAT | O_CLOEXEC, 0600)) < 0 ? -errno : 0);
        put("mkdir", TRY(mkdir(DEV_PATH("-theirs3"), 0700)));
        put("symlink", TRY(symlink("target", DEV_PATH("-theirs3"))));
        put("fifo", TRY(mknod(DEV_PATH("-theirs3"), S_IFIFO | 0600, 0)));
        put("link", TRY(link(DEV_PATH("-shared"), DEV_PATH("-theirs3"))));
        put("rename", TRY(rename(DEV_PATH("-root"), DEV_PATH("-theirs3"))));
        put("rename-itself", TRY(rename(DEV_PATH("-root"), DEV_PATH("-root"))));
        say("");
        _exit(0);
    }
    say("%s: status=%d", label, wait_child(pid));
    q_unlink(DEV_NAME "-theirs");
    q_unlink(DEV_NAME "-theirs2");
}

/* The root itself: chmod, chown, the times and fchmod of an open of it,
   which change what others may do there; mq_open of a queue that is
   there does not search it (lookup_noperm), while making and unlinking
   one need to write and search it. Its mode, owner and time are put back
   at the end, as this is the host's /dev/mqueue on Linux. Then a queue
   opened again through its link in /proc/self/fd. */
static int dev_root(void) {
    struct stat st;
    if (stat("/dev/mqueue", &st)) return 31;
    mode_t mode = st.st_mode & 07777;
    uid_t uid = st.st_uid;
    gid_t gid = st.st_gid;
    struct timespec kept[2] = {{.tv_sec = 0, .tv_nsec = UTIME_OMIT}, st.st_mtim};
    q_unlink(DEV_NAME "-root");
    long q = q_open(DEV_NAME "-root", O_RDWR | O_CREAT, 0644, NULL);
    if (q < 0) return 32;
    /* One anyone may read and write, which another user may link
       whatever fs.protected_hardlinks is, so that link fails on the root. */
    q_unlink(DEV_NAME "-shared");
    long shared = q_open(DEV_NAME "-shared", O_RDWR | O_CREAT, 0600, NULL);
    if (shared < 0 || fchmod((int)shared, 0666)) return 34;
    printf("root-chmod:");
    put("0755", TRY(chmod("/dev/mqueue", 0755)));
    stat("/dev/mqueue", &st);
    printf(" mode=%o", st.st_mode);
    say("");
    as_user("user-0755");
    chmod("/dev/mqueue", 0711);
    as_user("user-0711");
    chmod("/dev/mqueue", 0700);
    as_user("user-0700");
    close((int)shared);
    q_unlink(DEV_NAME "-shared");
    long d = TRY(open("/dev/mqueue", O_RDONLY | O_DIRECTORY | O_CLOEXEC));
    printf("root-fd:");
    put("fchmod", TRY(fchmod((int)d, 0777)));
    stat("/dev/mqueue", &st);
    printf(" mode=%o", st.st_mode);
    say("");
    /* Without the sticky bit, another user may unlink root's queue. */
    pid_t pid = child();
    if (pid == 0) {
        if (unprivileged()) _exit(90);
        printf("unsticky:");
        put("unlink", TRY(unlink(DEV_PATH("-root"))));
        say("");
        _exit(0);
    }
    say("unsticky: status=%d", wait_child(pid));
    printf("root-owner:");
    put("chown", TRY(chown("/dev/mqueue", 2000, 3000)));
    stat("/dev/mqueue", &st);
    printf(" uid=%d gid=%d", st.st_uid, st.st_gid);
    put("fchown", TRY(fchown((int)d, uid, gid)));
    struct timespec times[2] = {{.tv_sec = 0, .tv_nsec = UTIME_OMIT}, {.tv_sec = 1234567, .tv_nsec = 5}};
    put("utimensat", TRY(utimensat(AT_FDCWD, "/dev/mqueue", times, 0)));
    put("mtime-s", stat_mtime("/dev/mqueue") / 1000000000LL);
    put("mtime-ns", stat_mtime("/dev/mqueue") % 1000000000LL);
    put("truncate", TRY(truncate("/dev/mqueue", 0)));
    put("chmod-back", TRY(chmod("/dev/mqueue", mode)));
    put("times-back", TRY(utimensat(AT_FDCWD, "/dev/mqueue", kept, 0)));
    stat("/dev/mqueue", &st);
    put("mode-back", (st.st_mode & 07777) == mode);
    put("owner-back", st.st_uid == uid && st.st_gid == gid);
    say("");
    close((int)d);
    close((int)q);

    /* A queue opened again through its link in /proc/self/fd. */
    q_unlink(DEV_NAME "-reopen");
    struct mq_attr small = {.mq_maxmsg = 2, .mq_msgsize = 8};
    q = q_open(DEV_NAME "-reopen", O_RDWR | O_CREAT, 0600, &small);
    if (q < 0) return 33;
    ftruncate((int)q, 100);
    char path[64];
    snprintf(path, sizeof path, "/proc/self/fd/%ld", q);
    long again = TRY(open(path, O_RDWR | O_CLOEXEC));
    printf("reopen:");
    put("open", again >= 0);
    put("send", q_send(again, "hi", 2, 1, NULL));
    say("");
    show_attr("reopen", again);
    show_link("reopen", again);
    printf("reopen:");
    put("directory", TRY(open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC)));
    long trunc = TRY(open(path, O_RDONLY | O_TRUNC | O_CLOEXEC));
    put("o_trunc", trunc >= 0);
    put("size", fd_size(q));
    close((int)trunc);
    say("");
    pid = child();
    if (pid == 0) {
        if (unprivileged()) _exit(90);
        printf("reopen-user:");
        put("open", TRY(open(path, O_RDONLY | O_CLOEXEC)) < 0 ? -errno : 0);
        say("");
        _exit(0);
    }
    say("reopen-user: status=%d", wait_child(pid));
    close((int)again);
    close((int)q);
    q_unlink(DEV_NAME "-reopen");
    return 0;
}
/* The calls on a queue's path in /dev/mqueue, which change its file as
   simple_setattr does: its mode and owner, its modification time (to the
   second, and only that time is compared), and its size, which only a
   truncate changes; then statfs, and the root, whose size counts its
   entries and whose time a queue made or unlinked in it stamps. */
static int dev_paths(void) {
    q_unlink(ATTRS_NAME);
    struct stat root;
    if (stat("/dev/mqueue", &root)) return 21;
    long base = (long)root.st_size;
    long long second = next_second();
    long q = q_open(ATTRS_NAME, O_RDWR | O_CREAT | O_EXCL, 0640, NULL);
    if (q < 0) return 22;
    printf("root:");
    put("made-grows", stat_size("/dev/mqueue") - base);
    put("made-stamped", stamped_between(stat_mtime("/dev/mqueue"), second, this_second()));
    long long made = stat_mtime("/dev/mqueue");
    next_second();
    long again = q_open(ATTRS_NAME, O_RDWR, 0, NULL);
    put("open-keeps", stat_mtime("/dev/mqueue") == made);
    put("size-kept", stat_size("/dev/mqueue") - base);
    say("");
    close((int)again);

    printf("chmod:");
    put("path", TRY(chmod(ATTRS_PATH, 04750)));
    put("missing", TRY(chmod(ATTRS_PATH "-none", 0600)));
    put("long", TRY(chmod("/dev/mqueue/"
                          "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                          "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                          "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                          0600)));
    say("");
    show_file("chmod", ATTRS_PATH);
    printf("chown:");
    put("path", TRY(chown(ATTRS_PATH, 2000, 3000)));
    say("");
    show_file("chown", ATTRS_PATH);
    printf("chown:");
    put("lchown", TRY(lchown(ATTRS_PATH, -1, 3001)));
    put("fchownat", TRY(fchownat(AT_FDCWD, ATTRS_PATH, 2001, -1, AT_SYMLINK_NOFOLLOW)));
    put("fchmodat", TRY(fchmodat(AT_FDCWD, ATTRS_PATH, 0640, 0)));
    put("missing", TRY(chown(ATTRS_PATH "-none", 0, 0)));
    say("");
    show_file("owned", ATTRS_PATH);

    struct timespec times[2] = {{.tv_sec = 1000, .tv_nsec = 0}, {.tv_sec = 1234567, .tv_nsec = 890}};
    printf("times:");
    put("utimensat", TRY(utimensat(AT_FDCWD, ATTRS_PATH, times, 0)));
    put("mtime-s", stat_mtime(ATTRS_PATH) / 1000000000LL);
    put("mtime-ns", stat_mtime(ATTRS_PATH) % 1000000000LL);
    struct timespec omit[2] = {{.tv_sec = 5, .tv_nsec = 0}, {.tv_sec = 0, .tv_nsec = UTIME_OMIT}};
    put("omit", TRY(utimensat(AT_FDCWD, ATTRS_PATH, omit, AT_SYMLINK_NOFOLLOW)));
    put("omit-keeps", stat_mtime(ATTRS_PATH) == 1234567000000000LL);
    struct timespec by_fd[2] = {{.tv_sec = 0, .tv_nsec = UTIME_OMIT}, {.tv_sec = 2000000, .tv_nsec = 5}};
    put("futimens", TRY(futimens((int)q, by_fd)));
    put("futimens-s", mtime_of(q) / 1000000000LL);
    struct timeval micros[2] = {{.tv_sec = 1, .tv_usec = 0}, {.tv_sec = 3000000, .tv_usec = 999999}};
    put("utimes", TRY(utimes(ATTRS_PATH, micros)));
    put("utimes-s", stat_mtime(ATTRS_PATH) / 1000000000LL);
    put("utimes-ns", stat_mtime(ATTRS_PATH) % 1000000000LL);
    put("missing", TRY(utimensat(AT_FDCWD, ATTRS_PATH "-none", NULL, 0)));
    second = next_second();
    put("now", TRY(utimensat(AT_FDCWD, ATTRS_PATH, NULL, 0)));
    put("now-stamped", stamped_between(stat_mtime(ATTRS_PATH), second, this_second()));
    say("");

    long long touched = stat_mtime(ATTRS_PATH);
    next_second();
    printf("truncate:");
    put("path", TRY(truncate(ATTRS_PATH, 1000)));
    put("size", stat_size(ATTRS_PATH));
    put("path-keeps-mtime", stat_mtime(ATTRS_PATH) == touched);
    put("past-lfs", TRY(truncate(ATTRS_PATH, 1L << 31)));
    put("lfs", TRY(truncate(ATTRS_PATH, (1L << 31) - 1)));
    put("lfs-size", stat_size(ATTRS_PATH));
    put("negative", TRY(truncate(ATTRS_PATH, -1)));
    put("missing", TRY(truncate(ATTRS_PATH "-none", 0)));
    say("");
    printf("ftruncate:");
    second = next_second();
    put("mq_open", TRY(ftruncate((int)q, 500)));
    put("size", fd_size(q));
    put("stamped", stamped_between(mtime_of(q), second, this_second()));
    put("past-lfs", TRY(ftruncate((int)q, 1L << 31)));
    long ro = q_open(ATTRS_NAME, O_RDONLY, 0, NULL);
    put("read-only", TRY(ftruncate((int)ro, 0)));
    long d = TRY(open(ATTRS_PATH, O_RDWR | O_CLOEXEC));
    put("opened-past-lfs", TRY(ftruncate((int)d, 1L << 31)));
    put("seek-end", TRY(lseek((int)d, 0, SEEK_END)));
    char line[100];
    lseek((int)d, 0, SEEK_SET);
    put("read", TRY(read((int)d, line, sizeof line)));
    say("");
    /* Opening it with O_TRUNC empties and stamps it, whatever the access
       mode; making it with O_TRUNC does not. */
    printf("o_trunc:");
    long long sized = mtime_of(q);
    second = next_second();
    long t = TRY(open(ATTRS_PATH, O_RDONLY | O_TRUNC | O_CLOEXEC));
    put("open", t >= 0);
    put("size", stat_size(ATTRS_PATH));
    put("stamped", stamped_between(stat_mtime(ATTRS_PATH), second, this_second()) && sized != stat_mtime(ATTRS_PATH));
    close((int)t);
    ftruncate((int)q, 300);
    long made_trunc = TRY(open(ATTRS_PATH "-trunc", O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600));
    put("made", made_trunc >= 0);
    put("made-size", stat_size(ATTRS_PATH "-trunc"));
    put("other-kept", stat_size(ATTRS_PATH));
    close((int)made_trunc);
    unlink(ATTRS_PATH "-trunc");
    say("");

    struct statfs fs = {0};
    long result = TRY(statfs("/dev/mqueue", &fs));
    show_statfs("statfs-root", result, &fs);
    memset(&fs, 0, sizeof fs);
    result = TRY(statfs(ATTRS_PATH, &fs));
    show_statfs("statfs-queue", result, &fs);
    memset(&fs, 0, sizeof fs);
    result = TRY(fstatfs((int)q, &fs));
    show_statfs("fstatfs-mq_open", result, &fs);
    memset(&fs, 0, sizeof fs);
    result = TRY(fstatfs((int)d, &fs));
    show_statfs("fstatfs-opened", result, &fs);
    say("statfs-missing: statfs=%ld", TRY(statfs(ATTRS_PATH "-none", &fs)));
    close((int)ro);
    close((int)d);

    /* The owner (2001, in group 3001) may change it; another user may not,
       nor write it without a write bit for others. */
    for (int user = 1; user <= 2; user++) {
        pid_t pid = child();
        if (pid == 0) {
            if (syscall(SYS_setresgid, 3000 + user, 3000 + user, 3000 + user) || syscall(SYS_setgroups, 0, NULL) ||
                syscall(SYS_setresuid, 2000 + user, 2000 + user, 2000 + user))
                _exit(90);
            printf("user-%d:", user);
            put("chmod", TRY(chmod(ATTRS_PATH, 0660)));
            put("chown-group", TRY(chown(ATTRS_PATH, -1, 3001)));
            put("chown-user", TRY(chown(ATTRS_PATH, 0, -1)));
            put("utimensat", TRY(utimensat(AT_FDCWD, ATTRS_PATH, times, 0)));
            put("touch", TRY(utimensat(AT_FDCWD, ATTRS_PATH, NULL, 0)));
            put("truncate", TRY(truncate(ATTRS_PATH, 10)));
            put("o_trunc", TRY(open(ATTRS_PATH, O_RDONLY | O_TRUNC | O_CLOEXEC)) >= 0 ? 0 : -errno);
            say("");
            _exit(0);
        }
        say("user-%d: status=%d", user, wait_child(pid));
    }
    show_file("users", ATTRS_PATH);
    if (dev_names()) return 24;

    close((int)q);
    if (stat("/dev/mqueue", &root)) return 23;
    base = (long)root.st_size;
    second = next_second();
    printf("root:");
    put("unlink", TRY(unlink(ATTRS_PATH)));
    put("unlinked-shrinks", base - stat_size("/dev/mqueue"));
    put("unlinked-stamped", stamped_between(stat_mtime("/dev/mqueue"), second, this_second()));
    say("");
    return dev_root();
}
static int dev_case(void) {
    q_unlink(DEV_NAME);
    q_unlink(DEV_NAME "-made");
    struct stat st;
    long stated = TRY(stat("/dev/mqueue", &st));
    say("dev-mqueue: stat=%ld directory=%d perms=%o uid=%d dev-lists=%d", stated, S_ISDIR(st.st_mode),
        st.st_mode & 07777, st.st_uid, lists_directory("/dev", "mqueue"));
    struct mq_attr small = {.mq_maxmsg = 3, .mq_msgsize = 16};
    long q = q_open(DEV_NAME, O_RDWR | O_CREAT | O_EXCL, 0640, &small);
    if (q < 0) return 11;
    q_send(q, "abc", 3, 4, NULL);
    printf("queue:");
    put("listed-type", listed_type(DEV_NAME));
    stated = TRY(stat("/dev/mqueue/" DEV_NAME, &st));
    put("stat", stated);
    printf(" mode=%o size=%ld uid=%d", st.st_mode, (long)st.st_size, st.st_uid);
    say("");
    long d = TRY(open("/dev/mqueue/" DEV_NAME, O_RDWR | O_CLOEXEC));
    char line[100] = {0};
    long n = TRY(read((int)d, line, sizeof line - 1));
    char *end = strchr(line, ' ');
    if (end) *end = 0;
    say("opened: open=%d read=%ld [%s]", d >= 0, n, line);
    show_attr("opened", d);
    printf("opened");
    show_receive("got", d, 16, NULL);
    say("");
    show_dev_link("opened", d);
    show_link("mq_open", q);
    printf("open:");
    put("exclusive", TRY(open("/dev/mqueue/" DEV_NAME, O_RDWR | O_CREAT | O_EXCL, 0600)));
    put("missing", TRY(open("/dev/mqueue/" DEV_NAME "-none", O_RDONLY)));
    put("directory", TRY(open("/dev/mqueue/" DEV_NAME, O_RDONLY | O_DIRECTORY)));
    put("dir-write", TRY(open("/dev/mqueue", O_WRONLY)));
    put("access", TRY(access("/dev/mqueue/" DEV_NAME, R_OK | W_OK)));
    put("access-missing", TRY(access("/dev/mqueue/" DEV_NAME "-none", F_OK)));
    say("");
    /* A queue made through it has the namespace's default attributes. */
    umask(022);
    long made = TRY(open("/dev/mqueue/" DEV_NAME "-made", O_WRONLY | O_CREAT | O_EXCL, 0666));
    stated = TRY(stat("/dev/mqueue/" DEV_NAME "-made", &st));
    say("made: open=%d stat=%ld mode=%o", made >= 0, stated, st.st_mode);
    show_attr("made", made);
    long by_name = q_open(DEV_NAME "-made", O_RDONLY, 0, NULL);
    say("made: mq_open=%d", by_name >= 0);
    close((int)by_name);
    close((int)made);
    /* A new IPC namespace's queues are not there. */
    pid_t pid = child();
    if (pid == 0) {
        if (unshare(CLONE_NEWIPC)) _exit(90);
        long inner = q_open(DEV_NAME "-inner", O_RDWR | O_CREAT, 0600, NULL);
        printf("inner:");
        put("made", inner >= 0);
        put("listed", listed_type(DEV_NAME "-inner"));
        put("outer-listed", listed_type(DEV_NAME));
        put("outer-by-mq_open", q_open(DEV_NAME, O_RDONLY, 0, NULL));
        say("");
        _exit(0);
    }
    say("inner: status=%d", wait_child(pid));
    printf("unlink:");
    put("made", TRY(unlink("/dev/mqueue/" DEV_NAME "-made")));
    put("again", TRY(unlink("/dev/mqueue/" DEV_NAME "-made")));
    put("mq_open-after", q_open(DEV_NAME "-made", O_RDONLY, 0, NULL));
    put("rmdir", TRY(rmdir("/dev/mqueue/" DEV_NAME)));
    put("rmdir-missing", TRY(rmdir("/dev/mqueue/" DEV_NAME "-none")));
    put("unlink-missing", TRY(unlink("/dev/mqueue/" DEV_NAME "-none")));
    put("queue", TRY(unlink("/dev/mqueue/" DEV_NAME)));
    put("listed-after", listed_type(DEV_NAME));
    say("");
    show_dev_link("unlinked", d);
    close((int)d);
    close((int)q);
    return dev_paths();
}

/* A SIGEV_THREAD cookie's room in its netlink socket's receive buffer,
   which Linux charges from the registration on: once a socket with the
   smallest buffer has no room left, the next mq_notify waits until a
   receive makes some, a signal without SA_RESTART ends the wait (EINTR)
   and one with it does not. A cookie that a removal queues still holds its
   room until it is received. How many cookies fit depends on their size
   in the kernel, so only that some do is shown. */
static int room_socket = -1;
static long room_received = -1;
static void *receive_later(void *unused) {
    (void)unused;
    pause_ms(300);
    char buf[64];
    room_received = TRY(recv(room_socket, buf, sizeof buf, 0));
    return NULL;
}
static void arm(long millis) {
    struct itimerval t = {.it_value = {.tv_sec = millis / 1000, .tv_usec = millis % 1000 * 1000}};
    setitimer(ITIMER_REAL, &t, NULL);
}
static int room_case(void) {
    if (isolate()) return 10;
    room_socket = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, 0);
    if (room_socket < 0) return 11;
    int smallest = 0;
    setsockopt(room_socket, SOL_SOCKET, SO_RCVBUF, &smallest, sizeof smallest);
    struct sigaction interrupt = {.sa_handler = handler};
    sigaction(SIGALRM, &interrupt, NULL);
    static char cookie[32] = "cookie";
    struct sigevent event = {.sigev_notify = SIGEV_THREAD, .sigev_signo = room_socket};
    event.sigev_value.sival_ptr = cookie;
    struct mq_attr one = {.mq_maxmsg = 1, .mq_msgsize = 1};
    enum { MOST = 64 };
    long queues[MOST];
    int registered = 0;
    long refused = 0;
    for (int i = 0; i < MOST; i++) {
        char name[16];
        snprintf(name, sizeof name, "room-%d", i);
        queues[i] = q_open(name, O_RDWR | O_CREAT, 0600, &one);
        if (queues[i] < 0) return 12;
        arm(200);
        long r = q_notify(queues[i], &event);
        arm(0);
        if (r != 0) {
            refused = r;
            break;
        }
        registered++;
    }
    printf("room:");
    put("some-fit", registered > 0 && registered < MOST);
    put("full", refused);
    put("caught", caught);
    long next = queues[registered];
    /* A removal queues its cookie, which still takes its room. */
    put("remove", q_notify(queues[0], NULL));
    arm(200);
    put("removed-still-full", q_notify(next, &event));
    arm(0);
    /* A bad queue is looked up only after the room is found. */
    arm(200);
    put("bad-queue-waits", q_notify(-1, &event));
    arm(0);
    say("");
    /* With SA_RESTART the signal does not end the wait, and a receive in
       another thread lets it register. */
    struct sigaction restart = {.sa_handler = handler, .sa_flags = SA_RESTART};
    sigaction(SIGALRM, &restart, NULL);
    caught = 0;
    pthread_t thread;
    if (pthread_create(&thread, NULL, receive_later, NULL)) return 13;
    struct timespec start = monotonic();
    arm(100);
    long r = q_notify(next, &event);
    long waited = elapsed_ms(start);
    arm(0);
    pthread_join(thread, NULL);
    printf("room:");
    put("after-receive", r);
    put("waited", waited >= 250);
    put("restarted", caught);
    put("received", room_received);
    /* With room for one, a bad queue is EBADF, and its charge goes back. */
    char buf[64];
    put("remove-another", q_notify(queues[1], NULL));
    put("drain", TRY(recv(room_socket, buf, sizeof buf, MSG_DONTWAIT)));
    put("drained-last-byte", buf[31]);
    arm(500);
    put("bad-queue", q_notify(-1, &event));
    long fresh = q_open("room-fresh", O_RDWR | O_CREAT, 0600, &one);
    put("again", q_notify(fresh, &event));
    arm(0);
    say("");
    return 0;
}

/* A netlink socket a kernel message overran is held congested until its
   queue is emptied (NETLINK_S_CONGESTED): the overrun's ENOBUFS comes
   once, later messages are dropped even where they would fit, and a
   SIGEV_THREAD registration waits, where a signal without SA_RESTART
   ends it. Only whether each thing happened is shown, as how many
   messages fit takes their truesize. */
struct link_request {
    struct {
        unsigned int len;
        unsigned short type, flags;
        unsigned int seq, pid;
    } header;
    struct {
        unsigned char family, pad;
        unsigned short type;
        int index;
        unsigned int flags, change;
    } link;
};

static long ask_link(int s, unsigned int seq) {
    struct link_request request = {
        .header = {.len = sizeof request, .type = 18 /* RTM_GETLINK */, .flags = 1, .seq = seq},
        .link = {.index = 1},
    };
    return TRY(send(s, &request, sizeof request, 0));
}

static int has_error(int s) {
    struct pollfd p = {.fd = s};
    return poll(&p, 1, 0) == 1 && (p.revents & POLLERR) != 0;
}

/* Receives what is queued, and says whether a message of `seq` was among
   it (1), none (0), or the receive failed (its -errno). */
static long drain_for(int s, unsigned int seq) {
    static char buf[1 << 16];
    long seen = 0;
    for (;;) {
        long n = TRY(recv(s, buf, sizeof buf, MSG_DONTWAIT));
        if (n == -EAGAIN) return seen;
        if (n < 0) return n;
        for (long at = 0; at + 16 <= n;) {
            unsigned int len, got;
            memcpy(&len, buf + at, 4);
            memcpy(&got, buf + at + 8, 4);
            if (got == seq) seen = 1;
            if (len < 16) break;
            at += (len + 3) & ~3L;
        }
    }
}

/* The netlink address of port `port`, for a datagram from one socket to
   another. */
static struct sockaddr_nl_like {
    unsigned short family, pad;
    unsigned int pid, groups;
} netlink_to(unsigned int port) {
    struct sockaddr_nl_like to = {.family = AF_NETLINK, .pid = port};
    return to;
}

static unsigned int port_of(int s) {
    struct sockaddr_nl_like me = {0};
    socklen_t size = sizeof me;
    getsockname(s, (struct sockaddr *)&me, &size);
    return me.pid;
}

static int congested_case(void) {
    if (isolate()) return 10;
    int s = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, 0);
    if (s < 0) return 11;
    /* Room for several replies, so that some are still queued after a
       few receives have made room for a cookie. */
    int room = 32768;
    setsockopt(s, SOL_SOCKET, SO_RCVBUF, &room, sizeof room);
    struct sigaction interrupt = {.sa_handler = handler};
    sigaction(SIGALRM, &interrupt, NULL);
    enum { MOST = 256 };
    int sent = 0;
    while (sent < MOST && !has_error(s)) {
        if (ask_link(s, (unsigned int)sent + 1) < 0) return 12;
        sent++;
    }
    printf("congested:");
    put("overran", sent > 1 && sent < MOST);
    int error = 0;
    socklen_t size = sizeof error;
    getsockopt(s, SOL_SOCKET, SO_ERROR, &error, &size);
    put("error", error);
    char buf[1 << 16];
    long three = 0;
    for (int i = 0; i < 3; i++) three += TRY(recv(s, buf, sizeof buf, MSG_DONTWAIT)) > 0;
    put("three", three);
    /* Room for more, but the socket is still congested. */
    put("ask", ask_link(s, 9999) > 0);
    put("error-again", has_error(s));
    /* Another socket's datagram waits too, or is EAGAIN, and overruns
       nothing (netlink_attachskb from a user socket). */
    int user = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, 0);
    struct sockaddr_nl_like to = netlink_to(port_of(s));
    put("user-send", TRY(sendto(user, "hello", 5, MSG_DONTWAIT, (struct sockaddr *)&to, sizeof to)));
    static char cookie[32] = "cookie";
    struct sigevent event = {.sigev_notify = SIGEV_THREAD, .sigev_signo = s};
    event.sigev_value.sival_ptr = cookie;
    struct mq_attr one = {.mq_maxmsg = 1, .mq_msgsize = 1};
    long q = q_open("congested", O_RDWR | O_CREAT, 0600, &one);
    if (q < 0) return 13;
    caught = 0;
    arm(200);
    put("notify-waits", q_notify(q, &event));
    arm(0);
    put("caught", caught);
    put("dropped", drain_for(s, 9999) == 0);
    say("");
    /* Emptied, it takes messages and cookies again. */
    printf("emptied:");
    put("ask", ask_link(s, 10000) > 0);
    put("answered", drain_for(s, 10000));
    arm(500);
    put("notify", q_notify(q, &event));
    arm(0);
    say("");
    /* Filled by another socket's datagrams, a socket is full but not
       congested: no ENOBUFS, and a receive makes room for the next. */
    int other = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, 0);
    if (other < 0) return 14;
    setsockopt(other, SOL_SOCKET, SO_RCVBUF, &room, sizeof room);
    struct sockaddr_nl_like there = netlink_to(port_of(other));
    if (!there.pid) {
        /* Bound by its first send otherwise; bind it to have a port. */
        struct sockaddr_nl_like any = netlink_to(0);
        bind(other, (struct sockaddr *)&any, sizeof any);
        there = netlink_to(port_of(other));
    }
    static char datagram[1000];
    int filled = 0;
    long last = 0;
    while (filled < MOST) {
        last = TRY(sendto(user, datagram, sizeof datagram, MSG_DONTWAIT, (struct sockaddr *)&there, sizeof there));
        if (last < 0) break;
        filled++;
    }
    printf("user-filled:");
    put("filled", filled > 1 && filled < MOST);
    put("full", last);
    put("error", has_error(other));
    put("received", TRY(recv(other, buf, sizeof buf, MSG_DONTWAIT)));
    put("again", TRY(sendto(user, datagram, sizeof datagram, MSG_DONTWAIT, (struct sockaddr *)&there, sizeof there)));
    say("");
    return 0;
}

/* A link or rename between /dev/mqueue and another filesystem is EXDEV,
   but first both paths are walked, so search permission on the way is
   EACCES before it (filename_parentat, then the mount check). */
static int links_case(void) {
    char dir[] = "/tmp/mqueue-links-XXXXXX";
    if (!mkdtemp(dir)) return 10;
    chmod(dir, 0755);
    char out[64], locked[64], hidden[96];
    snprintf(out, sizeof out, "%s/out", dir);
    snprintf(locked, sizeof locked, "%s/locked", dir);
    snprintf(hidden, sizeof hidden, "%s/locked/x", dir);
    if (mkdir(locked, 0700)) return 12;
    int hidden_fd = open(hidden, O_RDWR | O_CREAT | O_CLOEXEC, 0666);
    if (hidden_fd < 0) return 13;
    close(hidden_fd);
    q_unlink(DEV_NAME "-via");
    long q = q_open(DEV_NAME "-via", O_RDWR | O_CREAT, 0600, NULL);
    if (q < 0 || fchmod((int)q, 0666)) return 14;
    printf("across:");
    put("link", TRY(link(DEV_PATH("-via"), out)));
    put("rename", TRY(rename(DEV_PATH("-via"), out)));
    put("rename-back", TRY(rename(hidden, DEV_PATH("-via2"))));
    say("");
    pid_t pid = child();
    if (pid == 0) {
        if (unprivileged()) _exit(90);
        printf("searched:");
        put("rename-to", TRY(rename(DEV_PATH("-via"), hidden)));
        put("rename-from", TRY(rename(hidden, DEV_PATH("-via2"))));
        put("exchange-to", TRY(syscall(SYS_renameat2, AT_FDCWD, DEV_PATH("-via"), AT_FDCWD, hidden, 2)));
        put("link-to", TRY(link(DEV_PATH("-via"), hidden)));
        put("link-from", TRY(link(hidden, DEV_PATH("-via2"))));
        put("rename-open", TRY(rename(DEV_PATH("-via"), out)));
        say("");
        _exit(0);
    }
    say("searched: status=%d", wait_child(pid));
    close((int)q);
    q_unlink(DEV_NAME "-via");
    unlink(hidden);
    rmdir(locked);
    rmdir(dir);
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
    if (!strcmp(mode, "mqueue-dev")) return dev_case();
    if (!strcmp(mode, "mqueue-room")) return room_case();
    if (!strcmp(mode, "mqueue-congested")) return congested_case();
    if (!strcmp(mode, "mqueue-links")) return links_case();
    return 3;
}
