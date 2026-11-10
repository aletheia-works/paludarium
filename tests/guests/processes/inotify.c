/* inotify, compared with Linux: the calls' errors and their order, the
   events a directory and a file hear of as they are made, changed, moved
   and removed, the queue's merging and overflow, and the waits of a read,
   poll and epoll.

   The watches leave out IN_OPEN, IN_CLOSE_*, and IN_ACCESS and IN_MODIFY
   are only looked for where no read or write of the file is made.

   Outputs are watch descriptors (numbered from 1 in each instance), masks,
   names, whether cookies match, counts and errno values. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/inotify.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <unistd.h>

/* Every event but the opens, closes and reads, which these cases do not make
   in the same way as Linux yet. */
#define WATCHED (IN_ALL_EVENTS & ~(IN_OPEN | IN_CLOSE))

static long e(long r) { return r < 0 ? -errno : r; }

static char base[64];
static char *at(const char *name) {
    static char paths[8][128];
    static int next;
    char *p = paths[next++ % 8];
    snprintf(p, sizeof paths[0], "%s/%s", base, name);
    return p;
}
static void make_base(const char *what) {
    snprintf(base, sizeof base, "/tmp/inotify-%s-XXXXXX", what);
    if (!mkdtemp(base)) {
        perror("mkdtemp");
        exit(90);
    }
}
static void touch(const char *path) {
    int fd = open(path, O_WRONLY | O_CREAT, 0644);
    if (fd >= 0) close(fd);
}
static int remove_one(const char *path, const struct stat *st, int kind, struct FTW *ftw) {
    (void)st, (void)kind, (void)ftw;
    return remove(path);
}
static void remove_all(void) { nftw(base, remove_one, 8, FTW_DEPTH | FTW_PHYS); }

/* The previous cookie seen, to tell a rename's pair. */
static unsigned last_cookie;
/* Prints every queued event of `fd`, one per line. */
static int drain(int fd, const char *label) {
    char buf[4096] __attribute__((aligned(__alignof__(struct inotify_event))));
    int count = 0;
    printf("%s:", label);
    for (;;) {
        ssize_t n = read(fd, buf, sizeof buf);
        if (n <= 0) {
            if (n < 0 && errno != EAGAIN) printf(" read=%d", -errno);
            break;
        }
        for (char *p = buf; p < buf + n;) {
            struct inotify_event *ev = (struct inotify_event *)p;
            const char *pair = "";
            if (ev->cookie) {
                pair = ev->cookie == last_cookie ? "=" : "+";
                last_cookie = ev->cookie;
            }
            printf(" [%d %#x%s%s%s len=%u]", ev->wd, ev->mask, pair, ev->len ? " " : "",
                   ev->len ? ev->name : "", ev->len);
            p += sizeof *ev + ev->len;
            count++;
        }
    }
    printf("\n");
    return count;
}

static int case_calls(void) {
    make_base("calls");
    long bad = e(inotify_init1(IN_CLOEXEC << 1));
    int high = syscall(SYS_inotify_init1, 0x100000000L | IN_CLOEXEC);
    printf("init1 bad=%ld high=%d cloexec=%d\n", bad, high > 0, high > 0 ? fcntl(high, F_GETFD) : -1);
    int plain = syscall(SYS_inotify_init);
    int fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    printf("plain fl=%#x fd=%d; fd fl=%#x fd=%d\n", fcntl(plain, F_GETFL), fcntl(plain, F_GETFD),
           fcntl(fd, F_GETFL), fcntl(fd, F_GETFD));
    char link[64], target[64] = {0};
    snprintf(link, sizeof link, "/proc/self/fd/%d", fd);
    if (readlink(link, target, sizeof target - 1) < 0) strcpy(target, "?");
    struct stat st;
    fstat(fd, &st);
    printf("link=%s mode=%#o\n", target, st.st_mode);

    char *dir = at("d"), *file = at("f"), *sym = at("s");
    mkdir(dir, 0755);
    touch(file);
    if (symlink(file, sym)) return 91;
    int p[2];
    if (pipe(p)) return 92;
    int path_fd = open(dir, O_PATH);
    long bits = e(inotify_add_watch(fd, dir, 0x800));
    long zero = e(inotify_add_watch(fd, dir, 0));
    long only_flags = e(inotify_add_watch(fd, dir, IN_ONLYDIR));
    long badf = e(inotify_add_watch(-1, dir, 0x800));
    long by_path = e(inotify_add_watch(path_fd, dir, IN_ATTRIB));
    long both = e(inotify_add_watch(fd, dir, IN_ATTRIB | IN_MASK_ADD | IN_MASK_CREATE));
    long piped = e(inotify_add_watch(p[0], dir, IN_ATTRIB));
    printf("add bits=%ld zero=%ld only-flags=%ld badf=%ld path-fd=%ld both=%ld pipe=%ld\n", bits, zero,
           only_flags, badf, by_path, both, piped);
    /* A bit outside ALL_INOTIFY_BITS is EINVAL, with valid bits too: 0x1000
       is the one gap among the events, 0x10000 and 0x8000000 lie between
       the flags. */
    long gap = e(inotify_add_watch(fd, dir, IN_ATTRIB | 0x1000));
    long between = e(inotify_add_watch(fd, dir, IN_ATTRIB | 0x10000));
    long flag_gap = e(inotify_add_watch(fd, dir, IN_ATTRIB | 0x8000000));
    printf("add unknown gap=%ld between=%ld flag-gap=%ld\n", gap, between, flag_gap);
    long fault = e(syscall(SYS_inotify_add_watch, fd, (void *)8, IN_ATTRIB));
    long missing = e(inotify_add_watch(fd, at("none"), IN_ATTRIB));
    long onlydir = e(inotify_add_watch(fd, file, IN_ATTRIB | IN_ONLYDIR));
    long empty = e(inotify_add_watch(fd, "", IN_ATTRIB));
    long slash = e(inotify_add_watch(fd, at("f/"), IN_ATTRIB));
    long high_bits = e(syscall(SYS_inotify_add_watch, 0x100000000L | fd, file, 0x100000000L | IN_ATTRIB));
    printf("add fault=%ld missing=%ld onlydir=%ld empty=%ld slash=%ld high=%ld\n", fault, missing,
           onlydir, empty, slash, high_bits);
    /* The file has the watch the call with the high bits made. */
    long wd_file = inotify_add_watch(fd, file, IN_ATTRIB);
    long through_link = inotify_add_watch(fd, sym, IN_ATTRIB);
    long wd_sym = inotify_add_watch(fd, sym, IN_ATTRIB | IN_DONT_FOLLOW);
    long again = inotify_add_watch(fd, file, IN_CREATE);
    long create = e(inotify_add_watch(fd, file, IN_ATTRIB | IN_MASK_CREATE));
    printf("file=%ld through-link=%ld link=%ld again=%ld create=%ld\n", wd_file, through_link, wd_sym,
           again, create);
    /* The file's watch wants IN_CREATE only now: a chmod is not reported. */
    chmod(file, 0600);
    drain(fd, "replaced");
    printf("mask-add=%d\n", inotify_add_watch(fd, file, IN_ATTRIB | IN_MASK_ADD));
    chmod(file, 0644);
    drain(fd, "added");
    long rm_bad = e(inotify_rm_watch(fd, 99));
    long rm_badf = e(inotify_rm_watch(-1, wd_file));
    long rm_pipe = e(inotify_rm_watch(p[0], wd_file));
    long rm_ok = e(inotify_rm_watch(fd, wd_file));
    long rm_again = e(inotify_rm_watch(fd, wd_file));
    printf("rm bad=%ld badf=%ld pipe=%ld ok=%ld again=%ld\n", rm_bad, rm_badf, rm_pipe, rm_ok, rm_again);
    int count = 0;
    long fionread = e(ioctl(fd, FIONREAD, &count));
    printf("fionread=%ld count=%d\n", fionread, count);
    char small[32];
    printf("read short=%ld\n", e(read(fd, small, 15)));
    drain(fd, "ignored");
    printf("next=%d\n", inotify_add_watch(fd, file, IN_ATTRIB));
    long set_zero = e(ioctl(fd, 0x40044900, 0L));
    long set_big = e(ioctl(fd, 0x40044900, 0x80000000L));
    long set_ok = e(ioctl(fd, 0x40044900, 40L));
    printf("setnext zero=%ld big=%ld ok=%ld\n", set_zero, set_big, set_ok);
    /* A new watch takes the number set; the directory's stays 1. */
    long after_set = inotify_add_watch(fd, base, IN_ATTRIB);
    long kept = inotify_add_watch(fd, dir, IN_ONLYDIR | IN_MASK_ADD);
    printf("after-set=%ld kept=%ld other=%ld\n", after_set, kept, e(ioctl(fd, TCGETS, small)));
    long wrote = e(write(fd, "x", 1));
    long seek = e(lseek(fd, 5, SEEK_SET));
    printf("write=%ld seek=%ld pread=%ld\n", wrote, seek, e(pread(fd, small, sizeof small, 0)));
    struct iovec iov = {small, sizeof small};
    long nowait = e(preadv2(fd, &iov, 1, -1, RWF_NOWAIT));
    printf("preadv2 nowait=%ld empty=%ld\n", nowait, e(read(fd, small, sizeof small)));
    /* Records that do not all fit: the first that does not ends the read. */
    chmod(file, 0600);
    chmod(dir, 0700);
    chmod(file, 0644);
    char two[40];
    long first = e(read(fd, two, sizeof two));
    printf("partial=%ld\n", first);
    drain(fd, "rest");
    remove_all();
    return 0;
}

static int case_directory(void) {
    make_base("directory");
    int fd = inotify_init1(IN_NONBLOCK);
    char *dir = at("w");
    mkdir(dir, 0755);
    int wd = inotify_add_watch(fd, dir, WATCHED);
    printf("wd=%d\n", wd);
    char *a = at("w/a"), *b = at("w/b"), *sub = at("w/sub"), *l = at("w/l"), *fifo = at("w/fifo");
    touch(a);
    mkdir(sub, 0700);
    if (symlink("a", l)) return 91;
    mkfifo(fifo, 0600);
    printf("link=%ld\n", e(link(a, b)));
    drain(fd, "made");
    chmod(a, 0600);
    chmod(sub, 0755);
    printf("chown none=%ld\n", e(chown(a, -1, -1)));
    drain(fd, "chown-none");
    long owned = e(chown(a, getuid(), -1));
    printf("chown=%ld lchown=%ld\n", owned, e(lchown(l, -1, getgid())));
    struct timespec both[2] = {{1, 0}, {2, 0}}, atime[2] = {{3, 0}, {0, UTIME_OMIT}},
                    mtime[2] = {{0, UTIME_OMIT}, {4, 0}}, none[2] = {{0, UTIME_OMIT}, {0, UTIME_OMIT}};
    utimensat(AT_FDCWD, a, both, 0);
    utimensat(AT_FDCWD, a, atime, 0);
    utimensat(AT_FDCWD, a, mtime, 0);
    utimensat(AT_FDCWD, a, none, 0);
    utimensat(AT_FDCWD, a, NULL, 0);
    printf("truncate=%ld\n", e(truncate(a, 3)));
    int f = open(a, O_WRONLY);
    long cut = e(ftruncate(f, 1));
    long moded = e(fchmod(f, 0640));
    printf("ftruncate=%ld fchmod=%ld futimens=%ld\n", cut, moded, e(futimens(f, mtime)));
    printf("fchown=%ld\n", e(fchown(f, -1, getgid())));
    close(f);
    f = open(a, O_RDONLY | O_TRUNC);
    close(f);
    long set = e(setxattr(a, "user.k", "v", 1, 0));
    long removed = e(removexattr(a, "user.k"));
    printf("setxattr=%ld removexattr=%ld missing=%ld\n", set, removed, e(removexattr(a, "user.k")));
    drain(fd, "changed");
    char *c = at("w/c");
    rename(a, c);
    rename(sub, at("w/sub2"));
    touch(at("w/d"));
    rename(c, at("w/d"));
    drain(fd, "renamed");
    printf("exchange=%ld\n",
           e(syscall(SYS_renameat2, AT_FDCWD, at("w/d"), AT_FDCWD, at("w/sub2"), 2)));
    drain(fd, "exchanged");
    /* A rename onto another link of the same file does nothing. */
    printf("same=%ld\n", e(rename(b, at("w/sub2"))));
    drain(fd, "same");
    unlink(l);
    unlink(fifo);
    unlink(at("w/sub2"));
    rmdir(at("w/d"));
    unlink(b);
    drain(fd, "removed");
    rmdir(dir);
    drain(fd, "gone");
    remove_all();
    return 0;
}

static int case_files(void) {
    make_base("files");
    int fd = inotify_init1(IN_NONBLOCK);
    char *dir = at("w"), *a = at("w/a"), *b = at("w/b"), *other = at("o");
    mkdir(dir, 0755);
    mkdir(other, 0755);
    touch(a);
    int wd_dir = inotify_add_watch(fd, dir, WATCHED);
    int wd_a = inotify_add_watch(fd, a, WATCHED);
    int wd_other = inotify_add_watch(fd, other, WATCHED);
    printf("wd dir=%d a=%d other=%d\n", wd_dir, wd_a, wd_other);
    /* The directory hears first, with the name. */
    chmod(a, 0600);
    printf("link=%ld\n", e(link(a, b)));
    unlink(b);
    drain(fd, "both");
    rename(a, at("o/a"));
    drain(fd, "moved-out");
    touch(at("o/x"));
    rename(at("o/x"), at("o/a"));
    drain(fd, "replaced");
    /* The watched directory itself, moved and removed. */
    int wd_sub = inotify_add_watch(fd, other, WATCHED);
    printf("same-dir=%d\n", wd_sub);
    rename(other, at("w/o"));
    unlink(at("w/o/a"));
    rmdir(at("w/o"));
    drain(fd, "dir-gone");
    remove_all();
    return 0;
}

static int case_flags(void) {
    make_base("flags");
    int fd = inotify_init1(IN_NONBLOCK);
    char *a = at("a"), *b = at("b");
    touch(a);
    touch(b);
    int once = inotify_add_watch(fd, a, IN_ATTRIB | IN_ONESHOT);
    chmod(a, 0600);
    chmod(a, 0644);
    drain(fd, "oneshot");
    printf("after=%d\n", inotify_add_watch(fd, a, IN_ATTRIB | IN_MASK_ADD | IN_ONESHOT));
    printf("dir-once=%d\n", inotify_add_watch(fd, base, IN_ATTRIB | IN_ONESHOT | IN_EXCL_UNLINK));
    chmod(a, 0600);
    drain(fd, "both-once");
    /* Repeats merge into the last event; others do not. */
    int dir = inotify_add_watch(fd, base, IN_ATTRIB | IN_CREATE | IN_DELETE);
    chmod(a, 0600);
    chmod(a, 0644);
    chmod(b, 0600);
    chmod(a, 0600);
    chmod(a, 0644);
    touch(at("c"));
    unlink(at("c"));
    touch(at("c"));
    unlink(at("c"));
    drain(fd, "merged");
    /* Two instances each hear of it. */
    int second = inotify_init1(IN_NONBLOCK);
    int in_second = inotify_add_watch(second, base, IN_ATTRIB);
    printf("second=%d once=%d dir=%d\n", in_second, once, dir);
    chmod(b, 0644);
    drain(fd, "first");
    drain(second, "second");
    /* Closing an instance takes its watches away. */
    close(second);
    chmod(b, 0600);
    drain(fd, "after-close");
    remove_all();
    return 0;
}

static int case_overflow(void) {
    make_base("overflow");
    int fd = inotify_init1(IN_NONBLOCK);
    char *a = at("a"), *b = at("b");
    touch(a);
    touch(b);
    inotify_add_watch(fd, base, IN_ATTRIB);
    for (int i = 0; i < 16400; i++) chmod(i % 2 ? b : a, 0600);
    int bytes = 0;
    ioctl(fd, FIONREAD, &bytes);
    char buf[4096] __attribute__((aligned(__alignof__(struct inotify_event))));
    long events = 0, overflows = 0, last_wd = 0;
    unsigned last_mask = 0;
    for (;;) {
        ssize_t n = read(fd, buf, sizeof buf);
        if (n <= 0) break;
        for (char *p = buf; p < buf + n;) {
            struct inotify_event *ev = (struct inotify_event *)p;
            events++;
            if (ev->mask & IN_Q_OVERFLOW) overflows++;
            last_wd = ev->wd;
            last_mask = ev->mask;
            p += sizeof *ev + ev->len;
        }
    }
    printf("fionread=%d events=%ld overflows=%ld last wd=%ld mask=%#x\n", bytes, events, overflows,
           last_wd, last_mask);
    chmod(a, 0644);
    drain(fd, "again");
    remove_all();
    return 0;
}

static void on_alarm(int sig) { (void)sig; }

static int case_wait(void) {
    make_base("wait");
    int fd = inotify_init1(0);
    inotify_add_watch(fd, base, IN_CREATE);
    struct pollfd pfd = {fd, POLLIN, 0};
    printf("poll empty=%d revents=%#x\n", poll(&pfd, 1, 0), pfd.revents);
    int ep = epoll_create1(0);
    struct epoll_event ev = {.events = EPOLLIN | EPOLLET, .data.u32 = 7}, out[2];
    epoll_ctl(ep, EPOLL_CTL_ADD, fd, &ev);
    printf("epoll empty=%d\n", epoll_wait(ep, out, 2, 0));
    /* A blocking read waits for a child's mkdir. */
    pid_t child = fork();
    if (child == 0) {
        usleep(100000);
        mkdir(at("child"), 0755);
        _exit(0);
    }
    char buf[256] __attribute__((aligned(__alignof__(struct inotify_event))));
    ssize_t n = read(fd, buf, sizeof buf);
    struct inotify_event *got = (struct inotify_event *)buf;
    printf("read=%ld mask=%#x name=%s\n", (long)n, n > 0 ? got->mask : 0, n > 0 ? got->name : "");
    waitpid(child, NULL, 0);
    touch(at("x"));
    printf("poll ready=%d revents=%#x\n", poll(&pfd, 1, 0), pfd.revents);
    long r = epoll_wait(ep, out, 2, 0);
    printf("epoll ready=%ld data=%u events=%#x\n", r, r > 0 ? out[0].data.u32 : 0, r > 0 ? out[0].events : 0);
    printf("epoll again=%d\n", epoll_wait(ep, out, 2, 0));
    touch(at("y"));
    printf("epoll edge=%d\n", epoll_wait(ep, out, 2, 0));
    int count = 0;
    ioctl(fd, FIONREAD, &count);
    printf("fionread=%d\n", count);
    while (read(fd, buf, sizeof buf) == (ssize_t)sizeof buf) {}
    /* A signal ends a blocking read with EINTR without SA_RESTART. */
    struct sigaction sa = {0};
    sa.sa_handler = on_alarm;
    sigaction(SIGALRM, &sa, NULL);
    struct itimerval t = {{0, 0}, {0, 100000}};
    setitimer(ITIMER_REAL, &t, NULL);
    printf("interrupted=%ld\n", e(read(fd, buf, sizeof buf)));
    remove_all();
    return 0;
}

int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "";
    setvbuf(stdout, NULL, _IOLBF, 0);
    alarm(20);
    if (!strcmp(mode, "inotify-calls")) return case_calls();
    if (!strcmp(mode, "inotify-directory")) return case_directory();
    if (!strcmp(mode, "inotify-files")) return case_files();
    if (!strcmp(mode, "inotify-flags")) return case_flags();
    if (!strcmp(mode, "inotify-overflow")) return case_overflow();
    if (!strcmp(mode, "inotify-wait")) return case_wait();
    return 2;
}
