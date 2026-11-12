/* inotify, compared with Linux: the calls' errors and their order, the
   events a directory and a file hear of as they are made, changed, moved
   and removed, the queue's merging and overflow, and the waits of a read,
   poll and epoll.

   The opens, closes, reads and writes of files are events too: those of
   the cases' own calls, never the C library's (stdout is not watched).

   Outputs are watch descriptors (numbered from 1 in each instance), masks,
   names, whether cookies match, counts and errno values. */
#define _GNU_SOURCE
#include <dirent.h>
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
#include <sys/mman.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <unistd.h>

#define WATCHED IN_ALL_EVENTS

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

/* The events of opening, reading, writing and closing files. */
static int case_content(void) {
    make_base("content");
    int fd = inotify_init1(IN_NONBLOCK);
    char *dir = at("w"), *f = at("w/f"), *g = at("w/g");
    mkdir(dir, 0755);
    touch(f);
    int wd_dir = inotify_add_watch(fd, dir, WATCHED);
    int wd_f = inotify_add_watch(fd, f, WATCHED);
    printf("wd dir=%d f=%d\n", wd_dir, wd_f);
    int rw = open(f, O_RDWR);
    char buf[64] = "hello";
    long w1 = e(write(rw, buf, 5));
    long r0 = e(read(rw, buf, sizeof buf));
    long p1 = e(pread(rw, buf, 2, 1));
    struct iovec iov[2] = {{buf, 1}, {buf + 1, 2}};
    long v1 = e(preadv(rw, iov, 2, 0));
    long v2 = e(pwritev(rw, iov, 2, 5));
    long none = e(write(rw, buf, 0));
    printf("write=%ld eof=%ld pread=%ld preadv=%ld pwritev=%ld empty=%ld\n", w1, r0, p1, v1, v2, none);
    drain(fd, "read-write");
    long fa = e(fallocate(rw, 0, 0, 16));
    int out = open(g, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    off_t from = 0;
    long sent = e(sendfile(out, rw, &from, 4));
    loff_t in_at = 0;
    long copied = e(copy_file_range(rw, &in_at, out, NULL, 3, 0));
    close(out);
    printf("fallocate=%ld sendfile=%ld copy=%ld\n", fa, sent, copied);
    drain(fd, "copies");
    /* The last close of a description is its IN_CLOSE_*. */
    int again = dup(rw);
    close(rw);
    drain(fd, "dup-closed");
    close(again);
    int ro = open(f, O_RDONLY);
    char link[64];
    snprintf(link, sizeof link, "/proc/self/fd/%d", ro);
    int through = open(link, O_RDONLY);
    close(through);
    int path = open(f, O_PATH);
    close(path);
    drain(fd, "opens");
    /* A mapping holds its file: the close comes as it goes. */
    char *map = mmap(NULL, 4096, PROT_READ, MAP_SHARED, ro, 0);
    close(ro);
    long first = map == MAP_FAILED ? -1 : map[0];
    drain(fd, "mapped");
    munmap(map, 4096);
    printf("mapped first=%ld\n", first);
    drain(fd, "unmapped");
    /* A directory read. */
    int d = open(dir, O_RDONLY | O_DIRECTORY);
    char entries[1024];
    long got = e(syscall(SYS_getdents64, d, entries, sizeof entries)) > 0;
    long end = e(syscall(SYS_getdents64, d, entries, sizeof entries));
    long small = e(syscall(SYS_getdents64, d, entries, 1));
    close(d);
    printf("getdents some=%ld end=%ld small=%ld\n", got, end, small);
    drain(fd, "directory");
    /* The old getdents reads a directory too. */
    d = open(dir, O_RDONLY | O_DIRECTORY);
    long old = e(syscall(SYS_getdents, d, entries, sizeof entries)) > 0;
    close(d);
    printf("old getdents some=%ld\n", old);
    drain(fd, "old-directory");
    /* O_CREAT | O_TRUNC of a new file, then of an old one. */
    int made = open(at("w/n"), O_WRONLY | O_CREAT | O_TRUNC, 0644);
    close(made);
    made = open(at("w/n"), O_WRONLY | O_CREAT | O_TRUNC, 0644);
    close(made);
    drain(fd, "creat");
    /* IN_EXCL_UNLINK: a removed file's events do not reach the watch. */
    int excl = inotify_init1(IN_NONBLOCK);
    inotify_add_watch(excl, dir, WATCHED | IN_EXCL_UNLINK);
    int gone = open(g, O_WRONLY);
    unlink(g);
    long late = e(write(gone, "x", 1));
    close(gone);
    printf("late=%ld\n", late);
    drain(excl, "excl-unlink");
    /* Without IN_EXCL_UNLINK the directory still hears of a removed open
       file, by the name it had; a watch on the file itself with the flag
       does not (read after the close, which Linux's IN_DELETE_SELF waits
       for). */
    int plain = inotify_init1(IN_NONBLOCK);
    char *h = at("w/h");
    touch(h);
    inotify_add_watch(plain, dir, WATCHED);
    int self = inotify_init1(IN_NONBLOCK);
    inotify_add_watch(self, h, WATCHED | IN_EXCL_UNLINK);
    int kept = open(h, O_RDWR);
    unlink(h);
    long kept_write = e(write(kept, "y", 1));
    long kept_read = e(pread(kept, buf, 1, 0));
    printf("kept write=%ld read=%ld\n", kept_write, kept_read);
    drain(plain, "unlinked-dir");
    close(kept);
    drain(plain, "unlinked-dir-closed");
    drain(self, "unlinked-self");
    remove_all();
    return 0;
}

/* A file removed while a description of it is open ends (IN_DELETE_SELF)
   only with its last close, as Linux's dentry lets go of it. */
static int case_held(void) {
    make_base("held");
    int fd = inotify_init1(IN_NONBLOCK);
    char *dir = at("w"), *h = at("w/h"), *t = at("w/t"), *x = at("w/x"), *m = at("w/m"), *sub = at("w/sub");
    mkdir(dir, 0755);
    mkdir(sub, 0755);
    touch(h);
    touch(t);
    touch(x);
    touch(m);
    int wd_dir = inotify_add_watch(fd, dir, WATCHED);
    int wd_h = inotify_add_watch(fd, h, WATCHED);
    int wd_t = inotify_add_watch(fd, t, WATCHED);
    int wd_m = inotify_add_watch(fd, m, WATCHED);
    int wd_sub = inotify_add_watch(fd, sub, WATCHED);
    printf("wd dir=%d h=%d t=%d m=%d sub=%d\n", wd_dir, wd_h, wd_t, wd_m, wd_sub);
    int open_h = open(h, O_RDWR);
    int again = dup(open_h);
    unlink(h);
    drain(fd, "unlinked");
    long wrote = e(write(open_h, "z", 1));
    close(open_h);
    drain(fd, "first-close");
    close(again);
    printf("wrote=%ld\n", wrote);
    drain(fd, "last-close");
    /* A rename onto a file that is open. */
    int open_t = open(t, O_RDONLY);
    rename(x, t);
    drain(fd, "replaced");
    close(open_t);
    drain(fd, "replaced-closed");
    /* A mapping holds its file after the descriptor is closed. */
    int open_m = open(m, O_RDWR);
    long sized = e(ftruncate(open_m, 4096));
    char *map = mmap(NULL, 4096, PROT_READ, MAP_SHARED, open_m, 0);
    close(open_m);
    unlink(m);
    printf("sized=%ld mapped=%d\n", sized, map != MAP_FAILED);
    drain(fd, "mapped");
    munmap(map, 4096);
    drain(fd, "unmapped");
    /* A directory open when it is removed. */
    int open_sub = open(sub, O_RDONLY | O_DIRECTORY);
    rmdir(sub);
    drain(fd, "rmdir");
    close(open_sub);
    drain(fd, "rmdir-closed");
    remove_all();
    return 0;
}

/* A working directory holds a removed directory as a descriptor does:
   its end waits until no process is in it. */
static int case_home(void) {
    make_base("home");
    int fd = inotify_init1(IN_NONBLOCK);
    char back[PATH_MAX];
    if (!getcwd(back, sizeof back)) return 91;
    char *own = at("own"), *kid = at("kid"), *fch = at("fch");
    mkdir(own, 0755);
    mkdir(kid, 0755);
    mkdir(fch, 0755);
    int wd_base = inotify_add_watch(fd, base, WATCHED);
    int wd_own = inotify_add_watch(fd, own, WATCHED);
    int wd_kid = inotify_add_watch(fd, kid, WATCHED);
    int wd_fch = inotify_add_watch(fd, fch, WATCHED);
    printf("wd base=%d own=%d kid=%d fch=%d\n", wd_base, wd_own, wd_kid, wd_fch);
    /* Its own working directory. */
    long in = e(chdir(own));
    long gone = e(rmdir(own));
    printf("chdir=%ld rmdir=%ld\n", in, gone);
    drain(fd, "own-removed");
    chdir(back);
    drain(fd, "own-left");
    /* A child's, which it got from a fork and keeps until it exits. */
    int ready[2], done[2];
    if (pipe(ready) || pipe(done)) return 92;
    pid_t child = fork();
    if (child == 0) {
        char byte = chdir(kid) == 0 ? 'y' : 'n';
        write(ready[1], &byte, 1);
        read(done[0], &byte, 1);
        _exit(0);
    }
    char byte = 0;
    read(ready[0], &byte, 1);
    printf("child in=%c rmdir=%ld\n", byte, e(rmdir(kid)));
    drain(fd, "kid-removed");
    write(done[1], "x", 1);
    waitpid(child, NULL, 0);
    drain(fd, "kid-exited");
    /* fchdir to a descriptor that is then closed. */
    int open_fch = open(fch, O_RDONLY | O_DIRECTORY);
    printf("fchdir=%ld\n", e(fchdir(open_fch)));
    close(open_fch);
    printf("rmdir=%ld\n", e(rmdir(fch)));
    drain(fd, "fchdir-removed");
    chdir(back);
    drain(fd, "fchdir-left");
    /* A rename over the working directory removes it too. */
    char *top = at("top"), *over = at("over");
    mkdir(top, 0755);
    mkdir(over, 0755);
    int wd_top = inotify_add_watch(fd, top, WATCHED);
    printf("wd top=%d\n", wd_top);
    chdir(top);
    printf("rename=%ld\n", e(rename(over, top)));
    drain(fd, "replaced");
    chdir(back);
    drain(fd, "replaced-left");
    remove_all();
    return 0;
}

/* A program a process runs holds its file (Linux's `exe_file`): removed,
   its end waits until no process runs it. Its exec's own events are not
   watched (case_exec has them). */
static int run_removing(const char *prog, const char *removed);
/* Copies `from` to `to`, runnable; whether any of it was copied. */
static int copy_file(const char *from_path, const char *to_path) {
    int from = open(from_path, O_RDONLY);
    int to = open(to_path, O_WRONLY | O_CREAT | O_TRUNC, 0755);
    char buf[65536];
    ssize_t n;
    long copied = 0;
    while ((n = read(from, buf, sizeof buf)) > 0) copied += write(to, buf, n);
    close(from);
    close(to);
    return copied > 0;
}
/* The ELF interpreter a program runs with is held as the program is (on
   Linux by its mappings): inotify-interp, this file linked on musl's
   dynamic linker by the relative name inotify-ld.so, which exec finds in
   the working directory, runs with a copy of it there. */
static int case_interpreter(void) {
    make_base("interpreter");
    char *ld = at("inotify-ld.so");
    printf("copied=%d\n", copy_file("/lib/ld-musl-x86_64.so.1", ld));
    char self[PATH_MAX];
    ssize_t len = readlink("/proc/self/exe", self, sizeof self - 32);
    if (len <= 0) return 95;
    self[len] = 0;
    strcpy(strrchr(self, '/') + 1, "inotify-interp");
    return run_removing(self, ld);
}
/* A child runs `prog` (as inotify-runner, from the base directory) while
   `removed` is unlinked; the events of `removed` until the child exits. */
static int run_removing(const char *prog, const char *removed) {
    int fd = inotify_init1(IN_NONBLOCK);
    int wd = inotify_add_watch(fd, removed, IN_ATTRIB | IN_DELETE_SELF | IN_MOVE_SELF);
    printf("wd=%d\n", wd);
    int ready[2], done[2];
    if (pipe(ready) || pipe(done)) return 92;
    pid_t child = fork();
    if (child == 0) {
        close(ready[0]);
        close(done[1]);
        dup2(ready[1], 10);
        dup2(done[0], 11);
        close(ready[1]);
        close(done[0]);
        if (chdir(base)) _exit(96);
        execl(prog, prog, "inotify-runner", (char *)NULL);
        _exit(93);
    }
    close(ready[1]);
    close(done[0]);
    char byte = 0;
    long got = read(ready[0], &byte, 1);
    printf("child ran=%ld byte=%c\n", got, byte);
    printf("unlink=%ld\n", e(unlink(removed)));
    drain(fd, "removed");
    close(done[1]);
    int status = 0;
    waitpid(child, &status, 0);
    printf("exited=%d\n", WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    drain(fd, "exited");
    remove_all();
    return 0;
}
static int case_running(void) {
    make_base("running");
    char *prog = at("prog");
    printf("copied=%d\n", copy_file("/proc/self/exe", prog));
    return run_removing(prog, prog);
}
/* The program case_running runs: it says it runs, then waits for the end
   of its input. */
static int case_runner(void) {
    char byte;
    if (write(10, "r", 1) != 1) return 94;
    while (read(11, &byte, 1) > 0) {}
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

/* A descriptor's events go where its file's name is now, as Linux's dentry
 * follows renames: of the file, of a directory above it, onto it, and
 * RENAME_EXCHANGE; an unlinked name, with another link left, keeps it. */
static int case_moved(void) {
    make_base("moved");
    int fd = inotify_init1(IN_NONBLOCK);
    int excl = inotify_init1(IN_NONBLOCK);
    char *src = at("src"), *dst = at("dst"), *moved = at("moved");
    mkdir(src, 0755);
    mkdir(dst, 0755);
    char from[160], to[160], other[160];
    snprintf(from, sizeof from, "%s/f", src);
    int f = open(from, O_RDWR | O_CREAT, 0644);
    int wd_src = inotify_add_watch(fd, src, WATCHED);
    int wd_dst = inotify_add_watch(fd, dst, WATCHED);
    printf("wd src=%d dst=%d\n", wd_src, wd_dst);
    char byte = 'x';
    snprintf(to, sizeof to, "%s/g", dst);
    printf("rename=%ld\n", e(rename(from, to)));
    drain(fd, "renamed");
    long wrote = e(write(f, &byte, 1));
    long mode = e(fchmod(f, 0600));
    printf("write=%ld fchmod=%ld pread=%ld\n", wrote, mode, e(pread(f, &byte, 1, 0)));
    drain(fd, "after-rename");
    /* Its directory renamed: the file is still in it. */
    printf("rename dir=%ld\n", e(rename(dst, moved)));
    drain(fd, "dir-renamed");
    printf("write=%ld\n", e(write(f, &byte, 1)));
    drain(fd, "after-dir-rename");
    /* Unlinked with another link left: the old name, which a watch with
     * IN_EXCL_UNLINK leaves out. */
    int wd_excl = inotify_add_watch(excl, moved, WATCHED | IN_EXCL_UNLINK);
    printf("wd excl=%d\n", wd_excl);
    snprintf(to, sizeof to, "%s/g", moved);
    snprintf(other, sizeof other, "%s/h", moved);
    long linked = e(link(to, other));
    printf("link=%ld unlink=%ld\n", linked, e(unlink(to)));
    drain(fd, "unlinked");
    drain(excl, "unlinked-excl");
    wrote = e(write(f, &byte, 1));
    printf("write=%ld fchmod=%ld\n", wrote, e(fchmod(f, 0644)));
    drain(fd, "after-unlink");
    drain(excl, "after-unlink-excl");
    /* A new file at the unlinked name, renamed and unlinked, leaves it. */
    char fresh[160];
    snprintf(fresh, sizeof fresh, "%s/n", moved);
    touch(to);
    long renamed = e(rename(to, fresh));
    printf("rename new=%ld unlink new=%ld\n", renamed, e(unlink(fresh)));
    drain(fd, "renewed");
    drain(excl, "renewed-excl");
    printf("write=%ld\n", e(write(f, &byte, 1)));
    drain(fd, "after-renew");
    drain(excl, "after-renew-excl");
    /* A name a rename replaces, while another link keeps the file. */
    char keep[160], over[160];
    snprintf(keep, sizeof keep, "%s/i", moved);
    snprintf(over, sizeof over, "%s/k", moved);
    int h = open(other, O_RDWR);
    touch(over);
    linked = e(link(other, keep));
    printf("open=%d link=%ld rename over=%ld\n", h >= 0, linked, e(rename(over, other)));
    drain(fd, "replaced");
    drain(excl, "replaced-excl");
    printf("write=%ld\n", e(write(h, &byte, 1)));
    drain(fd, "after-replace");
    drain(excl, "after-replace-excl");
    /* RENAME_EXCHANGE swaps two names. */
    char x[160], y[160];
    snprintf(x, sizeof x, "%s/x", moved);
    snprintf(y, sizeof y, "%s/y", src);
    int fx = open(x, O_RDWR | O_CREAT, 0644);
    int fy = open(y, O_RDWR | O_CREAT, 0644);
    drain(fd, "made");
    drain(excl, "made-excl");
    printf("exchange=%ld\n", e(syscall(SYS_renameat2, AT_FDCWD, x, AT_FDCWD, y, 2)));
    drain(fd, "exchanged");
    drain(excl, "exchanged-excl");
    printf("write x=%ld\n", e(write(fx, &byte, 1)));
    drain(fd, "after-exchange-x");
    drain(excl, "after-exchange-x-excl");
    printf("write y=%ld\n", e(write(fy, &byte, 1)));
    drain(fd, "after-exchange-y");
    drain(excl, "after-exchange-y-excl");
    /* A removed file opened again through /proc is the same dentry, which
     * RENAME_EXCHANGE of its directory moves once. */
    char gone_dir[160], swap_dir[160], gone[200], proc[64];
    snprintf(gone_dir, sizeof gone_dir, "%s/gone", base);
    snprintf(swap_dir, sizeof swap_dir, "%s/swap", base);
    mkdir(gone_dir, 0755);
    mkdir(swap_dir, 0755);
    snprintf(gone, sizeof gone, "%s/z", gone_dir);
    int fz = open(gone, O_RDWR | O_CREAT, 0644);
    unlink(gone);
    snprintf(proc, sizeof proc, "/proc/self/fd/%d", fz);
    int fz2 = open(proc, O_RDWR);
    int wd_gone = inotify_add_watch(fd, gone_dir, WATCHED);
    printf("wd gone=%d reopen=%d\n", wd_gone, fz2 >= 0);
    printf("exchange dirs=%ld\n",
           e(syscall(SYS_renameat2, AT_FDCWD, gone_dir, AT_FDCWD, swap_dir, 2)));
    drain(fd, "dirs-exchanged");
    printf("write=%ld\n", e(write(fz, &byte, 1)));
    drain(fd, "after-dirs-exchange");
    close(fz2);
    close(fz);
    drain(fd, "gone-closed");
    close(f);
    close(h);
    close(fx);
    close(fy);
    drain(fd, "closed");
    drain(excl, "closed-excl");
    close(fd);
    close(excl);
    remove_all();
    return 0;
}
/* A FIFO opened by its path is an open file: IN_OPEN once the open is done
 * and IN_CLOSE_* when its description closes, for the directory and the
 * FIFO, and its reads and writes for the FIFO only. splice, tee and
 * vmsplice tell what they moved bytes through. */
static int case_fifo(void) {
    make_base("fifo");
    int fd = inotify_init1(IN_NONBLOCK);
    char *fifo = at("p");
    char *lone = at("l");
    char *file = at("f");
    printf("mkfifo=%ld %ld\n", e(mkfifo(fifo, 0644)), e(mkfifo(lone, 0644)));
    int reg = open(file, O_RDWR | O_CREAT, 0644);
    printf("write=%ld\n", (long)write(reg, "xy", 2));
    int pipes[2];
    if (pipe(pipes)) return 92;
    int wd = inotify_add_watch(fd, base, WATCHED);
    int own = inotify_add_watch(fd, fifo, WATCHED);
    printf("wd=%d own=%d\n", wd, own);
    printf("lone writer=%ld\n", e(open(lone, O_WRONLY | O_NONBLOCK)));
    drain(fd, "enxio");
    int r = open(fifo, O_RDWR | O_NONBLOCK);
    drain(fd, "opened");
    long wrote = write(r, "a", 1);
    char got;
    printf("write=%ld read=%ld\n", wrote, (long)read(r, &got, 1));
    drain(fd, "rw");
    loff_t off = 0;
    printf("splice in=%ld\n", e(splice(reg, &off, r, NULL, 2, 0)));
    drain(fd, "spliced-in");
    printf("splice out=%ld\n", e(splice(r, NULL, reg, &off, 1, 0)));
    drain(fd, "spliced-out");
    printf("tee=%ld\n", e(tee(r, pipes[1], 1, 0)));
    drain(fd, "teed");
    struct iovec iov = {"z", 1};
    printf("vmsplice=%ld\n", e(vmsplice(r, &iov, 1, 0)));
    drain(fd, "vmspliced");
    printf("splice none=%ld\n", e(splice(reg, &off, r, NULL, 0, 0)));
    drain(fd, "none");
    int dup_r = dup(r);
    close(r);
    drain(fd, "one-closed");
    close(dup_r);
    drain(fd, "closed");
    int reader = open(fifo, O_RDONLY | O_NONBLOCK);
    char buf[4];
    printf("empty read=%ld\n", e(read(reader, buf, sizeof buf)));
    int writer = open(fifo, O_WRONLY | O_NONBLOCK);
    printf("write=%ld\n", (long)write(writer, "b", 1));
    struct iovec back = {buf, sizeof buf};
    printf("vmsplice read=%ld\n", e(vmsplice(reader, &back, 1, 0)));
    close(writer);
    close(reader);
    drain(fd, "reader");
    close(pipes[0]);
    close(pipes[1]);
    close(reg);
    close(fd);
    remove_all();
    return 0;
}

/* The files exec opens are open files: IN_OPEN as it opens each, IN_ACCESS
 * as it reads their first bytes, and IN_CLOSE_NOWRITE once nothing uses
 * them, a script at the end of the exec, the program and its ELF
 * interpreter when the process exits, and a file it cannot run at once.
 * A child runs each from the watched directory. */
static void run_watched(int fd, const char *name, const char *mode) {
    char *prog = at(name);
    char *const argv[] = {prog, (char *)mode, NULL};
    pid_t child = fork();
    if (child == 0) {
        if (chdir(base)) _exit(96);
        execv(prog, argv);
        _exit(errno == ENOEXEC ? 98 : errno == EACCES ? 97 : 93);
    }
    int status = 0;
    waitpid(child, &status, 0);
    printf("%s exited=%d\n", name, WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    drain(fd, name);
}
static int write_file(const char *path, const char *text, mode_t mode) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, mode);
    long n = write(fd, text, strlen(text));
    close(fd);
    return n == (long)strlen(text);
}
static int case_exec(void) {
    make_base("exec");
    char self[PATH_MAX];
    ssize_t len = readlink("/proc/self/exe", self, sizeof self - 32);
    if (len <= 0) return 95;
    self[len] = 0;
    printf("copied=%d", copy_file(self, at("prog")));
    strcpy(strrchr(self, '/') + 1, "inotify-interp");
    printf(" %d", copy_file(self, at("dyn")));
    printf(" %d\n", copy_file("/lib/ld-musl-x86_64.so.1", at("inotify-ld.so")));
    char line[160];
    snprintf(line, sizeof line, "#!%s inotify-quiet\n", at("prog"));
    printf("written=%d", write_file(at("shut"), line, 0644));
    printf(" %d", write_file(at("s"), line, 0755));
    printf(" %d", write_file(at("empty"), "", 0755));
    printf(" %d", write_file(at("junk"), "junk", 0755));
    snprintf(line, sizeof line, "#!%s\n", at("junk"));
    printf(" %d\n", write_file(at("bad"), line, 0755));
    int fd = inotify_init1(IN_NONBLOCK);
    printf("wd=%d\n", inotify_add_watch(fd, base, WATCHED));
    run_watched(fd, "shut", "inotify-quiet");
    run_watched(fd, "empty", "inotify-quiet");
    run_watched(fd, "junk", "inotify-quiet");
    run_watched(fd, "bad", "inotify-quiet");
    run_watched(fd, "prog", "inotify-quiet");
    run_watched(fd, "s", "inotify-quiet");
    run_watched(fd, "dyn", "inotify-quiet");
    close(fd);
    remove_all();
    return 0;
}

/* The instance itself: signal-driven I/O (O_ASYNC, FIOASYNC), whose signal
 * comes once for each event queued; its /proc/self/fdinfo, which lists its
 * watches the newest first; and /proc/sys/fs/inotify. Inode and device
 * numbers are compared, not printed, and the file handle Linux adds after
 * ignored_mask is not looked at. */
static int signals_taken(int fd) {
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGRTMIN + 6);
    struct timespec zero = {0, 0};
    siginfo_t info;
    int count = 0;
    while (sigtimedwait(&set, &info, &zero) > 0) {
        printf(" [code=%d band=%#lx fd=%s]", info.si_code, (long)info.si_band, info.si_fd == fd ? "own" : "other");
        count++;
    }
    return count;
}
static int case_instance(void) {
    make_base("instance");
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGRTMIN + 6);
    sigprocmask(SIG_BLOCK, &set, NULL);
    int fd = inotify_init1(IN_NONBLOCK);
    printf("setown=%ld setsig=%ld", e(fcntl(fd, F_SETOWN, getpid())), e(fcntl(fd, F_SETSIG, SIGRTMIN + 6)));
    printf(" setfl=%ld", e(fcntl(fd, F_SETFL, O_ASYNC | O_NONBLOCK)));
    printf(" async=%d\n", (fcntl(fd, F_GETFL) & O_ASYNC) != 0);
    int wd = inotify_add_watch(fd, base, IN_CREATE | IN_ATTRIB);
    touch(at("a"));
    printf("created:");
    printf(" count=%d\n", signals_taken(fd));
    chmod(at("a"), 0600);
    chmod(at("a"), 0600);
    printf("merged:");
    printf(" count=%d\n", signals_taken(fd));
    inotify_rm_watch(fd, wd);
    printf("removed:");
    printf(" count=%d\n", signals_taken(fd));
    int off = 0, on = 1;
    long off_set = e(ioctl(fd, FIOASYNC, &off));
    printf("fioasync off=%ld async=%d\n", off_set, (fcntl(fd, F_GETFL) & O_ASYNC) != 0);
    wd = inotify_add_watch(fd, base, IN_CREATE);
    touch(at("b"));
    printf("off:");
    printf(" count=%d\n", signals_taken(fd));
    long on_set = e(ioctl(fd, FIOASYNC, &on));
    printf("fioasync on=%ld async=%d\n", on_set, (fcntl(fd, F_GETFL) & O_ASYNC) != 0);
    touch(at("c"));
    printf("on:");
    printf(" count=%d\n", signals_taken(fd));
    drain(fd, "queued");
    close(fd);

    /* fdinfo: the lines every descriptor has, then one per watch. */
    int in = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    printf("wds=%d", inotify_add_watch(in, base, IN_CREATE));
    printf(" %d", inotify_add_watch(in, at("a"), IN_ATTRIB | IN_ONESHOT));
    printf(" %d\n", inotify_add_watch(in, base, IN_CREATE | IN_DELETE | IN_EXCL_UNLINK));
    struct stat own, dir, file;
    fstat(in, &own);
    stat(base, &dir);
    stat(at("a"), &file);
    /* statx's stx_mnt_id (STATX_MNT_ID), at byte 144 of its buffer. */
    unsigned long long sx[32] = {0};
    long sxr = e(syscall(SYS_statx, in, "", AT_EMPTY_PATH, 0x1000, sx));
    char path[64];
    snprintf(path, sizeof path, "/proc/self/fdinfo/%d", in);
    FILE *info = fopen(path, "r");
    char line[512];
    while (info && fgets(line, sizeof line, info)) {
        unsigned long long n;
        unsigned w, dev, mask, ignored;
        unsigned long long ino;
        if (sscanf(line, "mnt_id: %llu", &n) == 1) {
            printf("mnt_id %s\n", sxr == 0 && n == sx[144 / 8] ? "statx" : "other");
        } else if (sscanf(line, "ino: %llu", &n) == 1) {
            printf("ino %s\n", n == (unsigned long long)own.st_ino ? "fstat" : "other");
        } else if (sscanf(line, "inotify wd:%x ino:%llx sdev:%x mask:%x ignored_mask:%x", &w, &ino, &dev, &mask, &ignored) == 5) {
            const char *name = ino == (unsigned long long)dir.st_ino ? "base" : ino == (unsigned long long)file.st_ino ? "a" : "other";
            unsigned kernel = major(dir.st_dev) << 20 | minor(dir.st_dev);
            printf("watch wd=%x %s sdev=%s mask=%#x ignored=%x\n", w, name, dev == kernel ? "same" : "other", mask, ignored);
        } else {
            printf("%s", line);
        }
    }
    if (info) fclose(info);
    close(in);

    /* /proc/sys/fs/inotify: its files, root's 0644, each a number. */
    DIR *d = opendir("/proc/sys/fs/inotify");
    struct dirent *entry;
    printf("sysctl:");
    while (d && (entry = readdir(d))) {
        if (entry->d_name[0] == '.') continue;
        char name[300];
        snprintf(name, sizeof name, "/proc/sys/fs/inotify/%s", entry->d_name);
        struct stat st;
        stat(name, &st);
        FILE *v = fopen(name, "r");
        char value[32] = {0};
        char *got = v ? fgets(value, sizeof value, v) : NULL;
        if (v) fclose(v);
        char *end = NULL;
        long number = got ? strtol(value, &end, 10) : -1;
        printf(" [%s type=%d mode=%o uid=%u number=%d]", entry->d_name, entry->d_type, st.st_mode & 07777, st.st_uid,
               got && number >= 0 && end && *end == '\n');
    }
    if (d) closedir(d);
    printf("\n");
    /* Only root may open them to write. */
    pid_t child = fork();
    if (child == 0) {
        if (geteuid() == 0 && setresuid(65534, 65534, 65534)) _exit(97);
        _exit(-e(open("/proc/sys/fs/inotify/max_user_watches", O_WRONLY)));
    }
    int status = 0;
    waitpid(child, &status, 0);
    printf("write as a user=%d\n", WIFEXITED(status) ? -WEXITSTATUS(status) : -1);
    remove_all();
    return 0;
}

/* Reads that meet memory the process cannot write: each record is copied
 * out as it is taken, so the one that meets such a page is taken too and
 * the read is EFAULT, whatever came before; an address no process has
 * takes nothing. readv reads each buffer in turn and stops at one it does
 * not fill. */
static void show_record(const char *label, const char *p) {
    const struct inotify_event *ev = (const struct inotify_event *)p;
    printf("%s: [%d %#x %s len=%u]\n", label, ev->wd, ev->mask, ev->len ? ev->name : "", ev->len);
}
static int case_read(void) {
    make_base("read");
    int fd = inotify_init1(IN_NONBLOCK);
    printf("wd=%d\n", inotify_add_watch(fd, base, IN_CREATE));
    char *pages = mmap(NULL, 3 * 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (pages == MAP_FAILED) return 92;
    printf("mprotect=%ld\n", e(mprotect(pages + 4096, 4096, PROT_READ)));
    munmap(pages + 2 * 4096, 4096);
    /* Each record here is 16 bytes and a 16-byte name. */
    touch(at("a"));
    touch(at("b"));
    touch(at("c"));
    char *edge = pages + 4096 - 40;
    printf("partial=%ld\n", e(read(fd, edge, 96)));
    show_record("before", edge);
    drain(fd, "after-partial");
    touch(at("d"));
    touch(at("e"));
    printf("read-only=%ld\n", e(read(fd, pages + 4096, 64)));
    drain(fd, "after-read-only");
    touch(at("f"));
    touch(at("g"));
    printf("unmapped=%ld\n", e(read(fd, pages + 2 * 4096, 64)));
    drain(fd, "after-unmapped");
    touch(at("h"));
    printf("kernel=%ld\n", e(read(fd, (void *)-4096L, 64)));
    printf("none=%ld\n", e(read(fd, pages, 0)));
    drain(fd, "after-kernel");
    touch(at("i"));
    touch(at("j"));
    touch(at("k"));
    struct iovec iov[3] = {{pages, 32}, {pages + 64, 40}, {pages + 128, 64}};
    printf("readv=%ld\n", e(readv(fd, iov, 3)));
    show_record("first", pages);
    show_record("second", pages + 64);
    drain(fd, "after-readv");
    touch(at("l"));
    touch(at("m"));
    struct iovec faulting[2] = {{pages, 32}, {pages + 4096, 64}};
    printf("readv-fault=%ld\n", e(readv(fd, faulting, 2)));
    show_record("kept", pages);
    drain(fd, "after-readv-fault");
    touch(at("n"));
    struct iovec empty[2] = {{pages, 0}, {pages + 64, 0}};
    printf("readv-empty=%ld\n", e(readv(fd, empty, 2)));
    printf("preadv2 hipri=%ld\n", e(preadv2(fd, iov, 1, -1, RWF_HIPRI)));
    touch(at("o"));
    printf("preadv2 dsync=%ld\n", e(preadv2(fd, iov, 1, -1, RWF_DSYNC)));
    drain(fd, "after-preadv2");
    close(fd);
    remove_all();
    return 0;
}

/* A FIFO opened by its path is at its dentry as a file is: renames move
 * its events, and an open through /proc/self/fd, with no name left, opens
 * its pipe again (IN_OPEN) at the same dentry, which keeps the FIFO until
 * the last of them closes. */
static int case_fifo_moved(void) {
    make_base("fifo-moved");
    char *one = at("one");
    char *two = at("two");
    printf("mkdir=%ld %ld\n", e(mkdir(one, 0755)), e(mkdir(two, 0755)));
    char *p = at("one/p");
    char *q = at("two/q");
    char *r = at("one/r");
    printf("mkfifo=%ld %ld\n", e(mkfifo(p, 0644)), e(mkfifo(r, 0644)));
    int fd = inotify_init1(IN_NONBLOCK);
    int w1 = inotify_add_watch(fd, one, WATCHED);
    int w2 = inotify_add_watch(fd, two, WATCHED);
    int own = inotify_add_watch(fd, r, WATCHED);
    printf("wd=%d %d %d\n", w1, w2, own);
    int moved = open(p, O_RDWR | O_NONBLOCK);
    printf("rename=%ld\n", e(rename(p, q)));
    drain(fd, "renamed");
    close(moved);
    drain(fd, "closed");
    int first = open(r, O_RDWR | O_NONBLOCK);
    printf("unlink=%ld\n", e(unlink(r)));
    drain(fd, "unlinked");
    char link[64];
    snprintf(link, sizeof link, "/proc/self/fd/%d", first);
    int again = open(link, O_RDONLY | O_NONBLOCK);
    printf("again=%s\n", again >= 0 ? "open" : strerror(errno));
    drain(fd, "again");
    char got = 0;
    printf("write=%ld read=%ld byte=%c\n", (long)write(first, "x", 1), e(read(again, &got, 1)), got);
    drain(fd, "used");
    close(first);
    drain(fd, "first-closed");
    close(again);
    drain(fd, "last-closed");
    close(fd);
    remove_all();
    return 0;
}

/* The order of exec's closes: a program that runs with an ELF interpreter
 * and then execs a script; an exec whose interpreter is no ELF file; and
 * files only a descriptor holds, a memfd and a removed copy, run through
 * execveat. */
static void exec_child(const char *prog, char *const argv[]) {
    pid_t child = fork();
    if (child == 0) {
        if (chdir(base)) _exit(96);
        execv(prog, argv);
        _exit(errno == ELIBBAD ? 80 : errno == ENOEXEC ? 81 : errno == ENOENT ? 82 : 83);
    }
    int status = 0;
    waitpid(child, &status, 0);
    printf("%s exited=%d\n", strrchr(prog, '/') + 1, WIFEXITED(status) ? WEXITSTATUS(status) : -1);
}
static void execveat_child(int file, const char *label) {
    pid_t child = fork();
    if (child == 0) {
        char *const argv[] = {"fd-prog", "inotify-quiet", NULL};
        char *const envp[] = {NULL};
        syscall(SYS_execveat, file, "", argv, envp, AT_EMPTY_PATH);
        _exit(83);
    }
    int status = 0;
    waitpid(child, &status, 0);
    printf("%s exited=%d\n", label, WIFEXITED(status) ? WEXITSTATUS(status) : -1);
}
static int case_exec_order(void) {
    make_base("exec-order");
    if (mkdir(at("bad"), 0755)) return 92;
    char self[PATH_MAX];
    ssize_t len = readlink("/proc/self/exe", self, sizeof self - 32);
    if (len <= 0) return 95;
    self[len] = 0;
    printf("copied=%d", copy_file(self, at("prog")));
    strcpy(strrchr(self, '/') + 1, "inotify-interp");
    printf(" %d", copy_file(self, at("dyn")));
    printf(" %d", copy_file("/lib/ld-musl-x86_64.so.1", at("inotify-ld.so")));
    printf(" %d\n", copy_file(self, at("bad/dyn")));
    char line[160];
    snprintf(line, sizeof line, "#!%s inotify-quiet\n", at("prog"));
    printf("written=%d", write_file(at("s"), line, 0755));
    printf(" %d\n", write_file(at("bad/inotify-ld.so"), "junk", 0755));
    int fd = inotify_init1(IN_NONBLOCK);
    printf("wd=%d\n", inotify_add_watch(fd, base, WATCHED));
    char *then[] = {at("dyn"), "inotify-then", at("s"), NULL};
    exec_child(at("dyn"), then);
    drain(fd, "then");
    printf("wd=%d\n", inotify_add_watch(fd, at("bad"), WATCHED));
    if (chdir(at("bad"))) return 96;
    char *bad[] = {"dyn", "inotify-quiet", NULL};
    pid_t child = fork();
    if (child == 0) {
        execv("dyn", bad);
        _exit(errno == ELIBBAD ? 80 : errno == ENOEXEC ? 81 : errno == ENOENT ? 82 : 83);
    }
    int status = 0;
    waitpid(child, &status, 0);
    printf("bad exited=%d\n", WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    drain(fd, "bad");
    if (chdir("/")) return 96;
    int memfd = memfd_create("prog", 0);
    int from = open(at("prog"), O_RDONLY);
    struct stat st;
    fstat(from, &st);
    off_t off = 0;
    printf("memfd copied=%d\n", sendfile(memfd, from, &off, st.st_size) == st.st_size);
    close(from);
    snprintf(line, sizeof line, "/proc/self/fd/%d", memfd);
    int mw = inotify_add_watch(fd, line, WATCHED);
    printf("memfd wd=%d\n", mw);
    drain(fd, "memfd-copied");
    execveat_child(memfd, "memfd");
    drain(fd, "memfd");
    close(memfd);
    drain(fd, "memfd-closed");
    int removed = open(at("prog"), O_RDONLY);
    printf("unlink=%ld\n", e(unlink(at("prog"))));
    drain(fd, "unlinked");
    execveat_child(removed, "removed");
    drain(fd, "removed");
    close(removed);
    drain(fd, "removed-closed");
    close(fd);
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
    if (!strcmp(mode, "inotify-content")) return case_content();
    if (!strcmp(mode, "inotify-held")) return case_held();
    if (!strcmp(mode, "inotify-home")) return case_home();
    if (!strcmp(mode, "inotify-running")) return case_running();
    if (!strcmp(mode, "inotify-interpreter")) return case_interpreter();
    if (!strcmp(mode, "inotify-moved")) return case_moved();
    if (!strcmp(mode, "inotify-fifo")) return case_fifo();
    if (!strcmp(mode, "inotify-exec")) return case_exec();
    if (!strcmp(mode, "inotify-instance")) return case_instance();
    if (!strcmp(mode, "inotify-read")) return case_read();
    if (!strcmp(mode, "inotify-fifo-moved")) return case_fifo_moved();
    if (!strcmp(mode, "inotify-exec-order")) return case_exec_order();
    if (!strcmp(mode, "inotify-runner")) return case_runner();
    /* What case_exec_order's dynamic program does: runs argv[2]. */
    if (!strcmp(mode, "inotify-then") && argc > 2) {
        char *const next[] = {argv[2], "inotify-quiet", NULL};
        execv(argv[2], next);
        return 84;
    }
    /* What case_exec runs: nothing. */
    if (!strcmp(mode, "inotify-quiet")) return 0;
    return 2;
}
