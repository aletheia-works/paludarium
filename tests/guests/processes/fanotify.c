/* fanotify, compared with Linux: the calls' errors and their order, the
   marks fdinfo shows, the events of files with the descriptors they give,
   their merging, the file handles and names of the FID modes, the pidfds
   of FAN_REPORT_PIDFD, and what a group without CAP_SYS_ADMIN may do.

   Each case works in a directory of its own under /tmp. A file system
   mark there hears of what other programs do in /tmp too, so only the
   events of the case's own files are shown. Handles, file system IDs,
   descriptors and process IDs differ between runs: the outputs give
   whether they are the ones name_to_handle_at, statfs, readlink and getpid
   give, not their values. The cases run as root. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sched.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#define FAN_ACCESS 0x1
#define FAN_MODIFY 0x2
#define FAN_ATTRIB 0x4
#define FAN_CLOSE_WRITE 0x8
#define FAN_CLOSE_NOWRITE 0x10
#define FAN_OPEN 0x20
#define FAN_MOVED_FROM 0x40
#define FAN_MOVED_TO 0x80
#define FAN_CREATE 0x100
#define FAN_DELETE 0x200
#define FAN_DELETE_SELF 0x400
#define FAN_MOVE_SELF 0x800
#define FAN_OPEN_EXEC 0x1000
#define FAN_Q_OVERFLOW 0x4000
#define FAN_FS_ERROR 0x8000
#define FAN_OPEN_PERM 0x10000
#define FAN_ACCESS_PERM 0x20000
#define FAN_PRE_ACCESS 0x100000
#define FAN_MNT_ATTACH 0x1000000
#define FAN_EVENT_ON_CHILD 0x8000000
#define FAN_RENAME 0x10000000
#define FAN_ONDIR 0x40000000
#define FAN_CLOSE (FAN_CLOSE_WRITE | FAN_CLOSE_NOWRITE)

#define FAN_CLOEXEC 0x1
#define FAN_NONBLOCK 0x2
#define FAN_CLASS_CONTENT 0x4
#define FAN_CLASS_PRE_CONTENT 0x8
#define FAN_UNLIMITED_QUEUE 0x10
#define FAN_REPORT_PIDFD 0x80
#define FAN_REPORT_TID 0x100
#define FAN_REPORT_FID 0x200
#define FAN_REPORT_DIR_FID 0x400
#define FAN_REPORT_NAME 0x800
#define FAN_REPORT_TARGET_FID 0x1000
#define FAN_REPORT_FD_ERROR 0x2000
#define FAN_REPORT_MNT 0x4000
#define FAN_REPORT_DFID_NAME (FAN_REPORT_DIR_FID | FAN_REPORT_NAME)

#define FAN_MARK_ADD 0x1
#define FAN_MARK_REMOVE 0x2
#define FAN_MARK_DONT_FOLLOW 0x4
#define FAN_MARK_ONLYDIR 0x8
#define FAN_MARK_MOUNT 0x10
#define FAN_MARK_IGNORED_MASK 0x20
#define FAN_MARK_IGNORED_SURV_MODIFY 0x40
#define FAN_MARK_FLUSH 0x80
#define FAN_MARK_FILESYSTEM 0x100
#define FAN_MARK_EVICTABLE 0x200
#define FAN_MARK_IGNORE 0x400
#define FAN_MARK_MNTNS 0x110

struct metadata {
    uint32_t event_len;
    uint8_t vers;
    uint8_t reserved;
    uint16_t metadata_len;
    uint64_t mask;
    int32_t fd;
    int32_t pid;
};
struct info_header {
    uint8_t type;
    uint8_t pad;
    uint16_t len;
};
struct handle {
    unsigned bytes;
    int type;
    unsigned char f[128];
};

static long e(long r) { return r < 0 ? -errno : r; }
static long fan_init(unsigned flags, unsigned event_flags) {
    return e(syscall(SYS_fanotify_init, flags, event_flags));
}
static long fan_mark(int fd, unsigned flags, uint64_t mask, int dir, const char *path) {
    return e(syscall(SYS_fanotify_mark, fd, flags, mask, dir, path));
}

static char base[64];
static char *at(const char *name) {
    static char paths[8][128];
    static int next;
    char *p = paths[next++ % 8];
    snprintf(p, sizeof paths[0], "%s/%s", base, name);
    return p;
}
static void make_base(const char *what) {
    snprintf(base, sizeof base, "/tmp/fanotify-%s-XXXXXX", what);
    if (!mkdtemp(base)) {
        perror("mkdtemp");
        exit(90);
    }
}
static int remove_one(const char *path, const struct stat *st, int kind, struct FTW *ftw) {
    (void)st, (void)kind, (void)ftw;
    return remove(path);
}
static void remove_base(void) { nftw(base, remove_one, 16, FTW_DEPTH | FTW_PHYS); }
static void touch(const char *path) {
    int fd = open(path, O_WRONLY | O_CREAT, 0644);
    if (fd >= 0) close(fd);
}

/* The handle name_to_handle_at gives as an identifier (AT_HANDLE_FID). */
static int handle_of(const char *path, struct handle *h) {
    int mount;
    memset(h, 0, sizeof *h);
    h->bytes = sizeof h->f;
    return syscall(SYS_name_to_handle_at, AT_FDCWD, path, h, &mount, 0x200);
}
static int same_handle(const struct handle *a, const unsigned char *record) {
    unsigned bytes;
    int type;
    memcpy(&bytes, record, 4);
    memcpy(&type, record + 4, 4);
    return bytes == a->bytes && type == a->type && !memcmp(record + 8, a->f, bytes);
}
static int same_fsid(const char *path, const unsigned char *fsid) {
    struct statfs fs;
    if (statfs(path, &fs) != 0) return 0;
    return !memcmp(&fs.f_fsid, fsid, 8);
}

/* What a descriptor an event gives is: the path it names under the base,
   or "other". */
static const char *named(int fd, char *out, size_t size) {
    char link[64], target[256];
    snprintf(link, sizeof link, "/proc/self/fd/%d", fd);
    long n = readlink(link, target, sizeof target - 1);
    if (n < 0) return "unreadable";
    target[n] = 0;
    size_t len = strlen(base);
    if (strncmp(target, base, len) == 0) {
        snprintf(out, size, "%s", target[len] ? target + len + 1 : ".");
        return out;
    }
    return "other";
}

/* Reads one buffer of events from `fan` and prints those of the base's
   files: the mask, the descriptor's file, its flags and whether the pid
   is ours (or `child`'s). */
static void show_fd_events(const char *label, int fan, pid_t child) {
    char buf[4096];
    long n = e(read(fan, buf, sizeof buf));
    printf("%s: read=%s\n", label, n < 0 ? "error" : n == 0 ? "0" : "some");
    if (n < 0) {
        printf("  error %ld\n", n);
        return;
    }
    for (char *p = buf; p < buf + n;) {
        struct metadata m;
        memcpy(&m, p, sizeof m);
        char name[256];
        const char *what = m.fd >= 0 ? named(m.fd, name, sizeof name) : "none";
        if (strcmp(what, "other") != 0) {
            int flags = m.fd >= 0 ? fcntl(m.fd, F_GETFL) : -1;
            int cloexec = m.fd >= 0 ? fcntl(m.fd, F_GETFD) : -1;
            printf("  mask=%#llx file=%s len=%u vers=%u meta=%u flags=%#o cloexec=%d pid=%s\n",
                   (unsigned long long)m.mask, what, m.event_len, m.vers, m.metadata_len, flags & ~0100000,
                   cloexec, m.pid == getpid() ? "self" : m.pid == child && child ? "child" : m.pid == 0 ? "0" : "other");
        }
        if (m.fd >= 0) close(m.fd);
        if (m.event_len < sizeof m) break;
        p += m.event_len;
    }
}

static int drain(int fan) {
    char buf[8192];
    int count = 0;
    struct pollfd p = {fan, POLLIN, 0};
    while (poll(&p, 1, 0) == 1) {
        long n = read(fan, buf, sizeof buf);
        if (n <= 0) break;
        for (char *q = buf; q < buf + n;) {
            struct metadata m;
            memcpy(&m, q, sizeof m);
            if (m.fd >= 0) close(m.fd);
            count++;
            if (m.event_len < sizeof m) break;
            q += m.event_len;
        }
    }
    return count;
}

/* fanotify_init's checks, as root and as an unprivileged user. */
static int case_init(void) {
    printf("plain=%ld\n", fan_init(0, 0) >= 0);
    printf("bad flag=%ld\n", fan_init(0x10000, 0));
    printf("bad event flags=%ld rdwr3=%ld trunc=%ld\n", fan_init(0, O_TRUNC), fan_init(0, 3), fan_init(0, O_CREAT));
    printf("ok event flags=%ld\n", fan_init(0, O_RDWR | O_APPEND | O_NONBLOCK | O_SYNC | O_CLOEXEC | O_NOATIME) >= 0);
    printf("both classes=%ld\n", fan_init(FAN_CLASS_CONTENT | FAN_CLASS_PRE_CONTENT, 0));
    printf("fid content=%ld\n", fan_init(FAN_REPORT_FID | FAN_CLASS_CONTENT, 0));
    printf("name alone=%ld\n", fan_init(FAN_REPORT_NAME, 0));
    printf("target alone=%ld target dfid name=%ld\n", fan_init(FAN_REPORT_TARGET_FID | FAN_REPORT_DFID_NAME, 0),
           fan_init(FAN_REPORT_TARGET_FID | FAN_REPORT_DFID_NAME | FAN_REPORT_FID, 0) >= 0);
    printf("mnt content=%ld mnt fid=%ld mnt fd error=%ld mnt=%ld\n", fan_init(FAN_REPORT_MNT | FAN_CLASS_CONTENT, 0),
           fan_init(FAN_REPORT_MNT | FAN_REPORT_FID, 0), fan_init(FAN_REPORT_MNT | FAN_REPORT_FD_ERROR, 0),
           fan_init(FAN_REPORT_MNT, 0) >= 0);
    printf("pidfd tid=%ld\n", fan_init(FAN_REPORT_PIDFD | FAN_REPORT_TID, 0) >= 0);
    int fan = fan_init(FAN_CLOEXEC | FAN_NONBLOCK | FAN_REPORT_FID, O_RDONLY);
    printf("fd flags=%#o cloexec=%d\n", fcntl(fan, F_GETFL) & ~0100000, fcntl(fan, F_GETFD));
    char link[64], target[64] = {0};
    snprintf(link, sizeof link, "/proc/self/fd/%d", fan);
    readlink(link, target, sizeof target - 1);
    printf("link=%s\n", target);
    char path[64];
    snprintf(path, sizeof path, "/proc/self/fdinfo/%d", fan);
    FILE *info = fopen(path, "r");
    char line[256];
    while (info && fgets(line, sizeof line, info))
        if (strncmp(line, "fanotify", 8) == 0) printf("fdinfo %s", line);
    if (info) fclose(info);
    char buf[64];
    printf("read empty=%ld\n", e(read(fan, buf, sizeof buf)));
    printf("read short=%ld\n", e(read(fan, buf, 4)));
    int queued = -1;
    printf("fionread=%ld %d\n", e(ioctl(fan, FIONREAD, &queued)), queued);
    printf("other ioctl=%ld\n", e(ioctl(fan, 0x5401, &queued)));
    printf("lseek=%ld\n", e(lseek(fan, 10, SEEK_SET)));
    struct {
        int fd;
        unsigned response;
    } response = {5, 1};
    printf("write short=%ld\n", e(write(fan, &response, 4)));
    printf("write no event=%ld\n", e(write(fan, &response, sizeof response)));
    response.response = 3;
    printf("write bad=%ld\n", e(write(fan, &response, sizeof response)));
    response.response = 2 | (5u << 24);
    printf("write errno notif=%ld\n", e(write(fan, &response, sizeof response)));
    response.response = 1 | 0x10;
    printf("write audit=%ld\n", e(write(fan, &response, sizeof response)));
    response.fd = -5;
    response.response = 1;
    printf("write negative=%ld\n", e(write(fan, &response, sizeof response)));
    close(fan);

    pid_t child = fork();
    if (child == 0) {
        setresgid(65534, 65534, 65534);
        setresuid(65534, 65534, 65534);
        printf("unprivileged plain=%ld\n", fan_init(0, 0));
        printf("unprivileged fid=%ld\n", fan_init(FAN_REPORT_FID, 0) >= 0);
        printf("unprivileged dfid name=%ld\n", fan_init(FAN_REPORT_DFID_NAME, 0) >= 0);
        printf("unprivileged fid tid=%ld\n", fan_init(FAN_REPORT_FID | FAN_REPORT_TID, 0));
        printf("unprivileged fid queue=%ld\n", fan_init(FAN_REPORT_FID | FAN_UNLIMITED_QUEUE, 0));
        printf("unprivileged bad flag=%ld\n", fan_init(FAN_REPORT_FID | 0x10000, 0));
        _exit(0);
    }
    waitpid(child, NULL, 0);
    return 0;
}

/* fanotify_mark's checks, and the marks fdinfo shows. */
static void show_marks(int fan) {
    char path[64];
    snprintf(path, sizeof path, "/proc/self/fdinfo/%d", fan);
    FILE *info = fopen(path, "r");
    char line[512];
    while (info && fgets(line, sizeof line, info)) {
        if (strncmp(line, "fanotify ", 9) != 0) continue;
        char *p;
        if ((p = strstr(line, "mflags:"))) {
            unsigned mflags, mask, ignored;
            sscanf(p, "mflags:%x mask:%x ignored_mask:%x", &mflags, &mask, &ignored);
            const char *kind = strstr(line, "ino:") ? "inode" : strstr(line, "mnt_id:") ? "mount" : "sb";
            printf("  %s mflags=%x mask=%x ignored=%x", kind, mflags, mask, ignored);
            if (strstr(line, "f_handle:")) {
                unsigned bytes;
                int type;
                char *h = strstr(line, "fhandle-bytes:");
                sscanf(h, "fhandle-bytes:%x fhandle-type:%x", &bytes, &type);
                struct handle want;
                handle_of(base, &want);
                printf(" handle=%s", bytes == want.bytes && type == want.type ? "base-like" : "other");
            }
            printf("\n");
        } else if (strstr(line, "flags:")) {
            printf("  %s", line);
        }
    }
    if (info) fclose(info);
}
static int case_marks(void) {
    make_base("marks");
    touch(at("f"));
    mkdir(at("d"), 0755);
    symlink(at("f"), at("link"));
    int fan = fan_init(0, O_RDONLY);
    int fid = fan_init(FAN_REPORT_FID, O_RDONLY);
    int dfid = fan_init(FAN_REPORT_DFID_NAME, O_RDONLY);
    int content = fan_init(FAN_CLASS_CONTENT, O_RDONLY);
    int target = fan_init(FAN_REPORT_DFID_NAME | FAN_REPORT_FID | FAN_REPORT_TARGET_FID, O_RDONLY);
    printf("high mask=%ld\n", fan_mark(fan, FAN_MARK_ADD, 1ull << 32, AT_FDCWD, at("f")));
    printf("bad flag=%ld\n", fan_mark(fan, FAN_MARK_ADD | 0x800, FAN_OPEN, AT_FDCWD, at("f")));
    printf("no command=%ld two=%ld\n", fan_mark(fan, 0, FAN_OPEN, AT_FDCWD, at("f")),
           fan_mark(fan, FAN_MARK_ADD | FAN_MARK_REMOVE, FAN_OPEN, AT_FDCWD, at("f")));
    printf("no mask=%ld\n", fan_mark(fan, FAN_MARK_ADD, 0, AT_FDCWD, at("f")));
    printf("flush flags=%ld\n", fan_mark(fan, FAN_MARK_FLUSH | FAN_MARK_DONT_FOLLOW, 0, AT_FDCWD, NULL));
    printf("bad event=%ld\n", fan_mark(fan, FAN_MARK_ADD, 0x2000, AT_FDCWD, at("f")));
    printf("both ignores=%ld\n",
           fan_mark(fan, FAN_MARK_ADD | FAN_MARK_IGNORE | FAN_MARK_IGNORED_MASK, FAN_OPEN, AT_FDCWD, at("f")));
    printf("bad fd=%ld not fanotify=%ld\n", fan_mark(-1, FAN_MARK_ADD, FAN_OPEN, AT_FDCWD, at("f")),
           fan_mark(1, FAN_MARK_ADD, FAN_OPEN, AT_FDCWD, at("f")));
    printf("mount event=%ld mntns=%ld\n", fan_mark(fan, FAN_MARK_ADD, FAN_MNT_ATTACH, AT_FDCWD, at("f")),
           fan_mark(fan, FAN_MARK_ADD | FAN_MARK_MNTNS, FAN_OPEN, AT_FDCWD, at("f")));
    /* A permission mark on a file the case never opens, as Linux would
       wait for an answer. */
    touch(at("p"));
    printf("perm notif=%ld perm content=%ld pre content=%ld\n",
           fan_mark(fan, FAN_MARK_ADD, FAN_OPEN_PERM, AT_FDCWD, at("p")),
           fan_mark(content, FAN_MARK_ADD, FAN_OPEN_PERM | FAN_ACCESS_PERM, AT_FDCWD, at("p")),
           fan_mark(content, FAN_MARK_ADD, FAN_PRE_ACCESS, AT_FDCWD, at("p")));
    printf("fs error inode=%ld\n", fan_mark(fid, FAN_MARK_ADD, FAN_FS_ERROR, AT_FDCWD, at("f")));
    printf("evictable mount=%ld\n", fan_mark(fan, FAN_MARK_ADD | FAN_MARK_MOUNT | FAN_MARK_EVICTABLE, FAN_OPEN, AT_FDCWD, base));
    printf("inode event fd mode=%ld fid mount=%ld\n", fan_mark(fan, FAN_MARK_ADD, FAN_CREATE, AT_FDCWD, at("d")),
           fan_mark(fid, FAN_MARK_ADD | FAN_MARK_MOUNT, FAN_CREATE, AT_FDCWD, base));
    printf("rename without name=%ld\n", fan_mark(fid, FAN_MARK_ADD, FAN_RENAME, AT_FDCWD, at("d")));
    printf("missing=%ld\n", fan_mark(fan, FAN_MARK_ADD, FAN_OPEN, AT_FDCWD, at("missing")));
    printf("onlydir file=%ld\n", fan_mark(fan, FAN_MARK_ADD | FAN_MARK_ONLYDIR, FAN_OPEN, AT_FDCWD, at("f")));
    int ffd = open(at("f"), O_RDONLY);
    printf("onlydir fd=%ld\n", fan_mark(fan, FAN_MARK_ADD | FAN_MARK_ONLYDIR, FAN_OPEN, ffd, NULL));
    printf("by fd=%ld bad dfd=%ld\n", fan_mark(fan, FAN_MARK_ADD, FAN_OPEN, ffd, NULL),
           fan_mark(fan, FAN_MARK_ADD, FAN_OPEN, 999, NULL));
    printf("strict non-dir=%ld\n", fan_mark(target, FAN_MARK_ADD, FAN_CREATE, AT_FDCWD, at("f")));
    printf("strict rename non-dir=%ld\n", fan_mark(dfid, FAN_MARK_ADD, FAN_RENAME, AT_FDCWD, at("f")));
    printf("old api non-dir=%ld\n", fan_mark(dfid, FAN_MARK_ADD, FAN_CREATE | FAN_ONDIR, AT_FDCWD, at("f")));
    printf("ignore dir=%ld ignore mount=%ld\n", fan_mark(fan, FAN_MARK_ADD | FAN_MARK_IGNORE, FAN_OPEN, AT_FDCWD, at("d")),
           fan_mark(fan, FAN_MARK_ADD | FAN_MARK_IGNORE | FAN_MARK_MOUNT, FAN_OPEN, AT_FDCWD, base));
    printf("remove missing=%ld\n", fan_mark(fan, FAN_MARK_REMOVE, FAN_OPEN, AT_FDCWD, at("d")));
    printf("proc fid sb=%ld proc fid inode=%ld\n",
           fan_mark(fid, FAN_MARK_ADD | FAN_MARK_FILESYSTEM, FAN_OPEN, AT_FDCWD, "/proc/self/status"),
           fan_mark(fid, FAN_MARK_ADD, FAN_OPEN, AT_FDCWD, "/proc/self/status"));
    printf("proc perm=%ld\n", fan_mark(content, FAN_MARK_ADD, FAN_OPEN_PERM, AT_FDCWD, "/proc/self/status"));
    int pipes[2];
    pipe(pipes);
    printf("pipe sb=%ld pipe inode=%ld\n", fan_mark(fan, FAN_MARK_ADD | FAN_MARK_FILESYSTEM, FAN_OPEN, pipes[0], NULL),
           fan_mark(fan, FAN_MARK_ADD, FAN_ACCESS, pipes[0], NULL));
    close(pipes[0]);
    close(pipes[1]);

    /* What the marks become, as fdinfo shows them. */
    int g = fan_init(FAN_REPORT_DFID_NAME, O_RDONLY);
    printf("dir=%ld\n", fan_mark(g, FAN_MARK_ADD, FAN_CREATE | FAN_ONDIR | FAN_EVENT_ON_CHILD, AT_FDCWD, base));
    printf("add=%ld\n", fan_mark(g, FAN_MARK_ADD, FAN_DELETE, AT_FDCWD, base));
    printf("file=%ld\n", fan_mark(g, FAN_MARK_ADD, FAN_OPEN, AT_FDCWD, at("f")));
    printf("link=%ld\n", fan_mark(g, FAN_MARK_ADD | FAN_MARK_DONT_FOLLOW, FAN_OPEN, AT_FDCWD, at("link")));
    printf("ignore=%ld\n", fan_mark(g, FAN_MARK_ADD | FAN_MARK_IGNORED_MASK, FAN_CLOSE | FAN_ONDIR, AT_FDCWD, at("f")));
    printf("ignore surv=%ld\n",
           fan_mark(g, FAN_MARK_ADD | FAN_MARK_IGNORED_MASK | FAN_MARK_IGNORED_SURV_MODIFY, FAN_ACCESS, AT_FDCWD, at("f")));
    printf("ignore flags on old=%ld\n", fan_mark(g, FAN_MARK_ADD | FAN_MARK_IGNORE, FAN_ACCESS, AT_FDCWD, at("f")));
    printf("new ignore=%ld\n", fan_mark(g, FAN_MARK_ADD | FAN_MARK_IGNORE | FAN_MARK_IGNORED_SURV_MODIFY,
                                         FAN_ACCESS | FAN_ONDIR, AT_FDCWD, at("d")));
    printf("old ignore on new=%ld\n", fan_mark(g, FAN_MARK_ADD | FAN_MARK_IGNORED_MASK, FAN_ACCESS, AT_FDCWD, at("d")));
    printf("evictable=%ld\n", fan_mark(g, FAN_MARK_ADD | FAN_MARK_EVICTABLE, FAN_OPEN, AT_FDCWD, at("d")));
    printf("evictable new=%ld\n", fan_mark(g, FAN_MARK_ADD | FAN_MARK_EVICTABLE, FAN_CLOSE, AT_FDCWD, at("link")));
    printf("sb=%ld\n", fan_mark(g, FAN_MARK_ADD | FAN_MARK_FILESYSTEM, FAN_ATTRIB, AT_FDCWD, base));
    printf("mount=%ld\n", fan_mark(g, FAN_MARK_ADD | FAN_MARK_MOUNT, FAN_CLOSE_WRITE, AT_FDCWD, base));
    show_marks(g);
    printf("remove part=%ld\n", fan_mark(g, FAN_MARK_REMOVE, FAN_DELETE, AT_FDCWD, base));
    printf("remove rest=%ld\n", fan_mark(g, FAN_MARK_REMOVE, FAN_CREATE | FAN_ONDIR | FAN_EVENT_ON_CHILD, AT_FDCWD, base));
    printf("remove again=%ld\n", fan_mark(g, FAN_MARK_REMOVE, FAN_CREATE, AT_FDCWD, base));
    printf("remove ignore=%ld\n", fan_mark(g, FAN_MARK_REMOVE | FAN_MARK_IGNORED_MASK, FAN_CLOSE, AT_FDCWD, at("f")));
    show_marks(g);
    printf("flush inodes=%ld\n", fan_mark(g, FAN_MARK_FLUSH, 0, AT_FDCWD, NULL));
    show_marks(g);
    printf("flush sb=%ld\n", fan_mark(g, FAN_MARK_FLUSH | FAN_MARK_FILESYSTEM, 0, AT_FDCWD, NULL));
    show_marks(g);
    remove_base();
    return 0;
}

/* The events of a file and a directory, with the descriptors they give. */
static int case_events(void) {
    make_base("events");
    touch(at("f"));
    mkdir(at("d"), 0755);
    int fan = fan_init(FAN_NONBLOCK, O_RDONLY | O_CLOEXEC);
    printf("file mark=%ld\n", fan_mark(fan, FAN_MARK_ADD, FAN_OPEN | FAN_ACCESS | FAN_MODIFY | FAN_CLOSE, AT_FDCWD, at("f")));
    int fd = open(at("f"), O_RDWR);
    char c = 'x';
    write(fd, &c, 1);
    lseek(fd, 0, SEEK_SET);
    read(fd, &c, 1);
    read(fd, &c, 1);
    close(fd);
    show_fd_events("file", fan, 0);
    int queued = -1;
    ioctl(fan, FIONREAD, &queued);
    printf("fionread after=%d\n", queued);
    /* Merged while queued: two reads of the same file. */
    fd = open(at("f"), O_RDONLY);
    show_fd_events("open", fan, 0);
    pread(fd, &c, 1, 0);
    pread(fd, &c, 1, 0);
    ioctl(fan, FIONREAD, &queued);
    printf("fionread merged=%d\n", queued);
    show_fd_events("reads", fan, 0);
    close(fd);
    show_fd_events("close", fan, 0);
    /* Truncation by path is no path event: no descriptor to give. */
    truncate(at("f"), 0);
    show_fd_events("truncate", fan, 0);
    /* A directory's children, with FAN_EVENT_ON_CHILD, and the directory
       itself with FAN_ONDIR. */
    touch(at("d/g"));
    printf("dir mark=%ld\n", fan_mark(fan, FAN_MARK_ADD, FAN_OPEN | FAN_CLOSE | FAN_EVENT_ON_CHILD, AT_FDCWD, at("d")));
    fd = open(at("d/g"), O_RDONLY);
    close(fd);
    fd = open(at("d"), O_RDONLY | O_DIRECTORY);
    close(fd);
    show_fd_events("children", fan, 0);
    printf("ondir=%ld\n", fan_mark(fan, FAN_MARK_ADD, FAN_OPEN | FAN_ONDIR, AT_FDCWD, at("d")));
    fd = open(at("d"), O_RDONLY | O_DIRECTORY);
    close(fd);
    show_fd_events("ondir", fan, 0);
    /* An ignore mask, which a modification ends. */
    printf("ignore=%ld\n", fan_mark(fan, FAN_MARK_ADD | FAN_MARK_IGNORED_MASK, FAN_CLOSE_NOWRITE, AT_FDCWD, at("d/g")));
    fd = open(at("d/g"), O_RDONLY);
    close(fd);
    show_fd_events("ignored", fan, 0);
    fd = open(at("d/g"), O_WRONLY);
    write(fd, &c, 1);
    close(fd);
    fd = open(at("d/g"), O_RDONLY);
    close(fd);
    show_fd_events("after modify", fan, 0);
    /* A child process's events. */
    pid_t child = fork();
    if (child == 0) {
        int f = open(at("f"), O_RDONLY);
        close(f);
        _exit(0);
    }
    waitpid(child, NULL, 0);
    show_fd_events("child", fan, child);
    /* A mount mark and a file system mark, on /tmp. */
    int mnt = fan_init(FAN_NONBLOCK, O_RDONLY);
    printf("mount mark=%ld\n", fan_mark(mnt, FAN_MARK_ADD | FAN_MARK_MOUNT, FAN_OPEN | FAN_CLOSE_WRITE, AT_FDCWD, base));
    fd = open(at("d/g"), O_WRONLY);
    close(fd);
    show_fd_events("mount", mnt, 0);
    close(mnt);
    int sb = fan_init(FAN_NONBLOCK, O_RDONLY);
    printf("sb mark=%ld\n", fan_mark(sb, FAN_MARK_ADD | FAN_MARK_FILESYSTEM, FAN_CLOSE_WRITE, AT_FDCWD, base));
    fd = open(at("d/g"), O_WRONLY);
    close(fd);
    show_fd_events("sb", sb, 0);
    close(sb);
    /* A descriptor that fails to open, with and without FAN_REPORT_FD_ERROR. */
    int err = fan_init(FAN_NONBLOCK | FAN_REPORT_FD_ERROR, O_RDWR);
    mkdir(at("e"), 0755);
    printf("fd error mark=%ld\n", fan_mark(err, FAN_MARK_ADD, FAN_OPEN | FAN_ONDIR, AT_FDCWD, at("e")));
    fd = open(at("e"), O_RDONLY | O_DIRECTORY);
    close(fd);
    char buf[256];
    long n = e(read(err, buf, sizeof buf));
    struct metadata m;
    memcpy(&m, buf, sizeof m);
    printf("fd error read=%ld fd=%d\n", n > 0 ? 1 : n, n > 0 ? m.fd : 0);
    int plain = fan_init(FAN_NONBLOCK, O_RDWR);
    fan_mark(plain, FAN_MARK_ADD, FAN_OPEN | FAN_ONDIR, AT_FDCWD, at("e"));
    fd = open(at("e"), O_RDONLY | O_DIRECTORY);
    close(fd);
    printf("fd error plain=%ld\n", e(read(plain, buf, sizeof buf)));
    printf("fd error then=%ld\n", e(read(plain, buf, sizeof buf)));
    /* The file's end ends its marks. */
    unlink(at("f"));
    printf("after unlink remove=%ld\n", fan_mark(fan, FAN_MARK_REMOVE, FAN_OPEN, AT_FDCWD, at("d")));
    drain(fan);
    remove_base();
    return 0;
}

/* The records of the FID modes, of the base and the files the cases make
   in it, by the handles they had when the case looked ([remember]). */
static struct handle known[5];
static const char *known_names[5] = {"base", "d", "f", "d/g", "h"};
static void remember(void) {
    handle_of(base, &known[0]);
    handle_of(at("d"), &known[1]);
    handle_of(at("f"), &known[2]);
    handle_of(at("d/g"), &known[3]);
    handle_of(at("h"), &known[4]);
}
static void show_fid_events(const char *label, int fan) {
    char buf[8192];
    long n = e(read(fan, buf, sizeof buf));
    printf("%s: read=%s\n", label, n < 0 ? "error" : "some");
    if (n < 0) {
        printf("  error %ld\n", n);
        return;
    }
    for (char *p = buf; p < buf + n;) {
        struct metadata m;
        memcpy(&m, p, sizeof m);
        int ours = 0;
        char line[1024];
        /* The lengths of the handles are the file system's: /tmp's may be
           another on Linux, so they are not shown. */
        int used = snprintf(line, sizeof line, "  mask=%#llx fd=%d pid=%s", (unsigned long long)m.mask, m.fd,
                            m.pid == getpid() ? "self" : m.pid == 0 ? "0" : "other");
        for (char *q = p + m.metadata_len; q < p + m.event_len;) {
            struct info_header hdr;
            memcpy(&hdr, q, sizeof hdr);
            if (hdr.len == 0) break;
            if (hdr.type == 4) {
                int pidfd;
                memcpy(&pidfd, q + 4, 4);
                used += snprintf(line + used, sizeof line - used, " [pidfd %s]", pidfd >= 0 ? "fd" : pidfd == -1 ? "none" : "error");
                if (pidfd >= 0) close(pidfd);
            } else {
                const unsigned char *record = (unsigned char *)q + 12;
                const char *which = "other";
                for (int k = 0; k < 5; k++)
                    if (known[k].bytes && same_handle(&known[k], record)) which = known_names[k];
                if (strcmp(which, "other") != 0) ours = 1;
                unsigned bytes;
                memcpy(&bytes, record, 4);
                const char *name = (const char *)record + 8 + bytes;
                int has_name = hdr.type == 2 || hdr.type == 10 || hdr.type == 12;
                used += snprintf(line + used, sizeof line - used, " [type %u %s fsid=%s%s%s]", hdr.type, which,
                                 same_fsid(base, (unsigned char *)q + 4) ? "statfs" : "other", has_name ? " name=" : "",
                                 has_name ? name : "");
            }
            q += hdr.len;
        }
        if (ours) printf("%s\n", line);
        if (m.fd >= 0) close(m.fd);
        if (m.event_len < sizeof m) break;
        p += m.event_len;
    }
}
static int case_fid(void) {
    make_base("fid");
    mkdir(at("d"), 0755);
    touch(at("f"));
    int fid = fan_init(FAN_NONBLOCK | FAN_REPORT_FID, O_RDONLY);
    printf("fid dir=%ld\n", fan_mark(fid, FAN_MARK_ADD,
                                      FAN_CREATE | FAN_DELETE | FAN_MOVED_FROM | FAN_MOVED_TO | FAN_ATTRIB | FAN_ONDIR |
                                          FAN_EVENT_ON_CHILD | FAN_OPEN | FAN_CLOSE | FAN_MODIFY | FAN_DELETE_SELF,
                                      AT_FDCWD, base));
    printf("fid file=%ld\n", fan_mark(fid, FAN_MARK_ADD, FAN_DELETE_SELF | FAN_MOVE_SELF | FAN_ATTRIB, AT_FDCWD, at("f")));
    int dfid = fan_init(FAN_NONBLOCK | FAN_REPORT_DFID_NAME, O_RDONLY);
    printf("dfid sb=%ld\n", fan_mark(dfid, FAN_MARK_ADD | FAN_MARK_FILESYSTEM,
                                      FAN_CREATE | FAN_DELETE | FAN_MOVED_FROM | FAN_MOVED_TO | FAN_ATTRIB | FAN_ONDIR |
                                          FAN_OPEN | FAN_CLOSE_WRITE | FAN_DELETE_SELF | FAN_MOVE_SELF | FAN_RENAME,
                                      AT_FDCWD, base));
    int target = fan_init(FAN_NONBLOCK | FAN_REPORT_DFID_NAME | FAN_REPORT_FID | FAN_REPORT_TARGET_FID, O_RDONLY);
    printf("target dir=%ld\n", fan_mark(target, FAN_MARK_ADD,
                                         FAN_CREATE | FAN_DELETE | FAN_MOVED_FROM | FAN_MOVED_TO | FAN_ONDIR | FAN_RENAME |
                                             FAN_ATTRIB | FAN_EVENT_ON_CHILD,
                                         AT_FDCWD, base));
    int dir_only = fan_init(FAN_NONBLOCK | FAN_REPORT_DIR_FID, O_RDONLY);
    printf("dir only=%ld\n", fan_mark(dir_only, FAN_MARK_ADD, FAN_CREATE | FAN_ATTRIB | FAN_EVENT_ON_CHILD | FAN_ONDIR,
                                       AT_FDCWD, base));

    touch(at("h"));
    mkdir(at("d/g"), 0755);
    remember();
    chmod(at("f"), 0600);
    chmod(at("d"), 0700);
    int fd = open(at("f"), O_WRONLY);
    write(fd, "x", 1);
    close(fd);
    rename(at("h"), at("d/h"));
    rename(at("d/h"), at("h"));
    link(at("f"), at("f2"));
    unlink(at("f2"));
    show_fid_events("fid", fid);
    show_fid_events("dfid", dfid);
    show_fid_events("target", target);
    show_fid_events("dir only", dir_only);
    /* Ends: of a file, and of a directory. */
    unlink(at("h"));
    unlink(at("f"));
    rmdir(at("d/g"));
    show_fid_events("ends fid", fid);
    show_fid_events("ends dfid", dfid);
    show_fid_events("ends target", target);
    int queued = -1;
    ioctl(dir_only, FIONREAD, &queued);
    printf("dir only queued=%d\n", queued);
    drain(dir_only);
    /* A read buffer too small for the first event. */
    touch(at("small"));
    char buf[24];
    printf("small=%ld\n", e(read(dfid, buf, sizeof buf)));
    drain(dfid);
    remove_base();
    return 0;
}

/* FAN_REPORT_PIDFD and FAN_REPORT_TID. */
static int case_pidfd(void) {
    make_base("pidfd");
    touch(at("f"));
    int fan = fan_init(FAN_NONBLOCK | FAN_REPORT_FID | FAN_REPORT_PIDFD, O_RDONLY);
    printf("mark=%ld\n", fan_mark(fan, FAN_MARK_ADD, FAN_OPEN | FAN_CLOSE, AT_FDCWD, at("f")));
    int ready[2], done[2];
    pipe(ready);
    pipe(done);
    pid_t child = fork();
    if (child == 0) {
        int f = open(at("f"), O_RDONLY);
        close(f);
        write(ready[1], "r", 1);
        char c;
        read(done[0], &c, 1);
        _exit(0);
    }
    char c;
    read(ready[0], &c, 1);
    char buf[4096];
    long n = e(read(fan, buf, sizeof buf));
    printf("read=%ld\n", n > 0 ? 1 : n);
    for (char *p = buf; n > 0 && p < buf + n;) {
        struct metadata m;
        memcpy(&m, p, sizeof m);
        for (char *q = p + m.metadata_len; q < p + m.event_len;) {
            struct info_header hdr;
            memcpy(&hdr, q, sizeof hdr);
            if (hdr.type == 4) {
                int pidfd;
                memcpy(&pidfd, q + 4, 4);
                printf("  mask=%#llx pid=%s pidfd=%s cloexec=%d signal=%ld\n", (unsigned long long)m.mask,
                       m.pid == child ? "child" : "other", pidfd >= 0 ? "fd" : "none", fcntl(pidfd, F_GETFD),
                       e(syscall(SYS_pidfd_send_signal, pidfd, 0, NULL, 0)));
                close(pidfd);
            }
            if (hdr.len == 0) break;
            q += hdr.len;
        }
        p += m.event_len;
    }
    write(done[1], "d", 1);
    waitpid(child, NULL, 0);
    remove_base();
    return 0;
}

/* A group without CAP_SYS_ADMIN. */
static int case_unprivileged(void) {
    make_base("unpriv");
    chmod(base, 0777);
    touch(at("f"));
    chmod(at("f"), 0644);
    touch(at("secret"));
    chmod(at("secret"), 0600);
    pid_t child = fork();
    if (child == 0) {
        setresgid(65534, 65534, 65534);
        setresuid(65534, 65534, 65534);
        int fan = fan_init(FAN_NONBLOCK | FAN_REPORT_FID, O_RDONLY);
        printf("inode=%ld\n", fan_mark(fan, FAN_MARK_ADD, FAN_OPEN | FAN_CLOSE | FAN_ATTRIB, AT_FDCWD, at("f")));
        printf("mount=%ld\n", fan_mark(fan, FAN_MARK_ADD | FAN_MARK_MOUNT, FAN_OPEN, AT_FDCWD, base));
        printf("sb=%ld\n", fan_mark(fan, FAN_MARK_ADD | FAN_MARK_FILESYSTEM, FAN_OPEN, AT_FDCWD, base));
        printf("unreadable=%ld\n", fan_mark(fan, FAN_MARK_ADD, FAN_OPEN, AT_FDCWD, at("secret")));
        int f = open(at("f"), O_RDONLY);
        close(f);
        remember();
        show_fid_events("own", fan);
        _exit(0);
    }
    /* The parent's own events, as the child's group sees them. */
    waitpid(child, NULL, 0);
    remove_base();
    return 0;
}

/* A child that opens `path` for reading: its exit status is 0 when the
   open succeeded, or the errno it failed with. It first closes its copy
   of the group `fan`, whose last close would otherwise be its own. */
static pid_t open_in_child(const char *path, int fan) {
    fflush(stdout);
    pid_t child = fork();
    if (child == 0) {
        close(fan);
        int fd = open(path, O_RDONLY);
        if (fd < 0) _exit(errno);
        close(fd);
        _exit(0);
    }
    return child;
}
static int child_result(pid_t child) {
    int status;
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status)) return -1;
    return WEXITSTATUS(status);
}
/* Reads one permission event from `fan`, which waits for it: the mask,
   the file it names, whether the pid is `child`'s; its descriptor. */
static int read_perm(const char *label, int fan, pid_t child) {
    char buf[256];
    long n = e(read(fan, buf, sizeof buf));
    if (n < (long)sizeof(struct metadata)) {
        printf("%s: read=%ld\n", label, n);
        return -1;
    }
    struct metadata m;
    memcpy(&m, buf, sizeof m);
    char name[256];
    printf("%s: mask=%#llx file=%s pid=%s more=%d\n", label, (unsigned long long)m.mask,
           m.fd >= 0 ? named(m.fd, name, sizeof name) : "none", m.pid == child ? "child" : "other",
           n > (long)m.event_len);
    return m.fd;
}
static long respond(int fan, int fd, uint32_t response) {
    struct {
        int32_t fd;
        uint32_t response;
    } r = {fd, response};
    return e(write(fan, &r, sizeof r));
}

/* Permission events (FAN_OPEN_PERM): an open of a marked file waits for
   the group's answer, which a read event's descriptor names; FAN_DENY
   fails it with EPERM, FAN_ALLOW lets it through, and so does the group's
   close. A notification group hears FAN_OPEN only of an open let
   through, and no close of a denied one. */
static int case_perm(void) {
    make_base("perm");
    touch(at("f"));
    int fan = fan_init(FAN_CLASS_CONTENT, O_RDONLY);
    int notif = fan_init(FAN_NONBLOCK, O_RDONLY);
    if (fan < 0 || notif < 0) return 80;
    printf("mark=%ld\n", fan_mark(fan, FAN_MARK_ADD, FAN_OPEN_PERM, AT_FDCWD, at("f")));
    printf("notif=%ld\n", fan_mark(notif, FAN_MARK_ADD, FAN_OPEN | FAN_CLOSE, AT_FDCWD, at("f")));
    /* A response no read event waits by. */
    printf("unknown=%ld negative=%ld\n", respond(fan, 99, 1), respond(fan, -1, 1));
    pid_t child = open_in_child(at("f"), fan);
    int fd = read_perm("deny", fan, child);
    printf("deny errno=%ld\n", respond(fan, fd, 2 | (1u << 24)));
    printf("deny=%ld\n", respond(fan, fd, 2));
    printf("again=%ld\n", respond(fan, fd, 1));
    if (fd >= 0) close(fd);
    printf("denied child=%d\n", child_result(child));
    show_fd_events("after deny", notif, child);
    child = open_in_child(at("f"), fan);
    fd = read_perm("allow", fan, child);
    printf("allow=%ld\n", respond(fan, fd, 1));
    if (fd >= 0) close(fd);
    printf("allowed child=%d\n", child_result(child));
    show_fd_events("after allow", notif, child);
    /* The group's close lets through what waits, read or not. */
    child = open_in_child(at("f"), fan);
    fd = read_perm("unanswered", fan, child);
    if (fd >= 0) close(fd);
    close(fan);
    printf("closed child=%d\n", child_result(child));
    show_fd_events("after close", notif, child);
    close(notif);
    remove_base();
    return 0;
}

/* The mount ID statx gives for `path` (STATX_MNT_ID), or 0. */
static uint64_t mount_of(const char *path) {
    unsigned char buf[256] = {0};
    if (syscall(SYS_statx, AT_FDCWD, path, 0, 0x1000, buf) != 0) return 0;
    uint64_t id;
    memcpy(&id, buf + 144, 8);
    return id;
}
/* The mnt_id of each mount mark fdinfo shows for `fan`, as whose mount it
   is: `a`'s, `b`'s or another's. */
static void show_mount_marks(int fan, uint64_t a, uint64_t b) {
    char path[64];
    snprintf(path, sizeof path, "/proc/self/fdinfo/%d", fan);
    FILE *info = fopen(path, "r");
    char line[512];
    while (info && fgets(line, sizeof line, info)) {
        char *p = strstr(line, "mnt_id:");
        if (!p) continue;
        unsigned long long id = strtoull(p + 7, NULL, 16);
        printf("  mount mark of %s\n", id == a ? "a" : id == b ? "b" : "another");
    }
    if (info) fclose(info);
}

/* A mount mark hears only of its own mount: in a mount namespace of its
   own, a tmpfs at a and a bind mount of it at b, so one file system with
   two mounts. A mark on a hears of a/f, not of b/f, the same file, and
   fdinfo gives the mark's mount by its ID. */
static int case_mounts(void) {
    make_base("mounts");
    mkdir(at("a"), 0755);
    mkdir(at("b"), 0755);
    printf("unshare=%ld\n", e(unshare(CLONE_NEWNS)));
    printf("private=%ld\n", e(mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL)));
    printf("tmpfs=%ld\n", e(mount("none", at("a"), "tmpfs", 0, NULL)));
    touch(at("a/f"));
    printf("bind=%ld\n", e(mount(at("a"), at("b"), NULL, MS_BIND, NULL)));
    uint64_t a = mount_of(at("a")), b = mount_of(at("b"));
    printf("own ids=%d same file=%d\n", a != 0 && b != 0 && a != b, mount_of(at("a/f")) == a);
    int fan = fan_init(FAN_NONBLOCK, O_RDONLY);
    if (fan < 0) return 80;
    printf("mark a=%ld\n", fan_mark(fan, FAN_MARK_ADD | FAN_MARK_MOUNT, FAN_OPEN | FAN_CLOSE_WRITE, AT_FDCWD, at("a")));
    show_mount_marks(fan, a, b);
    touch(at("b/f"));
    show_fd_events("through b", fan, 0);
    touch(at("a/f"));
    show_fd_events("through a", fan, 0);
    /* A mark on b too: each mount's events are its own mark's. */
    printf("mark b=%ld\n", fan_mark(fan, FAN_MARK_ADD | FAN_MARK_MOUNT, FAN_OPEN, AT_FDCWD, at("b")));
    show_mount_marks(fan, a, b);
    touch(at("b/f"));
    show_fd_events("through b, marked", fan, 0);
    /* Removing a's mark leaves b's. */
    printf("remove a=%ld\n", fan_mark(fan, FAN_MARK_REMOVE | FAN_MARK_MOUNT, FAN_OPEN | FAN_CLOSE_WRITE, AT_FDCWD, at("a")));
    show_mount_marks(fan, a, b);
    touch(at("a/f"));
    show_fd_events("through a, unmarked", fan, 0);
    /* A descriptor names its mount for a mark too (dfd, NULL path). */
    int dir = open(at("a"), O_RDONLY | O_DIRECTORY);
    printf("mark a by descriptor=%ld\n", fan_mark(fan, FAN_MARK_ADD | FAN_MARK_MOUNT, FAN_CLOSE_WRITE, dir, NULL));
    close(dir);
    show_mount_marks(fan, a, b);
    close(fan);
    printf("umount=%ld %ld\n", e(umount2(at("b"), 0)), e(umount2(at("a"), 0)));
    remove_base();
    return 0;
}

int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "";
    setvbuf(stdout, NULL, _IOLBF, 0);
    alarm(20);
    if (!strcmp(mode, "fanotify-init")) return case_init();
    if (!strcmp(mode, "fanotify-marks")) return case_marks();
    if (!strcmp(mode, "fanotify-events")) return case_events();
    if (!strcmp(mode, "fanotify-fid")) return case_fid();
    if (!strcmp(mode, "fanotify-pidfd")) return case_pidfd();
    if (!strcmp(mode, "fanotify-unprivileged")) return case_unprivileged();
    if (!strcmp(mode, "fanotify-mounts")) return case_mounts();
    if (!strcmp(mode, "fanotify-perm")) return case_perm();
    printf("unknown mode %s\n", mode);
    return 2;
}
