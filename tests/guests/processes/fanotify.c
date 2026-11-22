/* fanotify, compared with Linux: the calls' errors and their order, the
   marks fdinfo shows, the events of files with the descriptors they give,
   their merging (within the newest 128 of a bucket), the marks that go
   with a superblock, the file handles and names of the FID modes, the pidfds
   of FAN_REPORT_PIDFD, the mount events of FAN_REPORT_MNT (moves too),
   what a group without CAP_SYS_ADMIN may do, and the evictable marks
   /proc/sys/vm/drop_caches evicts.

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
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
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
#define FAN_OPEN_EXEC_PERM 0x40000
#define FAN_PRE_ACCESS 0x100000
#define FAN_MNT_ATTACH 0x1000000
#define FAN_MNT_DETACH 0x2000000
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
    /* An unmounted mount's marks go with it, and a new mount at b, which
       may take its ID, is not marked. */
    printf("umount b=%ld\n", e(umount2(at("b"), 0)));
    show_mount_marks(fan, a, b);
    printf("tmpfs at b=%ld\n", e(mount("none", at("b"), "tmpfs", 0, NULL)));
    touch(at("b/g"));
    show_fd_events("through the new b", fan, 0);
    close(fan);
    printf("umount=%ld %ld\n", e(umount2(at("b"), 0)), e(umount2(at("a"), 0)));
    remove_base();
    return 0;
}

/* The unique mount ID statx gives for `path` (STATX_MNT_ID_UNIQUE), or 0. */
static uint64_t unique_of(const char *path) {
    unsigned char buf[256] = {0};
    if (syscall(SYS_statx, AT_FDCWD, path, 0, 0x4000, buf) != 0) return 0;
    uint32_t got;
    memcpy(&got, buf, 4);
    if (!(got & 0x4000)) return 0;
    uint64_t id;
    memcpy(&id, buf + 144, 8);
    return id;
}
static struct {
    const char *name;
    uint64_t id;
} seen_mounts[16];
static int seen_count;
/* Gives `path`'s mount the name `name` in the events shown. */
static void name_mount_at(const char *name, const char *path) {
    if (seen_count == 16) return;
    seen_mounts[seen_count].name = name;
    seen_mounts[seen_count++].id = unique_of(path);
}
static void name_mount(const char *name) { name_mount_at(name, at(name)); }
static const char *mount_name(uint64_t id) {
    for (int i = 0; i < seen_count; i++)
        if (seen_mounts[i].id && seen_mounts[i].id == id) return seen_mounts[i].name;
    return "another";
}
/* Each mount event queued for `fan`: its mask, descriptor, pid, length,
   and its info records, the mount's by the name it was mounted at. */
static void show_mount_events(const char *label, int fan) {
    printf("%s:\n", label);
    char buf[4096] __attribute__((aligned(8)));
    for (;;) {
        ssize_t n = read(fan, buf, sizeof buf);
        if (n <= 0) {
            if (n < 0 && errno != EAGAIN) printf("  read=%d\n", -errno);
            return;
        }
        for (ssize_t at_ = 0; at_ < n;) {
            struct metadata m;
            memcpy(&m, buf + at_, sizeof m);
            printf("  mask=%llx fd=%d pid=%s len=%u", (unsigned long long)m.mask, m.fd,
                   m.pid == getpid() ? "self" : "other", m.event_len);
            for (uint32_t r = m.metadata_len; r + sizeof(struct info_header) <= m.event_len;) {
                struct info_header h;
                memcpy(&h, buf + at_ + r, sizeof h);
                if (h.type == 7 && h.len == 16) {
                    uint64_t id;
                    memcpy(&id, buf + at_ + r + 8, 8);
                    printf(" mount=%s", mount_name(id));
                } else {
                    printf(" info=%d/%d", h.type, h.len);
                }
                if (!h.len) break;
                r += h.len;
            }
            printf("\n");
            if (!m.event_len) return;
            at_ += m.event_len;
        }
    }
}

/* How many mount namespace marks fdinfo shows for `fan`. */
static int namespace_marks(int fan) {
    char path[64], line[512];
    snprintf(path, sizeof path, "/proc/self/fdinfo/%d", fan);
    FILE *info = fopen(path, "r");
    int n = 0;
    while (info && fgets(line, sizeof line, info)) n += strstr(line, "fanotify mnt_ns:") != NULL;
    if (info) fclose(info);
    return n;
}

/* A mount namespace that ends with its last process: a child unshares
   one, a copy of this one, and waits; the group marks it by the child's
   /proc/<pid>/ns/mnt and lets the child exit. Each of its mounts goes,
   those mountinfo shows and the one below its root, before the wait ends
   (exit_task_namespaces comes before exit_notify), each a FAN_MNT_DETACH
   with the child's pid. */
static void show_namespace_exit(int fan) {
    int ready[2], go[2];
    if (pipe(ready) || pipe(go)) return;
    pid_t child = fork();
    if (child == 0) {
        char c = unshare(CLONE_NEWNS) == 0 ? 'r' : 'x';
        if (write(ready[1], &c, 1) != 1 || read(go[0], &c, 1) != 1) _exit(1);
        _exit(0);
    }
    char c = 0;
    if (read(ready[0], &c, 1) != 1 || c != 'r') {
        printf("child unshare failed\n");
        return;
    }
    char path[64], line[512];
    snprintf(path, sizeof path, "/proc/%d/mountinfo", child);
    FILE *info = fopen(path, "r");
    int listed = 0;
    while (info && fgets(line, sizeof line, info)) listed++;
    if (info) fclose(info);
    snprintf(path, sizeof path, "/proc/%d/ns/mnt", child);
    printf("mark child namespace=%ld\n", fan_mark(fan, FAN_MARK_ADD | FAN_MARK_MNTNS, FAN_MNT_DETACH, AT_FDCWD, path));
    if (write(go[1], "g", 1) != 1) return;
    int status;
    waitpid(child, &status, 0);
    int events = 0, detach = 0, from_child = 0;
    char buf[8192] __attribute__((aligned(8)));
    ssize_t n;
    while ((n = read(fan, buf, sizeof buf)) > 0) {
        for (ssize_t at_ = 0; at_ < n;) {
            struct metadata m;
            memcpy(&m, buf + at_, sizeof m);
            events++;
            detach += m.mask == FAN_MNT_DETACH;
            from_child += m.pid == child;
            if (!m.event_len) break;
            at_ += m.event_len;
        }
    }
    printf("child exit: mounts=%s detach=%d child's pid=%d\n",
           events == listed + 1 ? "mountinfo's and the one below the root" : "other",
           detach == events, from_child == events);
    close(ready[0]);
    close(ready[1]);
    close(go[0]);
    close(go[1]);
}

/* FAN_MNT_ATTACH and FAN_MNT_DETACH: a group with FAN_REPORT_MNT and a
   mark on the mount namespace hears of each mount that comes into it, goes
   or moves (both bits), with no descriptor and a record of the mount's
   unique ID. In a mount namespace of its own: tmpfs mounts, a recursive
   bind, a move, a detached tree attached, a mount propagated to a peer and
   its unmount, a lazy unmount of a tree, and a group that asked for
   FAN_MNT_DETACH alone. Once the mark is removed nothing more comes. A
   namespace OPEN_TREE_NAMESPACE makes, marked by its descriptor, takes out
   each of its mounts as its last descriptor closes (put_mnt_ns), the one
   below its root first; another namespace's file takes no mark. A
   namespace that ends as a child exits does the same, before the parent's
   wait ends, with the child's pid. When fdinfo stops showing an ended
   namespace's mark depends on the kernel: Linux master removes it in
   free_mnt_ns (1a116222acdc), and the release before that change removed
   it only as the last passive reference went, after an RCU grace period,
   so the count is printed only before the end. */
static int case_mount_events(void) {
    make_base("mount-events");
    const char *dirs[] = {"a", "b", "c", "d", "e"};
    for (int i = 0; i < 5; i++) mkdir(at(dirs[i]), 0755);
    printf("unshare=%ld\n", e(unshare(CLONE_NEWNS)));
    printf("private=%ld\n", e(mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL)));
    int fan = fan_init(FAN_REPORT_MNT | FAN_NONBLOCK, 0);
    int detach = fan_init(FAN_REPORT_MNT | FAN_NONBLOCK, 0);
    if (fan < 0 || detach < 0) return 80;
    printf("mark=%ld detach only=%ld\n",
           fan_mark(fan, FAN_MARK_ADD | FAN_MARK_MNTNS, FAN_MNT_ATTACH | FAN_MNT_DETACH, AT_FDCWD, "/proc/self/ns/mnt"),
           fan_mark(detach, FAN_MARK_ADD | FAN_MARK_MNTNS, FAN_MNT_DETACH, AT_FDCWD, "/proc/self/ns/mnt"));
    printf("tmpfs a=%ld\n", e(mount("none", at("a"), "tmpfs", 0, NULL)));
    name_mount("a");
    mkdir(at("a/in"), 0755);
    printf("tmpfs a/in=%ld\n", e(mount("none", at("a/in"), "tmpfs", 0, NULL)));
    name_mount("a/in");
    show_mount_events("mounted", fan);
    show_mount_events("mounted, detach only", detach);
    printf("bind a b=%ld\n", e(mount(at("a"), at("b"), NULL, MS_BIND | MS_REC, NULL)));
    name_mount("b");
    name_mount("b/in");
    show_mount_events("bound", fan);
    printf("move b c=%ld\n", e(mount(at("b"), at("c"), NULL, MS_MOVE, NULL)));
    show_mount_events("moved", fan);
    show_mount_events("moved, detach only", detach);
    int tree = e(syscall(428 /* open_tree */, AT_FDCWD, at("a"), 1 | 0x8000));
    printf("open_tree=%d\n", tree >= 0);
    show_mount_events("cloned", fan);
    printf("move_mount d=%ld\n", e(syscall(429 /* move_mount */, tree, "", AT_FDCWD, at("d"), 4)));
    close(tree);
    name_mount("d");
    name_mount("d/in");
    show_mount_events("attached", fan);
    printf("shared a=%ld\n", e(mount(NULL, at("a"), NULL, MS_SHARED, NULL)));
    printf("bind a e=%ld\n", e(mount(at("a"), at("e"), NULL, MS_BIND, NULL)));
    name_mount("e");
    show_mount_events("bound shared", fan);
    mkdir(at("a/x"), 0755);
    printf("tmpfs a/x=%ld\n", e(mount("none", at("a/x"), "tmpfs", 0, NULL)));
    name_mount("a/x");
    name_mount("e/x");
    show_mount_events("propagated", fan);
    printf("umount a/x=%ld\n", e(umount2(at("a/x"), 0)));
    show_mount_events("propagated unmount", fan);
    printf("umount c=%ld\n", e(umount2(at("c"), MNT_DETACH)));
    show_mount_events("lazy unmount", fan);
    show_mount_events("lazy unmount, detach only", detach);
    printf("remove=%ld\n",
           fan_mark(fan, FAN_MARK_REMOVE | FAN_MARK_MNTNS, FAN_MNT_ATTACH | FAN_MNT_DETACH, AT_FDCWD, "/proc/self/ns/mnt"));
    printf("umount d=%ld\n", e(umount2(at("d"), MNT_DETACH)));
    show_mount_events("unmarked", fan);
    show_mount_events("unmarked, detach only", detach);
    printf("mark net=%ld\n", fan_mark(fan, FAN_MARK_ADD | FAN_MARK_MNTNS, FAN_MNT_ATTACH, AT_FDCWD, "/proc/self/ns/net"));
    int ns = e(syscall(428 /* open_tree */, AT_FDCWD, at("a"), 2 /* OPEN_TREE_NAMESPACE */ | 0x8000));
    printf("open_tree namespace=%d\n", ns >= 0);
    char link[64];
    snprintf(link, sizeof link, "/proc/self/fd/%d", ns);
    printf("mark namespace=%ld\n",
           fan_mark(fan, FAN_MARK_ADD | FAN_MARK_MNTNS, FAN_MNT_ATTACH | FAN_MNT_DETACH, AT_FDCWD, link));
    printf("namespace marks=%d\n", namespace_marks(fan));
    close(ns);
    show_mount_events("namespace ended", fan);
    show_namespace_exit(fan);
    close(fan);
    close(detach);
    // One by one: C leaves the order of a call's arguments open.
    long first = e(umount2(at("e"), 0));
    long second = e(umount2(at("a/in"), 0));
    long third = e(umount2(at("a"), 0));
    printf("umount=%ld %ld %ld\n", first, second, third);
    remove_base();
    return 0;
}

/* The moves of FAN_REPORT_MNT that are not a move_mount. An unmount that
   propagates to a copy that a mount covers slides that mount down onto
   the copy's parent (propagate_umount's reparent): it moves, before the
   mount and its copy go. pivot_root, in a child's mount namespace of its
   own, moves the old root, then the new one. */
static int case_mount_moves(void) {
    make_base("mount-moves");
    const char *dirs[] = {"a", "e", "p"};
    for (int i = 0; i < 3; i++) mkdir(at(dirs[i]), 0755);
    // Nothing below may touch the mounts of the namespace this began in.
    long shared = e(unshare(CLONE_NEWNS));
    printf("unshare=%ld\n", shared);
    if (shared) return 81;
    printf("private=%ld\n", e(mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL)));
    int fan = fan_init(FAN_REPORT_MNT | FAN_NONBLOCK, 0);
    if (fan < 0) return 80;
    printf("mark=%ld\n",
           fan_mark(fan, FAN_MARK_ADD | FAN_MARK_MNTNS, FAN_MNT_ATTACH | FAN_MNT_DETACH, AT_FDCWD, "/proc/self/ns/mnt"));
    printf("tmpfs a=%ld\n", e(mount("none", at("a"), "tmpfs", 0, NULL)));
    printf("shared a=%ld\n", e(mount(NULL, at("a"), NULL, MS_SHARED, NULL)));
    printf("bind a e=%ld\n", e(mount(at("a"), at("e"), NULL, MS_BIND, NULL)));
    mkdir(at("a/x"), 0755);
    printf("tmpfs a/x=%ld\n", e(mount("none", at("a/x"), "tmpfs", 0, NULL)));
    name_mount("a/x");
    name_mount("e/x");
    printf("private e/x=%ld\n", e(mount(NULL, at("e/x"), NULL, MS_PRIVATE, NULL)));
    printf("tmpfs on e/x=%ld\n", e(mount("none", at("e/x"), "tmpfs", 0, NULL)));
    name_mount_at("cover", at("e/x"));
    show_mount_events("mounted", fan);
    printf("umount a/x=%ld\n", e(umount2(at("a/x"), 0)));
    show_mount_events("propagated unmount", fan);
    uint64_t cover = seen_mounts[seen_count - 1].id;
    printf("cover at e/x=%d\n", cover != 0 && unique_of(at("e/x")) == cover);
    fflush(stdout);
    pid_t child = fork();
    if (child == 0) {
        seen_count = 0;
        // A pivot_root in the parent's namespace would change its root.
        if (unshare(CLONE_NEWNS)) _exit(1);
        printf("child private=%ld\n", e(mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL)));
        printf("tmpfs p=%ld\n", e(mount("none", at("p"), "tmpfs", 0, NULL)));
        mkdir(at("p/old"), 0755);
        name_mount_at("old root", "/");
        name_mount("p");
        int group = fan_init(FAN_REPORT_MNT | FAN_NONBLOCK, 0);
        printf("child mark=%ld\n",
               fan_mark(group, FAN_MARK_ADD | FAN_MARK_MNTNS, FAN_MNT_ATTACH | FAN_MNT_DETACH, AT_FDCWD,
                        "/proc/self/ns/mnt"));
        printf("pivot_root=%ld\n", e(syscall(SYS_pivot_root, at("p"), at("p/old"))));
        show_mount_events("pivoted", group);
        fflush(stdout);
        _exit(0);
    }
    int status = 0;
    waitpid(child, &status, 0);
    printf("child exit=%d\n", WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    show_mount_events("after the child", fan);
    close(fan);
    // One by one: C leaves the order of a call's arguments open.
    long first = e(umount2(at("e/x"), 0));
    long second = e(umount2(at("e"), 0));
    long third = e(umount2(at("a"), 0));
    printf("umount=%ld %ld %ld\n", first, second, third);
    remove_base();
    return 0;
}

/* FAN_OPEN_EXEC: exec's open of a program, a copy of this one under the
   base, is told as FAN_OPEN with FAN_OPEN_EXEC, as do_open_execat opens it
   with __FMODE_EXEC; a mark on FAN_OPEN_EXEC alone hears only that, and
   an open of the program to read it is FAN_OPEN alone. */
static int case_open_exec(const char *self) {
    make_base("exec");
    int from = open(self, O_RDONLY), to = open(at("prog"), O_WRONLY | O_CREAT, 0755);
    if (from < 0 || to < 0) return 80;
    char buf[65536];
    long n;
    while ((n = read(from, buf, sizeof buf)) > 0)
        if (write(to, buf, (size_t)n) != n) return 81;
    close(from);
    close(to);
    int exec_only = fan_init(FAN_NONBLOCK, O_RDONLY);
    int both = fan_init(FAN_NONBLOCK, O_RDONLY);
    if (exec_only < 0 || both < 0) return 82;
    printf("mark exec=%ld\n", fan_mark(exec_only, FAN_MARK_ADD, FAN_OPEN_EXEC, AT_FDCWD, at("prog")));
    printf("mark both=%ld\n", fan_mark(both, FAN_MARK_ADD, FAN_OPEN | FAN_OPEN_EXEC, AT_FDCWD, at("prog")));
    fflush(stdout);
    pid_t child = fork();
    if (child == 0) {
        execl(at("prog"), "prog", "fanotify-noop", (char *)NULL);
        _exit(127);
    }
    int status;
    waitpid(child, &status, 0);
    printf("exec status=%d\n", WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    show_fd_events("exec, FAN_OPEN_EXEC", exec_only, child);
    show_fd_events("exec, both", both, child);
    int fd = open(at("prog"), O_RDONLY);
    show_fd_events("open, FAN_OPEN_EXEC", exec_only, 0);
    show_fd_events("open, both", both, 0);
    /* execveat of that descriptor opens its file again for exec. */
    fflush(stdout);
    child = fork();
    if (child == 0) {
        char *argv[] = {"prog", "fanotify-noop", NULL}, *envp[] = {NULL};
        syscall(SYS_execveat, fd, "", argv, envp, 0x1000 /* AT_EMPTY_PATH */);
        _exit(127);
    }
    waitpid(child, &status, 0);
    printf("execveat status=%d\n", WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    show_fd_events("execveat, FAN_OPEN_EXEC", exec_only, child);
    show_fd_events("execveat, both", both, child);
    if (fd >= 0) close(fd);
    close(exec_only);
    close(both);
    remove_base();
    return 0;
}

/* FAN_ACCESS_PERM: a read of a description opened while a mark wanted
   it waits for the group's answer, which denies it (EPERM) or lets it
   through; a pread of no bytes asks too, a readv of none does not, and a
   description opened before the mark never asks. The child's results come
   back through a pipe, in order. */
static int case_access_perm(void) {
    make_base("access");
    int file = open(at("f"), O_WRONLY | O_CREAT, 0644);
    if (file < 0 || write(file, "data", 4) != 4) return 80;
    close(file);
    int early = open(at("f"), O_RDONLY);
    int fan = fan_init(FAN_CLASS_CONTENT, O_RDONLY);
    if (early < 0 || fan < 0) return 81;
    printf("mark=%ld\n", fan_mark(fan, FAN_MARK_ADD, FAN_ACCESS_PERM, AT_FDCWD, at("f")));
    int results[2];
    if (pipe(results)) return 82;
    fflush(stdout);
    pid_t child = fork();
    if (child == 0) {
        close(fan);
        close(results[0]);
        char c[4];
        long out[6];
        int fd = open(at("f"), O_RDONLY);
        out[0] = e(read(fd, c, 1));
        out[1] = e(read(fd, c, 1));
        out[2] = e(pread(fd, c, 0, 0));
        struct iovec none = {c, 0};
        out[3] = e(readv(fd, &none, 1));
        out[4] = e(read(early, c, 1));
        /* A description open only for writing is EBADF, asking nothing. */
        int writing = open(at("f"), O_WRONLY);
        out[5] = e(read(writing, c, 1));
        if (write(results[1], out, sizeof out) != (ssize_t)sizeof out) _exit(1);
        _exit(0);
    }
    close(results[1]);
    int fd = read_perm("read", fan, child);
    printf("deny=%ld\n", respond(fan, fd, 2));
    if (fd >= 0) close(fd);
    fd = read_perm("read again", fan, child);
    printf("allow=%ld\n", respond(fan, fd, 1));
    if (fd >= 0) close(fd);
    fd = read_perm("pread of none", fan, child);
    printf("allow=%ld\n", respond(fan, fd, 1));
    if (fd >= 0) close(fd);
    long out[6] = {0};
    long n = read(results[0], out, sizeof out);
    printf("child=%d results=%ld\n", child_result(child), n);
    printf("denied read=%ld allowed read=%ld pread of none=%ld readv of none=%ld early read=%ld write-only read=%ld\n",
           out[0], out[1], out[2], out[3], out[4], out[5]);
    /* Nothing else was asked. */
    struct pollfd p = {fan, POLLIN, 0};
    printf("more=%d\n", poll(&p, 1, 0));
    close(early);
    close(fan);
    remove_base();
    return 0;
}

/* An AIO request's layout (`struct iocb`) and its completion. */
struct aio_request {
    uint64_t data;
    uint32_t key, rw_flags;
    uint16_t opcode;
    int16_t reqprio;
    uint32_t fildes;
    uint64_t buf, nbytes;
    int64_t offset;
    uint64_t reserved2;
    uint32_t flags, resfd;
};
struct aio_completion {
    uint64_t data, obj;
    int64_t res, res2;
};

/* FAN_ACCESS_PERM of an AIO read: io_submit asks it at submission, as
   aio_read's rw_verify_area does, and waits for the answer before the read;
   a denied one fails io_submit (EPERM), one let through completes. The
   child's results come back through a pipe. */
static int case_aio_perm(void) {
    make_base("aio");
    int file = open(at("f"), O_WRONLY | O_CREAT, 0644);
    if (file < 0 || write(file, "data", 4) != 4) return 80;
    close(file);
    int fan = fan_init(FAN_CLASS_CONTENT, O_RDONLY);
    if (fan < 0) return 81;
    printf("mark=%ld\n", fan_mark(fan, FAN_MARK_ADD, FAN_ACCESS_PERM, AT_FDCWD, at("f")));
    int results[2];
    if (pipe(results)) return 82;
    fflush(stdout);
    pid_t child = fork();
    if (child == 0) {
        close(fan);
        close(results[0]);
        long out[4] = {0};
        unsigned long ctx = 0;
        char c[4];
        int fd = open(at("f"), O_RDONLY);
        if (syscall(SYS_io_setup, 4, &ctx) != 0) _exit(1);
        struct aio_request req = {.opcode = 0 /* IOCB_CMD_PREAD */, .fildes = (uint32_t)fd,
                                  .buf = (uint64_t)(uintptr_t)c, .nbytes = 4};
        struct aio_request *list[] = {&req};
        out[0] = e(syscall(SYS_io_submit, ctx, 1, list));
        out[1] = e(syscall(SYS_io_submit, ctx, 1, list));
        struct aio_completion done;
        struct timespec wait = {5, 0};
        out[2] = e(syscall(SYS_io_getevents, ctx, 1, 1, &done, &wait));
        out[3] = out[2] == 1 ? done.res : -1000;
        if (write(results[1], out, sizeof out) != (ssize_t)sizeof out) _exit(1);
        _exit(0);
    }
    close(results[1]);
    int fd = read_perm("aio read", fan, child);
    printf("deny=%ld\n", respond(fan, fd, 2));
    if (fd >= 0) close(fd);
    fd = read_perm("aio read again", fan, child);
    printf("allow=%ld\n", respond(fan, fd, 1));
    if (fd >= 0) close(fd);
    long out[4] = {0};
    long n = read(results[0], out, sizeof out);
    printf("child=%d results=%ld\n", child_result(child), n);
    printf("denied submit=%ld allowed submit=%ld events=%ld res=%ld\n", out[0], out[1], out[2], out[3]);
    struct pollfd p = {fan, POLLIN, 0};
    printf("more=%d\n", poll(&p, 1, 0));
    close(fan);
    remove_base();
    return 0;
}

/* A copy of this program under the base, for exec. */
static int copy_self(const char *self, const char *to_path) {
    int from = open(self, O_RDONLY), to = open(to_path, O_WRONLY | O_CREAT, 0755);
    if (from < 0 || to < 0) return -1;
    char buf[65536];
    long n;
    while ((n = read(from, buf, sizeof buf)) > 0)
        if (write(to, buf, (size_t)n) != n) return -1;
    close(from);
    close(to);
    return 0;
}
/* A child that execs `path`: its exit status is 0 for the program's own
   (it returns 0), or the errno execve failed with. */
static pid_t exec_in_child(const char *path, int fan) {
    fflush(stdout);
    pid_t child = fork();
    if (child == 0) {
        close(fan);
        execl(path, "prog", "fanotify-noop", (char *)NULL);
        _exit(errno);
    }
    return child;
}
/* Answers every permission event of `fan` with `response` until `child`
   exits: how many of each kind came. */
static void answer_until_exit(const char *label, int fan, pid_t child, uint32_t response) {
    int open_exec = 0, open = 0, access = 0, other = 0;
    for (;;) {
        struct pollfd p = {fan, POLLIN, 0};
        if (poll(&p, 1, 50) == 1) {
            char buf[256];
            long n = read(fan, buf, sizeof buf);
            if (n < (long)sizeof(struct metadata)) break;
            struct metadata m;
            memcpy(&m, buf, sizeof m);
            if (m.mask & FAN_OPEN_EXEC_PERM) open_exec++;
            else if (m.mask & FAN_OPEN_PERM) open++;
            else if (m.mask & FAN_ACCESS_PERM) access++;
            else other++;
            respond(fan, m.fd, response);
            if (m.fd >= 0) close(m.fd);
            continue;
        }
        int status;
        if (waitpid(child, &status, WNOHANG) == child) {
            printf("%s: status=%d open-exec=%d open=%d access=%d other=%d\n", label,
                   WIFEXITED(status) ? WEXITSTATUS(status) : -1, open_exec, open, access, other);
            return;
        }
    }
    printf("%s: read failed\n", label);
}

/* Exec's permission events: its open of the program asks
   FAN_OPEN_EXEC_PERM, then FAN_OPEN_PERM, as
   fsnotify_open_perm_and_set_mode does for __FMODE_EXEC, and its reads
   FAN_ACCESS_PERM once a kernel_read: the ELF header, then the program
   headers of this static program; a denial of any fails execve with
   EPERM. */
static int case_exec_perm(const char *self) {
    make_base("execperm");
    if (copy_self(self, at("prog"))) return 80;
    int fan = fan_init(FAN_CLASS_CONTENT, O_RDONLY);
    if (fan < 0) return 81;
    printf("mark=%ld\n", fan_mark(fan, FAN_MARK_ADD, FAN_OPEN_EXEC_PERM | FAN_OPEN_PERM, AT_FDCWD, at("prog")));
    /* The program's own open, let through, tells its open and its close. */
    int heard = fan_init(FAN_NONBLOCK, O_RDONLY);
    if (heard < 0) return 84;
    printf("heard=%ld\n", fan_mark(heard, FAN_MARK_ADD, FAN_OPEN | FAN_OPEN_EXEC | FAN_CLOSE, AT_FDCWD, at("prog")));
    pid_t child = exec_in_child(at("prog"), fan);
    int fd = read_perm("open-exec", fan, child);
    printf("allow=%ld\n", respond(fan, fd, 1));
    if (fd >= 0) close(fd);
    fd = read_perm("open", fan, child);
    printf("allow=%ld\n", respond(fan, fd, 1));
    if (fd >= 0) close(fd);
    printf("allowed child=%d\n", child_result(child));
    show_fd_events("program's events", heard, child);
    close(heard);
    child = exec_in_child(at("prog"), fan);
    fd = read_perm("open-exec", fan, child);
    printf("deny=%ld\n", respond(fan, fd, 2));
    if (fd >= 0) close(fd);
    printf("denied child=%d\n", child_result(child));
    child = exec_in_child(at("prog"), fan);
    fd = read_perm("open-exec", fan, child);
    printf("allow=%ld\n", respond(fan, fd, 1));
    if (fd >= 0) close(fd);
    fd = read_perm("open", fan, child);
    printf("deny=%ld\n", respond(fan, fd, 2));
    if (fd >= 0) close(fd);
    printf("denied open child=%d\n", child_result(child));
    /* Reads: let all through, then deny them. */
    printf("mark access=%ld\n", fan_mark(fan, FAN_MARK_ADD, FAN_ACCESS_PERM, AT_FDCWD, at("prog")));
    child = exec_in_child(at("prog"), fan);
    answer_until_exit("all allowed", fan, child, 1);
    printf("remove opens=%ld\n", fan_mark(fan, FAN_MARK_REMOVE, FAN_OPEN_EXEC_PERM | FAN_OPEN_PERM, AT_FDCWD, at("prog")));
    child = exec_in_child(at("prog"), fan);
    answer_until_exit("reads denied", fan, child, 2);
    close(fan);
    /* A script let through whose interpreter is denied: the script was
       opened, so it tells its open and its close all the same. */
    int script = open(at("script"), O_WRONLY | O_CREAT, 0755);
    char line[160];
    int len = snprintf(line, sizeof line, "#!%s fanotify-noop\n", at("prog"));
    if (script < 0 || write(script, line, (size_t)len) != len) return 82;
    close(script);
    fan = fan_init(FAN_CLASS_CONTENT, O_RDONLY);
    int notif = fan_init(FAN_NONBLOCK, O_RDONLY);
    if (fan < 0 || notif < 0) return 83;
    printf("mark script=%ld\n", fan_mark(fan, FAN_MARK_ADD, FAN_OPEN_PERM, AT_FDCWD, at("script")));
    printf("mark interpreter=%ld\n", fan_mark(fan, FAN_MARK_ADD, FAN_OPEN_EXEC_PERM, AT_FDCWD, at("prog")));
    printf("notif=%ld\n", fan_mark(notif, FAN_MARK_ADD, FAN_OPEN | FAN_OPEN_EXEC | FAN_CLOSE, AT_FDCWD, at("script")));
    child = exec_in_child(at("script"), fan);
    fd = read_perm("script open", fan, child);
    printf("allow=%ld\n", respond(fan, fd, 1));
    if (fd >= 0) close(fd);
    fd = read_perm("interpreter open-exec", fan, child);
    printf("deny=%ld\n", respond(fan, fd, 2));
    if (fd >= 0) close(fd);
    printf("script child=%d\n", child_result(child));
    show_fd_events("script's events", notif, child);
    close(notif);
    close(fan);
    /* An exec that fails before it loads (no interpreter) still asked the
       script's open: let through, it fails as without the mark and tells
       the open and close; denied, the denial's error comes first. */
    script = open(at("lost"), O_WRONLY | O_CREAT, 0755);
    len = snprintf(line, sizeof line, "#!%s\n", at("missing"));
    if (script < 0 || write(script, line, (size_t)len) != len) return 85;
    close(script);
    fan = fan_init(FAN_CLASS_CONTENT, O_RDONLY);
    notif = fan_init(FAN_NONBLOCK, O_RDONLY);
    if (fan < 0 || notif < 0) return 86;
    printf("mark lost=%ld\n", fan_mark(fan, FAN_MARK_ADD, FAN_OPEN_PERM, AT_FDCWD, at("lost")));
    printf("notif lost=%ld\n", fan_mark(notif, FAN_MARK_ADD, FAN_OPEN | FAN_OPEN_EXEC | FAN_CLOSE, AT_FDCWD, at("lost")));
    for (uint32_t response = 1; response <= 2; response++) {
        child = exec_in_child(at("lost"), fan);
        fd = read_perm("lost open", fan, child);
        printf("response %u=%ld\n", response, respond(fan, fd, response));
        if (fd >= 0) close(fd);
        printf("lost child=%d\n", child_result(child));
        show_fd_events("lost's events", notif, child);
    }
    close(notif);
    close(fan);
    remove_base();
    return 0;
}

/* Whether fdinfo shows a mark of `fan` on the inode `ino`. */
static int marked(int fan, ino_t ino) {
    char path[64], line[512], want[48];
    snprintf(path, sizeof path, "/proc/self/fdinfo/%d", fan);
    snprintf(want, sizeof want, "ino:%lx ", (unsigned long)ino);
    FILE *info = fopen(path, "r");
    int found = 0;
    while (info && fgets(line, sizeof line, info))
        if (!strncmp(line, "fanotify ", 9) && strstr(line, want)) found = 1;
    if (info) fclose(info);
    return found;
}
static long drop_caches(const char *value) {
    int fd = open("/proc/sys/vm/drop_caches", O_WRONLY);
    if (fd < 0) return -errno;
    long n = e(write(fd, value, strlen(value)));
    close(fd);
    return n;
}

/* /proc/sys/vm/drop_caches (fs/drop_caches.c): mode 0200, so not even
   root may read it; proc_dointvec_minmax takes 1 to 4. 2 (drop_slab)
   frees the inodes nothing uses, and with them their evictable marks
   (FAN_MARK_EVICTABLE, which hold no reference): not those of an open
   file, nor one another group's mark without FAN_MARK_EVICTABLE holds.

   One write evicts the free files' inodes, as each is set up so that
   nothing gives it a second chance. It is made, written back (fsync: a
   dirty inode is on no LRU) and marked by its descriptor, with no lookup,
   so its dentry first goes on the LRU at the close and without
   DCACHE_REFERENCED, which a dput of a dentry already there sets and which
   makes dentry_lru_isolate rotate it once. The first pass of drop_slab
   frees the two dentries, so freed > 1 and it passes again, and in that
   pass their inodes, unused and unreferenced, are freed. */
static int case_drop_caches(void) {
    make_base("drop-caches");
    struct stat st;
    long got = e(stat("/proc/sys/vm/drop_caches", &st));
    printf("stat=%ld mode=%o\n", got, got ? 0 : st.st_mode & 07777);
    printf("read open=%ld\n", e(open("/proc/sys/vm/drop_caches", O_RDONLY)));
    printf("read-write open=%ld\n", e(open("/proc/sys/vm/drop_caches", O_RDWR)));
    const char *values[] = {"0", "5", "x", "4\n"};
    for (int i = 0; i < 4; i++) printf("write %.1s=%ld\n", values[i], drop_caches(values[i]));
    int fan = fan_init(FAN_NONBLOCK, 0), other = fan_init(FAN_NONBLOCK, 0);
    if (fan < 0 || other < 0) return 80;
    const char *names[] = {"free", "free2", "open", "kept"};
    ino_t inos[4];
    for (int i = 0; i < 4; i++) {
        int fd = open(at(names[i]), O_WRONLY | O_CREAT | O_EXCL, 0644);
        if (fd < 0) return 82;
        fsync(fd);
        fstat(fd, &st);
        inos[i] = st.st_ino;
        printf("evictable %s=%ld\n", names[i],
               fan_mark(fan, FAN_MARK_ADD | FAN_MARK_EVICTABLE, FAN_OPEN, fd, NULL));
        if (i == 3) printf("other kept=%ld\n", fan_mark(other, FAN_MARK_ADD, FAN_OPEN, fd, NULL));
        close(fd);
    }
    int held = open(at("open"), O_RDONLY);
    printf("write 2=%ld\n", drop_caches("2"));
    for (int i = 0; i < 4; i++) printf("%s marked=%d\n", names[i], marked(fan, inos[i]));
    /* The free file's inode is a new one: nothing tells of its open. */
    int fd = open(at("free"), O_RDONLY);
    if (fd >= 0) close(fd);
    printf("events=%d\n", drain(fan));
    close(held);
    close(fan);
    close(other);
    remove_base();
    return 0;
}

/* The hash Linux's full_name_hash gives on x86-64, whole little-endian
   words first, then the bytes left over: what fanotify_alloc_name_event
   mixes a name into an event's merge key with, salted with its length. */
static uint32_t name_hash(const char *name) {
    const uint64_t golden = 0x61C8864680B583EBull;
    size_t len = strlen(name);
    uint64_t x = 0, y = len;
    for (; len >= 8; name += 8, len -= 8) {
        uint64_t a;
        memcpy(&a, name, 8);
        x ^= a;
        y ^= x;
        x = x << 12 | x >> 52;
        x += y;
        y = y << 45 | y >> 19;
        y *= 9;
    }
    if (len) {
        uint64_t a = 0;
        memcpy(&a, name, len);
        x ^= a;
    }
    y ^= x * golden;
    y *= golden;
    return (uint32_t)(y >> 32);
}

/* The events of a directory and name a read gives: how many there are,
   and the masks of those of `name`, in order. */
static void show_name_events(const char *label, int fan, const char *name) {
    static char buf[65536];
    int count = 0;
    printf("%s:", label);
    struct pollfd p = {fan, POLLIN, 0};
    while (poll(&p, 1, 0) == 1) {
        long n = read(fan, buf, sizeof buf);
        if (n <= 0) break;
        for (char *q = buf; q < buf + n;) {
            struct metadata m;
            memcpy(&m, q, sizeof m);
            count++;
            struct info_header hdr;
            memcpy(&hdr, q + m.metadata_len, sizeof hdr);
            if (hdr.type == 2) {
                const unsigned char *record = (unsigned char *)q + m.metadata_len + 12;
                unsigned bytes;
                memcpy(&bytes, record, 4);
                if (!strcmp((const char *)record + 8 + bytes, name)) printf(" %#llx", (unsigned long long)m.mask);
            }
            if (m.event_len < sizeof m) break;
            q += m.event_len;
        }
    }
    printf(" (%d events)\n", count);
}

/* fanotify_merge looks for an event to merge into among the newest 128 of
   its bucket of the group's merge hash (FANOTIFY_MAX_MERGE_EVENTS): the
   events of names in one directory by one task share a bucket when the
   low 7 bits of their names' hashes do. With 127 such events between a
   name's creation and its removal, the removal merges; with 128 it is an
   event of its own. Events of other buckets in between do not count. */
static int case_merge_window(void) {
    make_base("merge-window");
    const char *first = "n00000";
    static char alike[128][8], other[40][8];
    int nalike = 0, nother = 0;
    uint32_t bucket = name_hash(first) & 127;
    for (int i = 1; i < 100000 && (nalike < 128 || nother < 40); i++) {
        char name[8];
        snprintf(name, sizeof name, "n%05d", i);
        if ((name_hash(name) & 127) == bucket) {
            if (nalike < 128) strcpy(alike[nalike++], name);
        } else if (nother < 40) {
            strcpy(other[nother++], name);
        }
    }
    printf("names=%d %d\n", nalike, nother);
    int fan = fan_init(FAN_REPORT_DFID_NAME | FAN_NONBLOCK, 0);
    if (fan < 0) return 80;
    const char *dirs[] = {"d", "e"};
    for (int k = 0; k < 2; k++) {
        int between = 127 + k;
        char dir[128], path[160];
        snprintf(dir, sizeof dir, "%s", at(dirs[k]));
        mkdir(dir, 0755);
        printf("mark %s=%ld\n", dirs[k], fan_mark(fan, FAN_MARK_ADD, FAN_CREATE | FAN_DELETE, AT_FDCWD, dir));
        snprintf(path, sizeof path, "%s/%s", dir, first);
        touch(path);
        for (int i = 0; i < between; i++) {
            snprintf(path, sizeof path, "%s/%s", dir, alike[i]);
            touch(path);
            if (i < nother) {
                snprintf(path, sizeof path, "%s/%s", dir, other[i]);
                touch(path);
            }
        }
        snprintf(path, sizeof path, "%s/%s", dir, first);
        printf("unlink=%ld\n", e(unlink(path)));
        char label[32];
        snprintf(label, sizeof label, "%d between", between);
        show_name_events(label, fan, first);
    }
    close(fan);
    remove_base();
    return 0;
}

/* fsnotify_sb_delete: as a tmpfs's superblock goes with its last mount,
   the marks on its files and on itself go, and a tmpfs that takes the
   device next hears nothing of them. A mark on another file system stays. */
static int marks_of(int fan) {
    char path[64], line[512];
    snprintf(path, sizeof path, "/proc/self/fdinfo/%d", fan);
    FILE *info = fopen(path, "r");
    int count = 0;
    while (info && fgets(line, sizeof line, info))
        if (!strncmp(line, "fanotify ", 9) && strncmp(line, "fanotify flags:", 15)) count++;
    if (info) fclose(info);
    return count;
}
static int case_superblock_marks(void) {
    make_base("superblock-marks");
    long shared = e(unshare(CLONE_NEWNS));
    printf("unshare=%ld\n", shared);
    if (shared) return 81;
    printf("private=%ld\n", e(mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL)));
    mkdir(at("m"), 0755);
    printf("tmpfs=%ld\n", e(mount("none", at("m"), "tmpfs", 0, NULL)));
    touch(at("m/f"));
    int fan = fan_init(FAN_NONBLOCK, 0);
    if (fan < 0) return 80;
    printf("file=%ld\n", fan_mark(fan, FAN_MARK_ADD, FAN_OPEN, AT_FDCWD, at("m/f")));
    printf("filesystem=%ld\n", fan_mark(fan, FAN_MARK_ADD | FAN_MARK_FILESYSTEM, FAN_OPEN, AT_FDCWD, at("m")));
    printf("other=%ld\n", fan_mark(fan, FAN_MARK_ADD, FAN_OPEN, AT_FDCWD, base));
    printf("marks=%d\n", marks_of(fan));
    printf("umount=%ld\n", e(umount2(at("m"), 0)));
    printf("marks after=%d\n", marks_of(fan));
    printf("tmpfs again=%ld\n", e(mount("none", at("m"), "tmpfs", 0, NULL)));
    /* Linux's anonymous device may be the first's again, or not. */
    touch(at("m/f"));
    int fd = open(at("m/f"), O_RDONLY);
    if (fd >= 0) close(fd);
    printf("events=%d\n", drain(fan));
    close(fan);
    printf("umount again=%ld\n", e(umount2(at("m"), 0)));
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
    if (!strcmp(mode, "fanotify-mount-events")) return case_mount_events();
    if (!strcmp(mode, "fanotify-mount-moves")) return case_mount_moves();
    if (!strcmp(mode, "fanotify-open-exec")) return case_open_exec(argc > 2 ? argv[2] : "");
    if (!strcmp(mode, "fanotify-aio-perm")) return case_aio_perm();
    if (!strcmp(mode, "fanotify-exec-perm")) return case_exec_perm(argc > 2 ? argv[2] : "");
    if (!strcmp(mode, "fanotify-noop")) return 0;
    if (!strcmp(mode, "fanotify-perm")) return case_perm();
    if (!strcmp(mode, "fanotify-access-perm")) return case_access_perm();
    if (!strcmp(mode, "fanotify-drop-caches")) return case_drop_caches();
    if (!strcmp(mode, "fanotify-merge-window")) return case_merge_window();
    if (!strcmp(mode, "fanotify-superblock-marks")) return case_superblock_marks();
    printf("unknown mode %s\n", mode);
    return 2;
}
