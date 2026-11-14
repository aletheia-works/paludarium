/* Linux's native asynchronous I/O (io_setup, io_destroy, io_submit,
   io_cancel, io_getevents, io_pgetevents), compared with Linux: the calls'
   errors and their order, the ring's header, the events reads, writes,
   syncs and polls give, the waits of io_getevents and io_pgetevents, and
   what becomes of the contexts across fork, vfork, execve and exit.

   Nothing printed depends on timing or on the machine: the events of a
   call are sorted by their data where Linux may complete some later (a
   sync runs in a kernel worker), the number of events a ring holds (which
   depends on the CPUs) is only compared with what was asked for, and the
   machine's aio-nr only by what it gains and loses. Whether a fork's child
   keeps the rings (Linux maps them VM_DONTCOPY since 2026) is not printed,
   as the runner's kernel may be older. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

typedef unsigned long aio_context_t;

struct iocb {
    uint64_t aio_data;
    uint32_t aio_key;
    uint32_t aio_rw_flags;
    uint16_t aio_lio_opcode;
    int16_t aio_reqprio;
    uint32_t aio_fildes;
    uint64_t aio_buf;
    uint64_t aio_nbytes;
    int64_t aio_offset;
    uint64_t aio_reserved2;
    uint32_t aio_flags;
    uint32_t aio_resfd;
};

struct io_event {
    uint64_t data;
    uint64_t obj;
    int64_t res;
    int64_t res2;
};

struct aio_ring {
    unsigned id, nr, head, tail, magic, compat_features, incompat_features, header_length;
};

enum {
    CMD_PREAD = 0,
    CMD_PWRITE = 1,
    CMD_FSYNC = 2,
    CMD_FDSYNC = 3,
    CMD_POLL = 5,
    CMD_NOOP = 6,
    CMD_PREADV = 7,
    CMD_PWRITEV = 8,
};
#define FLAG_RESFD 1
#ifndef RWF_NOWAIT
#define RWF_NOWAIT 0x8
#endif
#ifndef RWF_APPEND
#define RWF_APPEND 0x10
#endif
#ifndef RWF_NOAPPEND
#define RWF_NOAPPEND 0x20
#endif

static long e(long r) { return r < 0 ? -errno : r; }

static long setup(unsigned nr, aio_context_t *ctx) { return e(syscall(SYS_io_setup, nr, ctx)); }
static long destroy(aio_context_t ctx) { return e(syscall(SYS_io_destroy, ctx)); }
static long submit(aio_context_t ctx, long nr, struct iocb **iocbs) {
    return e(syscall(SYS_io_submit, ctx, nr, iocbs));
}
static long submit1(aio_context_t ctx, struct iocb *iocb) { return submit(ctx, 1, &iocb); }
static long cancel(aio_context_t ctx, struct iocb *iocb) {
    struct io_event ev;
    return e(syscall(SYS_io_cancel, ctx, iocb, &ev));
}
static long getevents(aio_context_t ctx, long min, long nr, struct io_event *ev, struct timespec *ts) {
    return e(syscall(SYS_io_getevents, ctx, min, nr, ev, ts));
}
static long pgetevents(aio_context_t ctx, long min, long nr, struct io_event *ev, struct timespec *ts,
                       void *usig) {
    return e(syscall(SYS_io_pgetevents, ctx, min, nr, ev, ts, usig));
}

static struct timespec zero;

static struct iocb rw(int opcode, int fd, void *buf, size_t len, long long off, uint64_t data) {
    struct iocb cb = {0};
    cb.aio_lio_opcode = opcode;
    cb.aio_fildes = fd;
    cb.aio_buf = (uintptr_t)buf;
    cb.aio_nbytes = len;
    cb.aio_offset = off;
    cb.aio_data = data;
    return cb;
}

static struct iocb poll_of(int fd, unsigned events, uint64_t data) {
    struct iocb cb = {0};
    cb.aio_lio_opcode = CMD_POLL;
    cb.aio_fildes = fd;
    cb.aio_buf = events;
    cb.aio_data = data;
    return cb;
}

static int by_data(const void *a, const void *b) {
    const struct io_event *x = a, *y = b;
    return x->data < y->data ? -1 : x->data > y->data;
}

/* Waits for `n` events and prints them in order of their data: data, res,
   and whether obj is the iocb in `iocbs` of that index. */
static void reap(const char *label, aio_context_t ctx, int n, struct iocb *iocbs) {
    struct io_event ev[32];
    long got = getevents(ctx, n, 32, ev, NULL);
    printf("%s: got=%ld", label, got);
    if (got > 0) {
        qsort(ev, got, sizeof ev[0], by_data);
        for (long i = 0; i < got; i++) {
            long which = iocbs ? ((struct iocb *)(uintptr_t)ev[i].obj - iocbs) : -1;
            printf(" [%llu %lld obj=%ld]", (unsigned long long)ev[i].data, (long long)ev[i].res, which);
        }
    }
    printf("\n");
}

static unsigned long aio_nr(void) {
    FILE *f = fopen("/proc/sys/fs/aio-nr", "r");
    unsigned long v = 0;
    if (!f || fscanf(f, "%lu", &v) != 1) v = ~0ul;
    if (f) fclose(f);
    return v;
}

static int mapped(void *at) {
    unsigned char vec;
    return mincore(at, 4096, &vec) == 0;
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
    snprintf(base, sizeof base, "/tmp/aio-%s-XXXXXX", what);
    if (!mkdtemp(base)) {
        perror("mkdtemp");
        exit(90);
    }
}

static unsigned long aio_max_nr(void) {
    FILE *f = fopen("/proc/sys/fs/aio-max-nr", "r");
    unsigned long v = 0;
    if (!f || fscanf(f, "%lu", &v) != 1) v = ~0ul;
    if (f) fclose(f);
    return v;
}

static int case_calls(void) {
    aio_context_t ctx = 0, other = 0;
    unsigned long before = aio_nr();
    unsigned long max = aio_max_nr();
    printf("efault=%ld\n", setup(1, (aio_context_t *)8));
    ctx = 1;
    printf("nonzero=%ld\n", setup(1, &ctx));
    ctx = 0;
    printf("none=%ld\n", setup(0, &ctx));
    printf("huge=%ld\n", setup(0x400001, &ctx));
    /* One past aio-max-nr (65536 unless the machine raised it). */
    printf("past-limit=%ld\n", max < 0x400000 ? setup(max + 1, &ctx) : -EAGAIN);
    printf("max-u32=%ld\n", setup(0xffffffffu, &ctx));
    printf("untouched=%d\n", ctx == 0);
    printf("setup=%ld\n", setup(10, &ctx));
    if (!ctx) return 3;
    struct aio_ring *ring = (struct aio_ring *)ctx;
    printf("aligned=%d id=%u head=%u tail=%u magic=%#x compat=%u incompat=%u header=%u\n",
           ctx % 4096 == 0, ring->id, ring->head, ring->tail, ring->magic, ring->compat_features,
           ring->incompat_features, ring->header_length);
    printf("nr>=2*asked=%d\n", ring->nr >= 20);
    printf("aio-nr+%lu\n", aio_nr() - before);
    /* The mapping: shared, read and write, as many pages as the events. */
    FILE *maps = fopen("/proc/self/maps", "r");
    char line[512];
    while (maps && fgets(line, sizeof line, maps)) {
        unsigned long lo, hi;
        char perms[8];
        if (sscanf(line, "%lx-%lx %7s", &lo, &hi, perms) == 3 && lo == ctx) {
            char *name = strchr(line, '/');
            printf("maps: %s pages=%d name=%s", perms,
                   hi - lo == ((32 + 32ul * ring->nr + 4095) & ~4095ul), name ? name : "none\n");
        }
    }
    if (maps) fclose(maps);
    printf("second=%ld", setup(20, &other));
    if (!other) return 3;
    printf(" id=%u\n", ((struct aio_ring *)other)->id);
    printf("aio-nr+%lu\n", aio_nr() - before);
    printf("destroy=%ld\n", destroy(ctx));
    printf("mapped=%d\n", mapped((void *)ctx));
    printf("again=%ld\n", destroy(ctx));
    printf("aio-nr+%lu\n", aio_nr() - before);
    aio_context_t third = 0;
    printf("third=%ld", setup(1, &third));
    if (!third) return 3;
    printf(" id=%u\n", ((struct aio_ring *)third)->id);
    /* Another context's index in the header names no context at this ID. */
    ((struct aio_ring *)third)->id = 1;
    printf("other-index=%ld\n", destroy(third));
    ((struct aio_ring *)third)->id = 0;
    printf("not-a-ring=%ld", destroy((aio_context_t)base));
    printf(" null=%ld\n", destroy(0));
    printf("destroy-third=%ld", destroy(third));
    printf(" destroy-other=%ld\n", destroy(other));
    printf("aio-nr+%lu\n", aio_nr() - before);
    /* The other calls find no context either. */
    struct io_event ev;
    struct iocb cb = rw(CMD_PREAD, 0, &ev, 0, 0, 0), *list[1] = {&cb};
    printf("submit=%ld", submit(ctx, 1, list));
    printf(" getevents=%ld", getevents(ctx, 0, 1, &ev, &zero));
    printf(" pgetevents=%ld", pgetevents(ctx, 0, 1, &ev, &zero, NULL));
    printf(" cancel=%ld\n", cancel(ctx, &cb));
    return 0;
}

static int case_rw(void) {
    make_base("rw");
    int fd = open(at("file"), O_RDWR | O_CREAT | O_TRUNC, 0600);
    if (write(fd, "hello world", 11) != 11) return 91;
    int evfd = eventfd(0, EFD_NONBLOCK);
    aio_context_t ctx = 0;
    printf("setup=%ld\n", setup(16, &ctx));
    if (!ctx) return 3;
    char wbuf[] = "XY", rbuf[64] = {0}, a[2], b[3];
    struct iovec iov[2] = {{a, sizeof a}, {b, sizeof b}};
    struct iocb cbs[8];
    cbs[0] = rw(CMD_PWRITE, fd, wbuf, 2, 2, 1);
    cbs[0].aio_key = 0xdead;
    cbs[1] = rw(CMD_PREAD, fd, rbuf, sizeof rbuf, 0, 2);
    cbs[2] = rw(CMD_PREADV, fd, iov, 2, 6, 3);
    cbs[3] = rw(CMD_FSYNC, fd, NULL, 0, 0, 4);
    cbs[4] = rw(CMD_FDSYNC, fd, NULL, 0, 0, 5);
    cbs[5] = rw(CMD_PREAD, fd, rbuf, 4, 100, 6);
    cbs[6] = rw(CMD_PREAD, fd, (void *)8, 4, 0, 7);
    for (int i = 0; i < 7; i++) {
        cbs[i].aio_flags = FLAG_RESFD;
        cbs[i].aio_resfd = evfd;
    }
    struct iocb *list[8];
    for (int i = 0; i < 8; i++) list[i] = &cbs[i];
    printf("submit=%ld key=%#x\n", submit(ctx, 7, list), cbs[0].aio_key);
    reap("events", ctx, 7, cbs);
    uint64_t count = 0;
    printf("eventfd=%zd", read(evfd, &count, 8));
    printf(" count=%llu\n", (unsigned long long)count);
    printf("read=%.11s iov=%.2s%.3s pos=%ld\n", rbuf, a, b, (long)lseek(fd, 0, SEEK_CUR));
    /* A vector's count with bits past 32: import_iovec took an unsigned
       until Linux 965e5e451146, so 2 and 0 entries, not EINVAL. */
    memset(a, 0, sizeof a);
    memset(b, 0, sizeof b);
    cbs[0] = rw(CMD_PREADV, fd, iov, 0x100000002ul, 0, 1);
    cbs[1] = rw(CMD_PREADV, fd, iov, 1ul << 32, 0, 2);
    printf("wide-count submit=%ld\n", submit(ctx, 2, list));
    reap("wide-count", ctx, 2, cbs);
    printf("wide-count iov=%.2s%.3s\n", a, b);
    /* Writes: a vector at the end, an append, and an O_APPEND file's. */
    cbs[0] = rw(CMD_PWRITEV, fd, iov, 2, 11, 1);
    cbs[1] = rw(CMD_PWRITE, fd, "!", 1, 0, 2);
    cbs[1].aio_rw_flags = RWF_APPEND;
    printf("submit=%ld\n", submit(ctx, 2, list));
    reap("writes", ctx, 2, cbs);
    int app = open(at("file"), O_WRONLY | O_APPEND);
    cbs[0] = rw(CMD_PWRITE, app, "?", 1, 0, 1);
    printf("append=%ld\n", submit1(ctx, &cbs[0]));
    reap("append", ctx, 1, cbs);
    char all[32] = {0};
    printf("file=%zd %s\n", pread(fd, all, sizeof all - 1, 0), all);
    /* What each request is checked for, in order, with what was taken. */
    int wr = open(at("file"), O_WRONLY);
    int dir = open(base, O_RDONLY | O_DIRECTORY);
    struct {
        const char *what;
        struct iocb cb;
    } bad[] = {
        {"reserved2", rw(CMD_PREAD, -1, rbuf, 1, 0, 0)},
        {"negative-nbytes", rw(CMD_PREAD, -1, rbuf, -1, 0, 0)},
        {"bad-fd", rw(CMD_PREAD, 99, rbuf, 1, 0, 0)},
        {"bad-resfd", rw(CMD_PREAD, fd, rbuf, 1, 0, 0)},
        {"resfd-not-eventfd", rw(CMD_PREAD, fd, rbuf, 1, 0, 0)},
        {"noop", rw(CMD_NOOP, fd, rbuf, 1, 0, 0)},
        {"opcode-4", rw(4, fd, rbuf, 1, 0, 0)},
        {"opcode-9", rw(9, fd, rbuf, 1, 0, 0)},
        {"ioprio-level", rw(CMD_PREAD, fd, rbuf, 1, 0, 0)},
        {"unknown-rw-flag", rw(CMD_PREAD, fd, rbuf, 1, 0, 0)},
        {"append-noappend", rw(CMD_PREAD, fd, rbuf, 1, 0, 0)},
        {"read-write-only", rw(CMD_PREAD, wr, rbuf, 1, 0, 0)},
        {"write-read-only", rw(CMD_PWRITE, dir, rbuf, 1, 0, 0)},
        {"read-directory", rw(CMD_PREAD, dir, rbuf, 1, 0, 0)},
        {"negative-offset", rw(CMD_PREAD, fd, rbuf, 1, -1, 0)},
        {"offset-overflow", rw(CMD_PREAD, fd, rbuf, 2, 0x7fffffffffffffffll, 0)},
        /* The last page, which is the kernel's with 4-level and 5-level
           paging alike: 1 << 47 is a user address under LA57. */
        {"kernel-buffer", rw(CMD_PREAD, fd, (void *)-4096L, 1, 0, 0)},
        {"too-many-iovecs", rw(CMD_PREADV, fd, iov, 1025, 0, 0)},
        {"bad-iovecs", rw(CMD_PREADV, fd, (void *)8, 1, 0, 0)},
        {"fsync-buffer", rw(CMD_FSYNC, fd, rbuf, 0, 0, 0)},
        {"fsync-offset", rw(CMD_FDSYNC, fd, NULL, 0, 1, 0)},
        {"fsync-flags", rw(CMD_FSYNC, fd, NULL, 0, 0, 0)},
    };
    bad[0].cb.aio_reserved2 = 1;
    bad[3].cb.aio_flags = FLAG_RESFD;
    bad[3].cb.aio_resfd = 99;
    bad[4].cb.aio_flags = FLAG_RESFD;
    bad[4].cb.aio_resfd = fd;
    bad[8].cb.aio_flags = 2;
    bad[8].cb.aio_reqprio = 1;
    bad[9].cb.aio_rw_flags = 0x8000;
    bad[10].cb.aio_rw_flags = RWF_APPEND | RWF_NOAPPEND;
    bad[21].cb.aio_rw_flags = 1;
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++)
        printf("%s=%ld\n", bad[i].what, submit1(ctx, &bad[i].cb));
    /* An iocb that cannot be read, and one whose key cannot be written. */
    printf("iocb-unreadable=%ld\n", submit1(ctx, (struct iocb *)8));
    struct iocb *page = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    *page = rw(CMD_PREAD, fd, rbuf, 1, 0, 0);
    mprotect(page, 4096, PROT_READ);
    printf("key-unwritable=%ld\n", submit1(ctx, page));
    printf("pointers-unreadable=%ld\n", submit(ctx, 1, (struct iocb **)8));
    printf("negative-nr=%ld", submit(ctx, -1, list));
    printf(" zero=%ld\n", submit(ctx, 0, NULL));
    /* The count before the first failure. */
    cbs[0] = rw(CMD_PREAD, fd, rbuf, 1, 0, 1);
    cbs[1] = rw(CMD_PREAD, 99, rbuf, 1, 0, 2);
    cbs[2] = rw(CMD_PREAD, fd, rbuf, 1, 0, 3);
    printf("partial=%ld\n", submit(ctx, 3, list));
    reap("partial", ctx, 1, cbs);
    printf("destroy=%ld\n", destroy(ctx));
    unlink(at("file"));
    rmdir(base);
    return 0;
}

static int sigs;
static void counted(int sig) {
    (void)sig;
    sigs++;
}

static int case_streams(void) {
    aio_context_t ctx = 0;
    printf("setup=%ld\n", setup(16, &ctx));
    if (!ctx) return 3;
    signal(SIGPIPE, counted);
    int p[2], q[2], s[2];
    pipe(p);
    pipe2(q, O_NONBLOCK);
    socketpair(AF_UNIX, SOCK_STREAM, 0, s);
    char buf[16] = {0};
    struct iocb cbs[8], *list[8];
    for (int i = 0; i < 8; i++) list[i] = &cbs[i];
    /* A pipe reads and writes whatever the offset. */
    cbs[0] = rw(CMD_PWRITE, p[1], "abc", 3, 12345, 1);
    cbs[1] = rw(CMD_PREAD, p[0], buf, 2, 999, 2);
    cbs[2] = rw(CMD_PREAD, q[0], buf + 4, 2, 0, 3);
    cbs[3] = rw(CMD_PREAD, p[0], buf + 8, 4, 0, 4);
    cbs[3].aio_rw_flags = RWF_NOWAIT;
    printf("submit=%ld\n", submit(ctx, 3, list));
    reap("pipe", ctx, 3, cbs);
    printf("read=%.2s\n", buf);
    /* RWF_NOWAIT takes what is there, and does not wait when nothing is. */
    printf("nowait=%ld", submit1(ctx, &cbs[3]));
    printf(" again=%ld\n", submit1(ctx, &cbs[3]));
    reap("nowait", ctx, 2, cbs);
    /* A sync of a pipe has no fsync; a negative offset is checked for a
       pipe too. */
    struct iocb sync = rw(CMD_FSYNC, p[0], NULL, 0, 0, 0);
    struct iocb neg = rw(CMD_PREAD, p[0], buf, 1, -1, 0);
    printf("pipe-fsync=%ld", submit1(ctx, &sync));
    printf(" pipe-negative=%ld\n", submit1(ctx, &neg));
    /* A socket. */
    cbs[0] = rw(CMD_PWRITE, s[0], "hey", 3, 0, 1);
    cbs[1] = rw(CMD_PREAD, s[1], buf, sizeof buf, 0, 2);
    printf("socket=%ld\n", submit(ctx, 2, list));
    reap("socket", ctx, 2, cbs);
    printf("read=%.3s\n", buf);
    /* An eventfd reads, but has no write_iter. */
    int evfd = eventfd(5, 0);
    uint64_t value = 0;
    cbs[0] = rw(CMD_PREAD, evfd, &value, 8, 0, 1);
    printf("eventfd-read=%ld\n", submit1(ctx, &cbs[0]));
    reap("eventfd", ctx, 1, cbs);
    printf("value=%llu\n", (unsigned long long)value);
    cbs[0] = rw(CMD_PWRITE, evfd, &value, 8, 0, 1);
    printf("eventfd-write=%ld\n", submit1(ctx, &cbs[0]));
    /* A write with no reader: EPIPE for the event, SIGPIPE for the
       submitter. */
    close(q[0]);
    cbs[0] = rw(CMD_PWRITE, q[1], "x", 1, 0, 1);
    printf("broken=%ld\n", submit1(ctx, &cbs[0]));
    reap("broken", ctx, 1, cbs);
    printf("sigpipe=%d\n", sigs);
    /* A read of an empty pipe waits in io_submit for the writer. */
    pid_t child = fork();
    if (child == 0) {
        usleep(50000);
        write(p[1], "late", 4);
        _exit(0);
    }
    cbs[0] = rw(CMD_PREAD, p[0], buf, 4, 0, 1);
    printf("waited=%ld\n", submit1(ctx, &cbs[0]));
    reap("waited", ctx, 1, cbs);
    printf("read=%.4s\n", buf);
    waitpid(child, NULL, 0);
    /* A signal ends the wait: the event is EINTR, the submission counts. */
    struct sigaction sa = {.sa_handler = counted, .sa_flags = SA_RESTART};
    sigaction(SIGALRM, &sa, NULL);
    struct itimerval timer = {.it_value = {.tv_usec = 50000}};
    setitimer(ITIMER_REAL, &timer, NULL);
    sigs = 0;
    printf("interrupted=%ld\n", submit1(ctx, &cbs[0]));
    reap("interrupted", ctx, 1, cbs);
    printf("handled=%d\n", sigs);
    printf("destroy=%ld\n", destroy(ctx));
    return 0;
}

static void *writer(void *arg) {
    usleep(50000);
    write(*(int *)arg, "w", 1);
    return NULL;
}

static int case_poll(void) {
    make_base("poll");
    aio_context_t ctx = 0;
    printf("setup=%ld\n", setup(16, &ctx));
    if (!ctx) return 3;
    int fd = open(at("file"), O_RDWR | O_CREAT | O_TRUNC, 0600);
    int p[2];
    pipe(p);
    int evfd = eventfd(0, EFD_NONBLOCK);
    struct iocb cbs[8], *list[8];
    for (int i = 0; i < 8; i++) list[i] = &cbs[i];
    struct io_event ev[8];
    /* Ready at once: a regular file, a pipe that takes a write. */
    cbs[0] = poll_of(fd, POLLIN, 1);
    cbs[1] = poll_of(p[1], POLLOUT, 2);
    cbs[2] = poll_of(p[1], POLLOUT | POLLWRNORM, 3);
    printf("ready=%ld\n", submit(ctx, 3, list));
    reap("ready", ctx, 3, cbs);
    /* A regular file is never ready for POLLPRI and waits on nothing;
       unknown bits past 16 are EINVAL, as are the other fields. */
    cbs[0] = poll_of(fd, POLLPRI, 1);
    cbs[1] = poll_of(fd, 0x10000, 1);
    cbs[2] = poll_of(fd, POLLIN, 1);
    cbs[2].aio_nbytes = 1;
    cbs[3] = poll_of(fd, POLLIN, 1);
    cbs[3].aio_offset = 1;
    cbs[4] = poll_of(fd, POLLIN, 1);
    cbs[4].aio_rw_flags = 1;
    for (int i = 0; i < 5; i++) printf("bad-%d=%ld\n", i, submit1(ctx, &cbs[i]));
    /* One that waits, counted on an eventfd when the pipe is written. */
    cbs[0] = poll_of(p[0], POLLIN | POLLRDNORM, 1);
    cbs[0].aio_flags = FLAG_RESFD;
    cbs[0].aio_resfd = evfd;
    printf("waits=%ld", submit1(ctx, &cbs[0]));
    printf(" now=%ld\n", getevents(ctx, 0, 8, ev, &zero));
    write(p[1], "x", 1);
    reap("written", ctx, 1, cbs);
    uint64_t count = 0;
    printf("eventfd=%zd", read(evfd, &count, 8));
    printf(" count=%llu\n", (unsigned long long)count);
    char c;
    read(p[0], &c, 1);
    /* Cancelled: EINPROGRESS, and an event of nothing. */
    cbs[1] = poll_of(p[0], POLLIN, 2);
    printf("pending=%ld\n", submit1(ctx, &cbs[1]));
    printf("cancel-done=%ld", cancel(ctx, &cbs[0]));
    printf(" cancel-bad=%ld\n", cancel(ctx, (struct iocb *)8));
    printf("cancel=%ld", cancel(ctx, &cbs[1]));
    printf(" again=%ld\n", cancel(ctx, &cbs[1]));
    reap("cancelled", ctx, 1, cbs);
    cbs[1].aio_key = 1;
    printf("cancel-key=%ld\n", cancel(ctx, &cbs[1]));
    /* Completed while io_getevents waits, by another thread's write. */
    cbs[2] = poll_of(p[0], POLLIN, 3);
    printf("pending=%ld\n", submit1(ctx, &cbs[2]));
    pthread_t thread;
    pthread_create(&thread, NULL, writer, &p[1]);
    reap("thread", ctx, 1, cbs);
    pthread_join(thread, NULL);
    read(p[0], &c, 1);
    /* Completed while epoll waits for its eventfd. */
    cbs[3] = poll_of(p[0], POLLIN, 4);
    cbs[3].aio_flags = FLAG_RESFD;
    cbs[3].aio_resfd = evfd;
    printf("pending=%ld\n", submit1(ctx, &cbs[3]));
    int ep = epoll_create1(0);
    struct epoll_event want = {.events = EPOLLIN};
    epoll_ctl(ep, EPOLL_CTL_ADD, evfd, &want);
    pthread_create(&thread, NULL, writer, &p[1]);
    struct epoll_event got;
    printf("epoll=%d\n", epoll_wait(ep, &got, 1, 5000));
    pthread_join(thread, NULL);
    reap("epoll", ctx, 1, cbs);
    read(evfd, &count, 8);
    read(p[0], &c, 1);
    /* The writer's end hangs the reader up. */
    cbs[4] = poll_of(p[0], POLLIN, 5);
    printf("pending=%ld\n", submit1(ctx, &cbs[4]));
    close(p[1]);
    reap("hangup", ctx, 1, cbs);
    /* A FIFO open to read and write waits on two queues: EINVAL unless it
       is ready. */
    mkfifo(at("fifo"), 0600);
    int fifo = open(at("fifo"), O_RDWR);
    cbs[5] = poll_of(fifo, POLLIN, 6);
    printf("fifo-empty=%ld\n", submit1(ctx, &cbs[5]));
    write(fifo, "y", 1);
    printf("fifo-ready=%ld\n", submit1(ctx, &cbs[5]));
    reap("fifo", ctx, 1, cbs);
    /* io_destroy cancels what still waits, which the eventfd counts. */
    int r[2];
    pipe(r);
    cbs[6] = poll_of(r[0], POLLIN, 7);
    cbs[6].aio_flags = FLAG_RESFD;
    cbs[6].aio_resfd = evfd;
    printf("pending=%ld\n", submit1(ctx, &cbs[6]));
    printf("destroy=%ld\n", destroy(ctx));
    struct pollfd pfd = {.fd = evfd, .events = POLLIN};
    poll(&pfd, 1, 5000);
    printf("eventfd=%zd", read(evfd, &count, 8));
    printf(" count=%llu\n", (unsigned long long)count);
    unlink(at("fifo"));
    unlink(at("file"));
    rmdir(base);
    return 0;
}

static void handled(int sig) {
    (void)sig;
    sigs++;
}

static int case_getevents(void) {
    aio_context_t ctx = 0;
    printf("setup=%ld\n", setup(4, &ctx));
    if (!ctx) return 3;
    struct aio_ring *ring = (struct aio_ring *)ctx;
    struct io_event ev[8];
    int p[2];
    pipe(p);
    char buf[4];
    struct iocb cbs[8], *list[8];
    for (int i = 0; i < 8; i++) {
        list[i] = &cbs[i];
        cbs[i] = rw(CMD_PREAD, p[0], buf, 0, 0, i + 1);
    }
    printf("timeout-efault=%ld\n", getevents(ctx, 0, 1, ev, (struct timespec *)8));
    printf("min-past-nr=%ld", getevents(ctx, 2, 1, ev, &zero));
    printf(" min-negative=%ld", getevents(ctx, -1, 1, ev, &zero));
    printf(" nothing=%ld\n", getevents(ctx, 0, 0, ev, NULL));
    struct timespec ms10 = {.tv_nsec = 10000000};
    printf("empty=%ld", getevents(ctx, 0, 8, ev, &zero));
    printf(" timed-out=%ld\n", getevents(ctx, 1, 8, ev, &ms10));
    /* A negative timeout waits as none does, which Linux's timer never
       ends: not printed, as nothing would end it here. */
    /* The events are in the ring as io_submit returns, where the program
       may take them itself. */
    printf("submit=%ld", submit(ctx, 3, list));
    printf(" head=%u tail=%u\n", ring->head, ring->tail);
    printf("efault=%ld", getevents(ctx, 1, 8, (struct io_event *)8, NULL));
    printf(" head=%u\n", ring->head);
    printf("one=%ld", getevents(ctx, 1, 1, ev, NULL));
    printf(" data=%llu head=%u\n", (unsigned long long)ev[0].data, ring->head);
    ring->head = ring->tail;
    printf("taken=%ld\n", getevents(ctx, 0, 8, ev, &zero));
    /* A head past the events is taken modulo them. */
    printf("submit=%ld\n", submit(ctx, 1, list));
    ring->head += ring->nr;
    printf("modulo=%ld", getevents(ctx, 1, 8, ev, &zero));
    printf(" data=%llu\n", (unsigned long long)ev[0].data);
    /* Fewer than min_nr when the time is up. */
    submit(ctx, 1, list);
    printf("partial=%ld\n", getevents(ctx, 2, 8, ev, &ms10));
    /* A signal ends the wait with EINTR, which SA_RESTART does not restart,
       for io_getevents and io_pgetevents alike. */
    struct sigaction sa = {.sa_handler = handled, .sa_flags = SA_RESTART};
    sigaction(SIGALRM, &sa, NULL);
    struct itimerval timer = {.it_value = {.tv_usec = 30000}};
    setitimer(ITIMER_REAL, &timer, NULL);
    printf("interrupted=%ld", getevents(ctx, 1, 8, ev, NULL));
    printf(" handled=%d\n", sigs);
    setitimer(ITIMER_REAL, &timer, NULL);
    printf("p-interrupted=%ld", pgetevents(ctx, 1, 8, ev, NULL, NULL));
    printf(" handled=%d\n", sigs);
    /* io_pgetevents: its mask, then the size, are checked; the mask is in
       place while it waits, and the old one back after the handler. */
    struct {
        sigset_t *mask;
        size_t size;
    } usig;
    sigset_t blocked, open_mask, now;
    sigemptyset(&blocked);
    sigaddset(&blocked, SIGALRM);
    sigprocmask(SIG_BLOCK, &blocked, NULL);
    sigemptyset(&open_mask);
    usig.mask = &open_mask;
    usig.size = 4;
    printf("usig-efault=%ld", pgetevents(ctx, 0, 1, ev, &zero, (void *)8));
    printf(" size=%ld", pgetevents(ctx, 0, 1, ev, &zero, &usig));
    usig.mask = (sigset_t *)8;
    usig.size = 8;
    printf(" mask-efault=%ld\n", pgetevents(ctx, 0, 1, ev, &zero, &usig));
    usig.mask = &open_mask;
    setitimer(ITIMER_REAL, &timer, NULL);
    printf("unblocked=%ld", pgetevents(ctx, 1, 8, ev, NULL, &usig));
    sigprocmask(SIG_BLOCK, NULL, &now);
    printf(" handled=%d blocked-again=%d\n", sigs, sigismember(&now, SIGALRM));
    /* With the signal blocked and pending, io_getevents waits on. */
    raise(SIGALRM);
    printf("blocked-pending=%ld\n", getevents(ctx, 1, 8, ev, &ms10));
    sigprocmask(SIG_UNBLOCK, &blocked, NULL);
    printf("handled=%d\n", sigs);
    printf("destroy=%ld\n", destroy(ctx));
    return 0;
}

static int case_full(void) {
    aio_context_t ctx = 0;
    printf("setup=%ld\n", setup(1, &ctx));
    if (!ctx) return 3;
    struct aio_ring *ring = (struct aio_ring *)ctx;
    int p[2];
    pipe(p);
    char buf[1];
    struct iocb cb = rw(CMD_PREAD, p[0], buf, 0, 0, 1), *list[1] = {&cb};
    /* Requests take places in the ring until it is full: at least as many
       as asked for, fewer than its events (how many depends on the CPUs). */
    long taken = 0, r;
    while ((r = submit(ctx, 1, list)) == 1) taken++;
    printf("full=%ld enough=%d fewer=%d\n", r, taken >= 1, taken < (long)ring->nr);
    struct io_event ev[64];
    long got = 0;
    while ((r = getevents(ctx, 0, 64, ev, &zero)) > 0) got += r;
    printf("reaped-all=%d\n", got == taken);
    printf("room=%ld\n", submit(ctx, 1, list));
    printf("destroy=%ld\n", destroy(ctx));
    return 0;
}

static aio_context_t shared_ctx;
static void *waiter(void *arg) {
    struct io_event ev;
    (void)arg;
    long r = getevents(shared_ctx, 1, 1, &ev, NULL);
    return (void *)r;
}

/* A ring is a fixed mapping: mremap neither grows it (EFAULT) nor leaves it
 * behind (MREMAP_DONTUNMAP, EINVAL), and moves it whole with its context.
 * A move of part of it, which Linux master refuses since 2026-04
 * (aio_ring_mremap), is left out: CI's kernel may be older. */
static int case_mremap(void) {
    aio_context_t ctx = 0;
    printf("setup=%ld\n", setup(1000, &ctx));
    if (!ctx) return 3;
    unsigned long size = 32 + 32 * (unsigned long)((struct aio_ring *)ctx)->nr;
    printf("pages=%lu\n", size / 4096);
    void *grown = mremap((void *)ctx, size, size + 4096, MREMAP_MAYMOVE);
    printf("grow=%d\n", grown == MAP_FAILED ? -errno : 0);
    void *kept = mremap((void *)ctx, size, size, MREMAP_MAYMOVE | MREMAP_DONTUNMAP);
    printf("dontunmap=%d\n", kept == MAP_FAILED ? -errno : 0);
    void *to = mmap(NULL, size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (to == MAP_FAILED) return 4;
    void *moved = mremap((void *)ctx, size, size, MREMAP_MAYMOVE | MREMAP_FIXED, to);
    printf("moved=%d\n", moved == to ? 0 : -errno);
    printf("old destroy=%ld\n", destroy(ctx));
    printf("new destroy=%ld\n", destroy((aio_context_t)to));
    return 0;
}

static int case_lifetime(int argc, char **argv) {
    unsigned long before = aio_nr();
    aio_context_t ctx = 0;
    printf("setup=%ld\n", setup(10, &ctx));
    if (!ctx) return 3;
    int p[2];
    pipe(p);
    char buf[1];
    struct iocb cb = rw(CMD_PREAD, p[0], buf, 0, 0, 1);
    /* A fork's child has neither the contexts nor their rings, and may make
       its own; its exit ends them. */
    pid_t child = fork();
    if (child == 0) {
        printf("child: submit=%ld", submit1(ctx, &cb));
        printf(" destroy=%ld\n", destroy(ctx));
        aio_context_t own = 0;
        printf("child: setup=%ld", setup(5, &own));
        if (!own) _exit(3);
        printf(" id=%u aio-nr+%lu\n", ((struct aio_ring *)own)->id, aio_nr() - before);
        fflush(stdout);
        _exit(0);
    }
    waitpid(child, NULL, 0);
    printf("after-child: aio-nr+%lu\n", aio_nr() - before);
    printf("parent: submit=%ld\n", submit1(ctx, &cb));
    reap("parent", ctx, 1, NULL);
    /* A vfork child shares the address space and so the contexts. */
    child = vfork();
    if (child == 0) {
        syscall(SYS_io_submit, ctx, 1, (struct iocb *[]){&cb});
        _exit(0);
    }
    waitpid(child, NULL, 0);
    reap("vfork", ctx, 1, NULL);
    /* A thread waiting in io_getevents sees the context end. */
    shared_ctx = ctx;
    pthread_t thread;
    pthread_create(&thread, NULL, waiter, NULL);
    usleep(50000);
    printf("destroy=%ld\n", destroy(ctx));
    void *r;
    pthread_join(thread, &r);
    printf("waiter=%ld\n", (long)r);
    printf("aio-nr+%lu\n", aio_nr() - before);
    /* execve ends the contexts of the address space it leaves. */
    ctx = 0;
    printf("setup=%ld\n", setup(7, &ctx));
    if (!ctx) return 3;
    printf("aio-nr+%lu\n", aio_nr() - before);
    fflush(stdout);
    char ctx_arg[32], before_arg[32];
    snprintf(ctx_arg, sizeof ctx_arg, "%lu", ctx);
    snprintf(before_arg, sizeof before_arg, "%lu", before);
    child = fork();
    if (child == 0) {
        aio_context_t mine = 0;
        setup(3, &mine);
        snprintf(ctx_arg, sizeof ctx_arg, "%lu", mine);
        execl(argc > 2 ? argv[2] : "/proc/self/exe", "aio", "aio-exec", ctx_arg, before_arg, (char *)NULL);
        _exit(93);
    }
    waitpid(child, NULL, 0);
    printf("aio-nr+%lu\n", aio_nr() - before);
    printf("destroy=%ld\n", destroy(ctx));
    printf("aio-nr+%lu\n", aio_nr() - before);
    return 0;
}

static int case_exec(char **argv) {
    aio_context_t ctx = strtoul(argv[2], NULL, 10);
    unsigned long before = strtoul(argv[3], NULL, 10);
    /* The parent's context counts, the one execve left does not. */
    printf("exec: destroy=%ld", destroy(ctx));
    printf(" aio-nr+%lu\n", aio_nr() - before);
    return 0;
}

int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "";
    setvbuf(stdout, NULL, _IOLBF, 0);
    alarm(20);
    if (!strcmp(mode, "aio-calls")) return case_calls();
    if (!strcmp(mode, "aio-rw")) return case_rw();
    if (!strcmp(mode, "aio-streams")) return case_streams();
    if (!strcmp(mode, "aio-poll")) return case_poll();
    if (!strcmp(mode, "aio-getevents")) return case_getevents();
    if (!strcmp(mode, "aio-full")) return case_full();
    if (!strcmp(mode, "aio-lifetime")) return case_lifetime(argc, argv);
    if (!strcmp(mode, "aio-mremap")) return case_mremap();
    if (!strcmp(mode, "aio-exec") && argc > 3) return case_exec(argv);
    return 2;
}
