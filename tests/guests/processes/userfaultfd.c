/* userfaultfd, compared with Linux: the calls' errors and their order,
   UFFDIO_API and the ranges UFFDIO_REGISTER makes (the VMAs of
   /proc/self/maps and the `um` of smaps), and the faults of a thread on
   missing pages: the messages a read gives, UFFDIO_COPY, UFFDIO_ZEROPAGE,
   UFFDIO_WAKE and UFFDIO_UNREGISTER ending the wait, the features
   THREAD_ID, EXACT_ADDRESS and SIGBUS, a signal during the wait, closing
   the file, fork, and shared anonymous memory; and write protection:
   UFFDIO_REGISTER_MODE_WP (the `uw` of smaps), UFFDIO_WRITEPROTECT and
   UFFDIO_COPY_MODE_WP, the faults of writes to protected pages, which
   end with the protection, and what mprotect, fork and unregistering do
   to it; and UFFDIO_POISON: its errors, the SIGBUS of an access to a
   poisoned page (si_code and si_addr_lsb), a system call's copy and
   MADV_POPULATE_READ there, and what mprotect, fork, unregistering,
   mremap, MADV_DONTNEED, MADV_FREE, MADV_GUARD_INSTALL and munmap do to
   the poison, of private and of shared anonymous memory; and
   UFFDIO_MOVE: its errors and their order, a hole, a move that stops
   short, the wake of a fault, a page fork shares, the zero page, and
   guards at either end; and a memfd's mappings: shared and private, a
   hole that waits and a page the file has, fills that reach the file or
   do not, the end of the file, and the mappings that cannot be
   registered (one that may not write the file, System V shared memory);
   and the minor mode: a memfd's page the page cache has waits until
   UFFDIO_CONTINUE maps it, its errors, and a private mapping of it; and
   the write protection of a memfd's mapping and, with WP_UNPOPULATED, of
   private anonymous memory: the pages UFFDIO_WRITEPROTECT protects that
   have no entry (their bits in /proc/self/pagemap), a read and a write of
   one, what MADV_DONTNEED, fills, the minor mode, fork and mremap do to
   the protection; and WP_ASYNC: the features it brings, a write to a
   protected page that clears the protection rather than faulting (an
   instruction's and a system call's), of private anonymous memory and of
   the memory only WP_ASYNC registers (a file's private and shared
   mappings, System V shared memory), the modes and mappings it still
   refuses, and what MADV_DONTNEED does to a file's protected pages; and
   the events: fork's, whose message hands the child's new userfaultfd
   over, which the child's faults reach; mremap's move, which keeps the
   registration, and the unmaps it gives; MADV_DONTNEED's remove; the
   unmaps of munmap and a MAP_FIXED mmap; a context without the features,
   which is told nothing; and the fills that are EAGAIN while an unmap
   waits for its event to be read.

   Addresses are printed as offsets from the mapping, and thread IDs as
   whether they are the faulting thread's. Of what UFFDIO_API and
   UFFDIO_REGISTER report, the features and ioctls the cases use are
   checked, not the whole masks. The cases run as root, for a userfaultfd
   that the kernel's own faults reach (CAP_SYS_PTRACE). */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#define UFFD_API 0xaaULL
#define UFFD_USER_MODE_ONLY 1
#define UFFD_EVENT_PAGEFAULT 0x12
#define UFFD_PAGEFAULT_FLAG_WRITE 1
#define UFFD_FEATURE_PAGEFAULT_FLAG_WP (1ULL << 0)
#define UFFD_FEATURE_EVENT_FORK (1ULL << 1)
#define UFFD_FEATURE_EVENT_REMAP (1ULL << 2)
#define UFFD_FEATURE_EVENT_REMOVE (1ULL << 3)
#define UFFD_FEATURE_EVENT_UNMAP (1ULL << 6)
#define UFFD_EVENT_FORK 0x13
#define UFFD_EVENT_REMAP 0x14
#define UFFD_EVENT_REMOVE 0x15
#define UFFD_EVENT_UNMAP 0x16
#define UFFD_FEATURE_MISSING_SHMEM (1ULL << 5)
#define UFFD_FEATURE_SIGBUS (1ULL << 7)
#define UFFD_FEATURE_THREAD_ID (1ULL << 8)
#define UFFD_FEATURE_EXACT_ADDRESS (1ULL << 11)
#define UFFD_FEATURE_POISON (1ULL << 14)
#define UFFD_FEATURE_MOVE (1ULL << 16)
#define UFFD_FEATURE_MINOR_SHMEM (1ULL << 10)
#define UFFD_FEATURE_WP_HUGETLBFS_SHMEM (1ULL << 12)
#define UFFD_FEATURE_WP_UNPOPULATED (1ULL << 13)
#define UFFD_FEATURE_WP_ASYNC (1ULL << 15)
#define UFFD_PAGEFAULT_FLAG_MINOR 4
#define UFFDIO_REGISTER_MODE_MISSING 1ULL
#define UFFDIO_REGISTER_MODE_WP 2ULL
#define UFFDIO_REGISTER_MODE_MINOR 4ULL
#define UFFDIO_COPY_MODE_WP 2ULL
#define UFFDIO_WRITEPROTECT_MODE_WP 1ULL
#define UFFDIO_WRITEPROTECT_MODE_DONTWAKE 2ULL
#define UFFDIO_COPY_MODE_DONTWAKE 1ULL
#define UFFDIO_ZEROPAGE_MODE_DONTWAKE 1ULL
#define UFFDIO_POISON_MODE_DONTWAKE 1ULL
#define UFFDIO_MOVE_MODE_DONTWAKE 1ULL
#define UFFDIO_MOVE_MODE_ALLOW_SRC_HOLES 2ULL

#define UFFDIO_API 0xc018aa3f
#define UFFDIO_REGISTER 0xc020aa00
#define UFFDIO_UNREGISTER 0x8010aa01
#define UFFDIO_WAKE 0x8010aa02
#define UFFDIO_COPY 0xc028aa03
#define UFFDIO_ZEROPAGE 0xc020aa04
#define UFFDIO_MOVE 0xc028aa05
#define UFFDIO_WRITEPROTECT 0xc018aa06
#define UFFDIO_POISON 0xc020aa08
#define UFFDIO_CONTINUE 0xc020aa07
#define UFFDIO_CONTINUE_MODE_DONTWAKE 1ULL
#define UFFDIO_CONTINUE_MODE_WP 2ULL

#define RANGE_IOCTLS ((1ULL << 2) | (1ULL << 3) | (1ULL << 4))
#define WRITEPROTECT_IOCTL (1ULL << 6)
#define POISON_IOCTL (1ULL << 8)
#define CONTINUE_IOCTL (1ULL << 7)
#define MOVE_IOCTL (1ULL << 5)
#ifndef MADV_POPULATE_READ
#define MADV_POPULATE_READ 22
#endif
#ifndef MADV_GUARD_INSTALL
#define MADV_GUARD_INSTALL 102
#define MADV_GUARD_REMOVE 103
#endif
#define PAGE 4096

struct uffdio_api {
    uint64_t api, features, ioctls;
};
struct uffdio_range {
    uint64_t start, len;
};
struct uffdio_register {
    struct uffdio_range range;
    uint64_t mode, ioctls;
};
struct uffdio_copy {
    uint64_t dst, src, len, mode;
    int64_t copy;
};
struct uffdio_zeropage {
    struct uffdio_range range;
    uint64_t mode;
    int64_t zeropage;
};
struct uffdio_writeprotect {
    struct uffdio_range range;
    uint64_t mode;
};
struct uffdio_poison {
    struct uffdio_range range;
    uint64_t mode;
    int64_t updated;
};
struct uffdio_continue {
    struct uffdio_range range;
    uint64_t mode;
    int64_t mapped;
};
struct uffdio_move {
    uint64_t dst, src, len, mode;
    int64_t move;
};
struct uffd_msg {
    uint8_t event, reserved1;
    uint16_t reserved2;
    uint32_t reserved3;
    uint64_t flags, address;
    uint32_t ptid;
    uint32_t pad;
};

static const char *err(long r) {
    static char buf[32];
    if (r >= 0) {
        snprintf(buf, sizeof buf, "%ld", r);
        return buf;
    }
    return strerror(errno);
}

static int uffd(int flags) {
    return syscall(SYS_userfaultfd, flags);
}

/* A userfaultfd that took `features`, or -1. */
static int ready(int flags, uint64_t features) {
    int fd = uffd(flags);
    if (fd < 0) {
        printf("userfaultfd: %s\n", strerror(errno));
        return -1;
    }
    struct uffdio_api api = {UFFD_API, features, 0};
    if (ioctl(fd, UFFDIO_API, &api)) {
        printf("UFFDIO_API: %s\n", strerror(errno));
        close(fd);
        return -1;
    }
    return fd;
}

static long reg(int fd, void *at, size_t len, uint64_t mode, uint64_t *ioctls) {
    struct uffdio_register r = {{(uintptr_t)at, len}, mode, 0};
    long ret = ioctl(fd, UFFDIO_REGISTER, &r);
    if (ioctls)
        *ioctls = r.ioctls;
    return ret;
}

static long unreg(int fd, void *at, size_t len) {
    struct uffdio_range r = {(uintptr_t)at, len};
    return ioctl(fd, UFFDIO_UNREGISTER, &r);
}

static long copy(int fd, void *dst, const void *src, size_t len, uint64_t mode, int64_t *done) {
    struct uffdio_copy c = {(uintptr_t)dst, (uintptr_t)src, len, mode, 0x5a5a};
    long ret = ioctl(fd, UFFDIO_COPY, &c);
    if (done)
        *done = c.copy;
    return ret;
}

static long protect(int fd, void *at, size_t len, uint64_t mode) {
    struct uffdio_writeprotect w = {{(uintptr_t)at, len}, mode};
    return ioctl(fd, UFFDIO_WRITEPROTECT, &w);
}

static long zeropage(int fd, void *dst, size_t len, uint64_t mode, int64_t *done) {
    struct uffdio_zeropage z = {{(uintptr_t)dst, len}, mode, 0x5a5a};
    long ret = ioctl(fd, UFFDIO_ZEROPAGE, &z);
    if (done)
        *done = z.zeropage;
    return ret;
}

static long poison(int fd, void *at, size_t len, uint64_t mode, int64_t *done) {
    struct uffdio_poison p = {{(uintptr_t)at, len}, mode, 0x5a5a};
    long ret = ioctl(fd, UFFDIO_POISON, &p);
    if (done)
        *done = p.updated;
    return ret;
}

static long move(int fd, void *dst, void *src, size_t len, uint64_t mode, int64_t *done) {
    struct uffdio_move m = {(uintptr_t)dst, (uintptr_t)src, len, mode, 0x5a5a};
    long ret = ioctl(fd, UFFDIO_MOVE, &m);
    if (done)
        *done = m.move;
    return ret;
}

/* `len` bytes of private anonymous memory between two pages that cannot be
   accessed, so that its VMAs merge with no other. */
static void *anon(size_t len) {
    char *area = mmap(NULL, len + 2 * PAGE, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    mprotect(area + PAGE, len, PROT_READ | PROT_WRITE);
    return area + PAGE;
}

/* Whether the VmFlags of the VMA at `at` have `um` and `uw`; the VMA's
   bounds as offsets from `base`. */
static void vma(const char *what, void *base, void *at) {
    FILE *f = fopen("/proc/self/smaps", "r");
    char line[512];
    unsigned long start = 0, end = 0, a = (uintptr_t)at;
    int inside = 0;
    while (f && fgets(line, sizeof line, f)) {
        unsigned long s, e;
        if (sscanf(line, "%lx-%lx ", &s, &e) == 2 && strchr(line, '-') < strchr(line, ' ')) {
            inside = s <= a && a < e;
            if (inside)
                start = s, end = e;
            continue;
        }
        if (inside && !strncmp(line, "VmFlags:", 8)) {
            printf("%s: [%ld, %ld) um=%d uw=%d\n", what, (long)(start - (uintptr_t)base),
                   (long)(end - (uintptr_t)base), strstr(line, " um") != NULL,
                   strstr(line, " uw") != NULL);
            fclose(f);
            return;
        }
    }
    if (f)
        fclose(f);
    printf("%s: none\n", what);
}

static void fdinfo(const char *what, int fd);

static sigjmp_buf refused;
static void on_segv(int sig, siginfo_t *info, void *context) {
    (void)context;
    printf("signal %d code %d\n", sig, info->si_code);
    siglongjmp(refused, 1);
}

/* The calls' errors and their order. */
static int case_calls(void) {
    printf("bad flags: %s\n", err(uffd(0x10)));
    printf("user mode only, bad flags: %s\n", err(uffd(UFFD_USER_MODE_ONLY | 0x10)));
    int fd = uffd(O_CLOEXEC | O_NONBLOCK);
    printf("made: %d\n", fd >= 0);
    printf("F_GETFL: 0%o\n", fcntl(fd, F_GETFL));
    printf("F_GETFD: %d\n", fcntl(fd, F_GETFD));
    char link[64] = {0};
    char path[64];
    snprintf(path, sizeof path, "/proc/self/fd/%d", fd);
    readlink(path, link, sizeof link - 1);
    printf("link: %s\n", link);
    struct uffd_msg msg;
    printf("read before API: %s\n", err(read(fd, &msg, sizeof msg)));
    struct pollfd p = {fd, POLLIN, 0};
    int polled = poll(&p, 1, 0);
    printf("poll before API: %d %#x\n", polled, p.revents);
    uint64_t ioctls;
    printf("register before API: %s\n", err(reg(fd, (void *)0x100000, PAGE, 1, &ioctls)));
    struct uffdio_api api = {0xab, 0, 0};
    printf("bad API: %s", err(ioctl(fd, UFFDIO_API, &api)));
    printf(" -> %llx %llx %llx\n", (unsigned long long)api.api,
           (unsigned long long)api.features, (unsigned long long)api.ioctls);
    api = (struct uffdio_api){UFFD_API, 1ULL << 30, 0};
    printf("unknown feature: %s", err(ioctl(fd, UFFDIO_API, &api)));
    printf(" -> %llx %llx\n", (unsigned long long)api.api, (unsigned long long)api.ioctls);
    printf("API at NULL: %s\n", err(ioctl(fd, UFFDIO_API, NULL)));
    api = (struct uffdio_api){UFFD_API, UFFD_FEATURE_THREAD_ID, 0};
    printf("API: %s", err(ioctl(fd, UFFDIO_API, &api)));
    uint64_t used = UFFD_FEATURE_MISSING_SHMEM | UFFD_FEATURE_SIGBUS | UFFD_FEATURE_THREAD_ID |
                    UFFD_FEATURE_EXACT_ADDRESS;
    printf(" -> %llx features=%d %llx\n", (unsigned long long)api.api,
           (api.features & used) == used, (unsigned long long)api.ioctls);
    api = (struct uffdio_api){UFFD_API, 0, 0};
    printf("API again: %s", err(ioctl(fd, UFFDIO_API, &api)));
    printf(" -> %llx %llx %llx\n", (unsigned long long)api.api,
           (unsigned long long)api.features, (unsigned long long)api.ioctls);
    printf("unknown ioctl: %s\n", err(ioctl(fd, 0xc018aa3e, &api)));
    printf("read empty: %s\n", err(read(fd, &msg, sizeof msg)));
    printf("read short: %s\n", err(read(fd, &msg, sizeof msg - 1)));
    p.revents = 0;
    polled = poll(&p, 1, 0);
    printf("poll empty: %d %#x\n", polled, p.revents);
    printf("write: %s\n", err(write(fd, &msg, sizeof msg)));
    printf("lseek: %s\n", err(lseek(fd, 10, SEEK_SET)));

    char *base = anon(8 * PAGE);
    printf("mode 0: %s\n", err(reg(fd, base, PAGE, 0, NULL)));
    printf("mode 8: %s\n", err(reg(fd, base, PAGE, 8, NULL)));
    printf("unaligned start: %s\n", err(reg(fd, base + 1, PAGE, 1, NULL)));
    printf("unaligned len: %s\n", err(reg(fd, base, PAGE + 1, 1, NULL)));
    printf("len 0: %s\n", err(reg(fd, base, 0, 1, NULL)));
    printf("below mmap_min_addr: %s\n", err(reg(fd, (void *)0x1000, PAGE, 1, NULL)));
    printf("no VMA: %s\n", err(reg(fd, (void *)0x200000000000, PAGE, 1, NULL)));
    printf("register at NULL: %s\n", err(ioctl(fd, UFFDIO_REGISTER, NULL)));
    int file = open("/proc/self/exe", O_RDONLY);
    void *mapped = mmap(NULL, PAGE, PROT_READ, MAP_PRIVATE, file, 0);
    printf("file mapping: %s\n", err(reg(fd, mapped, PAGE, 1, NULL)));
    munmap(mapped, PAGE);
    close(file);

    ioctls = 0;
    printf("register: %s", err(reg(fd, base + 2 * PAGE, 3 * PAGE, 1, &ioctls)));
    printf(" ioctls=%d\n", (ioctls & RANGE_IOCTLS) == RANGE_IOCTLS);
    vma("below", base, base);
    vma("registered", base, base + 2 * PAGE);
    vma("above", base, base + 6 * PAGE);
    printf("register again: %s\n", err(reg(fd, base + 2 * PAGE, 3 * PAGE, 1, NULL)));
    int other = ready(0, 0);
    printf("other's range: %s\n", err(reg(other, base + 3 * PAGE, PAGE, 1, NULL)));
    printf("other unregisters: %s\n", err(unreg(other, base + 3 * PAGE, PAGE)));
    printf("other, beside: %s\n", err(reg(other, base, 2 * PAGE, 1, NULL)));
    vma("other's", base, base);
    close(other);
    vma("after closing the other", base, base);

    int64_t done;
    char src[PAGE];
    memset(src, 'c', sizeof src);
    printf("copy, bad mode: %s\n", err(copy(fd, base + 2 * PAGE, src, PAGE, 4, &done)));
    printf("copy, unaligned dst: %s\n", err(copy(fd, base + 2 * PAGE + 8, src, PAGE, 0, &done)));
    /* Elsewhere than in a range, which gives its VMA an anon_vma of its
       own: a VMA of this mapping that took one would not merge with the
       others again (is_mergeable_anon_vma). */
    char *elsewhere = anon(PAGE);
    printf("copy outside: %s", err(copy(fd, elsewhere, src, PAGE, 0, &done)));
    printf(" copy=%lld\n", (long long)done);
    printf("copy across the end: %s", err(copy(fd, base + 4 * PAGE, src, 2 * PAGE, 0, &done)));
    printf(" copy=%lld\n", (long long)done);
    printf("copy from NULL: %s", err(copy(fd, base + 2 * PAGE, (void *)0x10000, PAGE, 0, &done)));
    printf(" copy=%lld\n", (long long)done);
    /* From an address within a page, which a copy may be from. */
    static char from[2 * PAGE];
    memset(from, 'c', sizeof from);
    from[PAGE] = 'd';
    printf("copy from within a page: %s", err(copy(fd, base + 2 * PAGE, from + 1, PAGE, 0, &done)));
    printf(" copy=%lld bytes=%c%c\n", (long long)done, base[2 * PAGE + 5], base[3 * PAGE - 1]);
    printf("copy again: %s", err(copy(fd, base + 2 * PAGE, src, PAGE, 0, &done)));
    printf(" copy=%lld\n", (long long)done);
    printf("zeropage: %s", err(zeropage(fd, base + 4 * PAGE, PAGE, 0, &done)));
    printf(" zeropage=%lld byte=%d\n", (long long)done, base[4 * PAGE]);
    printf("copy up to a page: %s", err(copy(fd, base + 3 * PAGE, src, 2 * PAGE, 0, &done)));
    printf(" copy=%lld byte=%c\n", (long long)done, base[3 * PAGE]);
    printf("zeropage, bad mode: %s\n", err(zeropage(fd, base + 2 * PAGE, PAGE, 2, &done)));
    printf("zeropage on a page: %s", err(zeropage(fd, base + 2 * PAGE, PAGE, 0, &done)));
    printf(" zeropage=%lld\n", (long long)done);
    printf("unregister unaligned: %s\n", err(unreg(fd, base + 1, PAGE)));
    printf("unregister no VMA: %s\n", err(unreg(fd, (void *)0x200000000000, PAGE)));
    printf("unregister part: %s\n", err(unreg(fd, base + 3 * PAGE, PAGE)));
    vma("left", base, base + 2 * PAGE);
    vma("unregistered", base, base + 3 * PAGE);
    vma("right", base, base + 4 * PAGE);
    printf("zeropage unregistered: %s", err(zeropage(fd, base + 3 * PAGE, PAGE, 0, &done)));
    printf(" zeropage=%lld\n", (long long)done);
    printf("wake: %s\n", err(ioctl(fd, UFFDIO_WAKE, &(struct uffdio_range){(uintptr_t)base, PAGE})));
    printf("wake, len 0: %s\n", err(ioctl(fd, UFFDIO_WAKE, &(struct uffdio_range){(uintptr_t)base, 0})));
    /* An access the protection refuses is SIGSEGV (SEGV_ACCERR), not a
       fault for the userfaultfd. */
    printf("register read-only: %s\n", err(reg(fd, base + 6 * PAGE, PAGE, 1, NULL)));
    mprotect(base + 6 * PAGE, PAGE, PROT_READ);
    struct sigaction segv = {0};
    segv.sa_sigaction = on_segv;
    segv.sa_flags = SA_SIGINFO;
    sigaction(SIGSEGV, &segv, NULL);
    if (!sigsetjmp(refused, 1))
        base[6 * PAGE] = 'x';
    signal(SIGSEGV, SIG_DFL);
    fdinfo("refused", fd);
    mprotect(base + 6 * PAGE, PAGE, PROT_READ | PROT_WRITE);
    printf("unregister all: %s\n", err(unreg(fd, base, 8 * PAGE)));
    vma("all", base, base + 2 * PAGE);
    close(fd);
    return 0;
}

/* A thread that touches the pages it is given. */
struct toucher {
    volatile char *at;
    int write;
    char seen;
    pid_t tid;
};

static void *touch(void *arg) {
    struct toucher *t = arg;
    t->tid = gettid();
    if (t->write)
        *t->at = 'w';
    t->seen = *t->at;
    return NULL;
}

static void message(const char *what, int fd, void *base, pid_t tid) {
    struct uffd_msg msg;
    memset(&msg, 0xee, sizeof msg);
    long n = read(fd, &msg, sizeof msg);
    if (n < 0) {
        printf("%s: %s\n", what, strerror(errno));
        return;
    }
    printf("%s: %ld event=%#x flags=%llu at=%ld thread=%d reserved=%d%d%d\n", what, n, msg.event,
           (unsigned long long)msg.flags, (long)(msg.address - (uintptr_t)base),
           tid ? (pid_t)msg.ptid == tid : (int)msg.ptid, msg.reserved1, msg.reserved2,
           msg.reserved3);
}

static void fdinfo(const char *what, int fd) {
    char path[64], line[256];
    snprintf(path, sizeof path, "/proc/self/fdinfo/%d", fd);
    FILE *f = fopen(path, "r");
    printf("%s:", what);
    while (f && fgets(line, sizeof line, f)) {
        if (!strncmp(line, "pending:", 8) || !strncmp(line, "total:", 6)) {
            line[strcspn(line, "\n")] = 0;
            printf(" %s", line);
        } else if (!strncmp(line, "API:", 4)) {
            /* The version and the features; the ioctls are the kernel's. */
            *strrchr(line, ':') = 0;
            printf(" %s", line);
        }
    }
    printf("\n");
    if (f)
        fclose(f);
}

/* Waits until `fd` has a message, for at most a few seconds. */
static int wait_message(int fd) {
    struct pollfd p = {fd, POLLIN, 0};
    return poll(&p, 1, 5000);
}

static void wait_blocked(pid_t tid) {
    /* The thread sleeps in the fault: `S` in its stat. */
    char path[64], buf[256];
    snprintf(path, sizeof path, "/proc/self/task/%d/stat", tid);
    for (int i = 0; i < 500; i++) {
        FILE *f = fopen(path, "r");
        if (f) {
            size_t n = fread(buf, 1, sizeof buf - 1, f);
            fclose(f);
            buf[n] = 0;
            char *state = strrchr(buf, ')');
            if (state && state[2] == 'S')
                return;
        }
        usleep(10000);
    }
}

/* The faults of a thread, which reads give and fills end. */
static int case_faults(void) {
    int fd = ready(O_NONBLOCK, UFFD_FEATURE_THREAD_ID);
    char *base = anon(4 * PAGE);
    reg(fd, base, 4 * PAGE, UFFDIO_REGISTER_MODE_MISSING, NULL);
    char src[PAGE];
    memset(src, 'c', sizeof src);
    int64_t done;

    /* A read fault, which UFFDIO_ZEROPAGE ends. */
    struct toucher t = {base + 100, 0, 0, 0};
    pthread_t thread;
    pthread_create(&thread, NULL, touch, &t);
    printf("polled: %d\n", wait_message(fd));
    fdinfo("pending", fd);
    while (!t.tid)
        usleep(1000);
    message("read fault", fd, base, t.tid);
    fdinfo("read", fd);
    struct pollfd p = {fd, POLLIN, 0};
    printf("poll after the read: %d\n", poll(&p, 1, 0));
    printf("zeropage: %s", err(zeropage(fd, base, PAGE, 0, &done)));
    printf(" zeropage=%lld\n", (long long)done);
    pthread_join(thread, NULL);
    printf("seen: %d\n", t.seen);
    fdinfo("after", fd);

    /* A write fault, which UFFDIO_COPY ends; the thread's ID is in the
       message. */
    t = (struct toucher){base + PAGE + 7, 1, 0, 0};
    pthread_create(&thread, NULL, touch, &t);
    wait_message(fd);
    while (!t.tid)
        usleep(1000);
    message("write fault", fd, base, t.tid);
    printf("copy: %s", err(copy(fd, base + PAGE, src, PAGE, 0, &done)));
    printf(" copy=%lld\n", (long long)done);
    pthread_join(thread, NULL);
    printf("seen: %c, byte 8: %c\n", t.seen, base[PAGE + 8]);

    /* UFFDIO_COPY_MODE_DONTWAKE leaves it waiting until UFFDIO_WAKE. */
    t = (struct toucher){base + 2 * PAGE, 0, 0, 0};
    pthread_create(&thread, NULL, touch, &t);
    wait_message(fd);
    message("third", fd, base, t.tid);
    printf("copy, don't wake: %s\n", err(copy(fd, base + 2 * PAGE, src, PAGE, UFFDIO_COPY_MODE_DONTWAKE, &done)));
    fdinfo("not woken", fd);
    printf("wake elsewhere: %s\n",
           err(ioctl(fd, UFFDIO_WAKE, &(struct uffdio_range){(uintptr_t)base + 3 * PAGE, PAGE})));
    fdinfo("still", fd);
    printf("wake: %s\n",
           err(ioctl(fd, UFFDIO_WAKE, &(struct uffdio_range){(uintptr_t)base + 2 * PAGE, PAGE})));
    pthread_join(thread, NULL);
    printf("seen: %c\n", t.seen);
    fdinfo("woken", fd);

    /* UFFDIO_UNREGISTER ends a wait, and the page is memory as any. */
    t = (struct toucher){base + 3 * PAGE, 0, 0, 0};
    pthread_create(&thread, NULL, touch, &t);
    wait_message(fd);
    message("fourth", fd, base, t.tid);
    printf("unregister: %s\n", err(unreg(fd, base + 3 * PAGE, PAGE)));
    pthread_join(thread, NULL);
    printf("seen: %d\n", t.seen);
    printf("read none: %s\n", err(read(fd, src, sizeof(struct uffd_msg))));
    close(fd);
    return 0;
}

static volatile int signalled;
static void on_signal(int sig) {
    (void)sig;
    signalled++;
}

/* A signal during the wait runs its handler, then the access faults
   again; closing the file ends the wait. */
static int case_signals(void) {
    int fd = ready(0, 0);
    char *base = anon(2 * PAGE);
    reg(fd, base, 2 * PAGE, UFFDIO_REGISTER_MODE_MISSING, NULL);
    struct sigaction sa = {0};
    sa.sa_handler = on_signal;
    sigaction(SIGUSR1, &sa, NULL);
    struct toucher t = {base, 0, 0, 0};
    pthread_t thread;
    pthread_create(&thread, NULL, touch, &t);
    message("first", fd, base, 0);
    while (!t.tid)
        usleep(1000);
    wait_blocked(t.tid);
    syscall(SYS_tgkill, getpid(), t.tid, SIGUSR1);
    message("again", fd, base, 0);
    printf("signalled: %d\n", signalled);
    char src[PAGE];
    memset(src, 's', sizeof src);
    int64_t done;
    printf("copy: %s\n", err(copy(fd, base, src, PAGE, 0, &done)));
    pthread_join(thread, NULL);
    printf("seen: %c\n", t.seen);

    t = (struct toucher){base + PAGE, 1, 0, 0};
    pthread_create(&thread, NULL, touch, &t);
    message("before closing", fd, base, 0);
    close(fd);
    pthread_join(thread, NULL);
    printf("after closing: %c\n", t.seen);
    vma("closed", base, base);
    return 0;
}

static char *bus_base;
static void on_bus(int sig, siginfo_t *info, void *context) {
    (void)context;
    printf("signal %d code %d at %ld\n", sig, info->si_code, (long)((char *)info->si_addr - bus_base));
    _exit(0);
}

/* UFFD_FEATURE_SIGBUS: the fault raises SIGBUS at the address itself. A
   forked child does not keep the registration. */
static int case_sigbus(void) {
    int fd = ready(0, UFFD_FEATURE_SIGBUS | UFFD_FEATURE_EXACT_ADDRESS);
    char *base = anon(PAGE);
    reg(fd, base, PAGE, UFFDIO_REGISTER_MODE_MISSING, NULL);
    fdinfo("sigbus", fd);
    pid_t child = fork();
    if (child == 0) {
        printf("child: %d\n", base[10]);
        vma("child's", base, base);
        _exit(0);
    }
    waitpid(child, NULL, 0);
    struct sigaction sa = {0};
    sa.sa_sigaction = on_bus;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGBUS, &sa, NULL);
    bus_base = base;
    (void)*(volatile char *)(base + 123);
    printf("no signal\n");
    return 1;
}

/* Shared anonymous memory: a page another mapping of it has is not
   missing. */
static int case_shared(void) {
    int fd = ready(O_NONBLOCK, 0);
    char *base = mmap(NULL, 2 * PAGE, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    pid_t child = fork();
    if (child == 0) {
        base[PAGE] = 'k';
        _exit(0);
    }
    waitpid(child, NULL, 0);
    uint64_t ioctls = 0;
    printf("register: %s", err(reg(fd, base, 2 * PAGE, UFFDIO_REGISTER_MODE_MISSING, &ioctls)));
    printf(" ioctls=%d\n", (ioctls & RANGE_IOCTLS) == RANGE_IOCTLS);
    vma("shared", base, base);
    printf("the child's page: %c\n", base[PAGE]);
    struct toucher t = {base + 9, 1, 0, 0};
    pthread_t thread;
    pthread_create(&thread, NULL, touch, &t);
    wait_message(fd);
    message("shared fault", fd, base, 0);
    char src[PAGE];
    memset(src, 'h', sizeof src);
    int64_t done;
    printf("copy over the child's: %s", err(copy(fd, base + PAGE, src, PAGE, 0, &done)));
    printf(" copy=%lld\n", (long long)done);
    printf("copy: %s", err(copy(fd, base, src, PAGE, 0, &done)));
    printf(" copy=%lld\n", (long long)done);
    pthread_join(thread, NULL);
    printf("seen: %c byte 10: %c\n", t.seen, base[10]);
    close(fd);
    return 0;
}

/* Waits for the fault of `t`'s thread, then prints its message. */
static void protected_fault(const char *what, int fd, void *base, struct toucher *t) {
    wait_message(fd);
    while (!t->tid)
        usleep(1000);
    message(what, fd, base, t->tid);
}

/* Write protection of private anonymous memory. */
static int case_wp(void) {
    int fd = ready(O_NONBLOCK, UFFD_FEATURE_PAGEFAULT_FLAG_WP | UFFD_FEATURE_THREAD_ID);
    char *base = anon(4 * PAGE);
    printf("minor: %s\n", err(reg(fd, base, PAGE, UFFDIO_REGISTER_MODE_MINOR, NULL)));
    printf("protect unregistered: %s\n", err(protect(fd, base, PAGE, UFFDIO_WRITEPROTECT_MODE_WP)));
    uint64_t ioctls = 0;
    /* Registered before the pages are touched, so that each is a page of
       its own (alloc_anon_folio gives a registered VMA no larger folio). */
    printf("register: %s", err(reg(fd, base, 3 * PAGE, UFFDIO_REGISTER_MODE_WP, &ioctls)));
    printf(" ioctls=%d writeprotect=%d\n", (ioctls & RANGE_IOCTLS) == RANGE_IOCTLS,
           (ioctls & WRITEPROTECT_IOCTL) != 0);
    vma("protected", base, base);
    vma("beside", base, base + 3 * PAGE);
    base[0] = 'a';
    base[PAGE] = 'b';
    /* A page read only shows the zero page, which is protected too; one
       never touched has nothing to protect. */
    printf("zero page: %d\n", base[2 * PAGE]);
    printf("bad mode: %s\n", err(protect(fd, base, PAGE, 4)));
    printf("protect, don't wake: %s\n",
           err(protect(fd, base, PAGE, UFFDIO_WRITEPROTECT_MODE_WP | UFFDIO_WRITEPROTECT_MODE_DONTWAKE)));
    printf("unaligned: %s\n", err(protect(fd, base + 1, PAGE, UFFDIO_WRITEPROTECT_MODE_WP)));
    printf("past the range: %s\n", err(protect(fd, base, 4 * PAGE, UFFDIO_WRITEPROTECT_MODE_WP)));
    printf("protect: %s\n", err(protect(fd, base, 3 * PAGE, UFFDIO_WRITEPROTECT_MODE_WP)));
    printf("read: %c\n", base[0]);

    /* A write faults with the WP flag, until the protection ends. */
    struct toucher t = {base + 5, 1, 0, 0};
    pthread_t thread;
    pthread_create(&thread, NULL, touch, &t);
    protected_fault("write fault", fd, base, &t);
    fdinfo("waiting", fd);
    printf("wake elsewhere: %s\n", err(protect(fd, base + PAGE, PAGE, 0)));
    fdinfo("still", fd);
    printf("unprotect: %s\n", err(protect(fd, base, PAGE, 0)));
    pthread_join(thread, NULL);
    printf("seen: %c byte 0: %c\n", t.seen, base[0]);

    /* DONTWAKE leaves it waiting until UFFDIO_WAKE. The zero page is
       protected as any. */
    t = (struct toucher){base + 2 * PAGE, 1, 0, 0};
    pthread_create(&thread, NULL, touch, &t);
    protected_fault("zero page fault", fd, base, &t);
    printf("unprotect, don't wake: %s\n", err(protect(fd, base + 2 * PAGE, PAGE, UFFDIO_WRITEPROTECT_MODE_DONTWAKE)));
    fdinfo("not woken", fd);
    printf("wake: %s\n",
           err(ioctl(fd, UFFDIO_WAKE, &(struct uffdio_range){(uintptr_t)base + 2 * PAGE, PAGE})));
    pthread_join(thread, NULL);
    printf("seen: %c\n", t.seen);

    /* mprotect keeps the protection: a write it refuses is SIGSEGV, and
       one it allows again faults to the userfaultfd. */
    printf("protect again: %s\n", err(protect(fd, base, PAGE, UFFDIO_WRITEPROTECT_MODE_WP)));
    mprotect(base, PAGE, PROT_READ);
    struct sigaction segv = {0};
    segv.sa_sigaction = on_segv;
    segv.sa_flags = SA_SIGINFO;
    sigaction(SIGSEGV, &segv, NULL);
    if (!sigsetjmp(refused, 1))
        base[0] = 'x';
    signal(SIGSEGV, SIG_DFL);
    mprotect(base, PAGE, PROT_READ | PROT_WRITE);
    vma("after mprotect", base, base);

    /* A child gets the pages without their protection. */
    pid_t child = fork();
    if (child == 0) {
        base[0] = 'c';
        base[PAGE] = 'c';
        printf("child: %c %c\n", base[0], base[PAGE]);
        _exit(0);
    }
    waitpid(child, NULL, 0);
    printf("parent's: %c %c\n", base[0], base[PAGE]);

    t = (struct toucher){base + PAGE - 1, 1, 0, 0};
    pthread_create(&thread, NULL, touch, &t);
    protected_fault("after fork", fd, base, &t);
    /* Unregistering takes the protection away, but does not end the wait
       of a range registered for write protection alone. */
    printf("unregister: %s\n", err(unreg(fd, base, PAGE)));
    vma("unregistered", base, base);
    fdinfo("after unregistering", fd);
    printf("wake: %s\n", err(ioctl(fd, UFFDIO_WAKE, &(struct uffdio_range){(uintptr_t)base, PAGE})));
    pthread_join(thread, NULL);
    printf("seen: %c\n", t.seen);
    printf("page 3 untouched, written: %c\n", (base[3 * PAGE] = 'u'));
    close(fd);

    /* UFFDIO_COPY_MODE_WP fills a missing page write-protected, which
       needs the write-protect mode. */
    fd = ready(O_NONBLOCK, 0);
    char *more = anon(2 * PAGE);
    char src[PAGE];
    memset(src, 'p', sizeof src);
    int64_t done;
    reg(fd, more, 2 * PAGE, UFFDIO_REGISTER_MODE_MISSING, NULL);
    printf("copy WP, missing only: %s", err(copy(fd, more, src, PAGE, UFFDIO_COPY_MODE_WP, &done)));
    printf(" copy=%lld\n", (long long)done);
    printf("register both: %s",
           err(reg(fd, more, 2 * PAGE, UFFDIO_REGISTER_MODE_MISSING | UFFDIO_REGISTER_MODE_WP, &ioctls)));
    printf(" writeprotect=%d\n", (ioctls & WRITEPROTECT_IOCTL) != 0);
    vma("both", more, more);
    t = (struct toucher){more + PAGE + 3, 1, 0, 0};
    pthread_create(&thread, NULL, touch, &t);
    protected_fault("missing", fd, more, &t);
    printf("copy WP: %s", err(copy(fd, more + PAGE, src, PAGE, UFFDIO_COPY_MODE_WP, &done)));
    printf(" copy=%lld\n", (long long)done);
    protected_fault("then protected", fd, more, &t);
    printf("unprotect: %s\n", err(protect(fd, more + PAGE, PAGE, 0)));
    pthread_join(thread, NULL);
    printf("seen: %c byte 4: %c\n", t.seen, more[PAGE + 4]);
    close(fd);
    printf("closed, written: %c\n", (more[PAGE] = 'z'));
    return 0;
}

static sigjmp_buf faulted;
static char *fault_base;
static void on_fault(int sig, siginfo_t *info, void *context) {
    (void)context;
    printf("  signal %d code %d at %ld", sig, info->si_code,
           (long)((char *)info->si_addr - fault_base));
    if (sig == SIGBUS)
        printf(" lsb %d", info->si_addr_lsb);
    printf("\n");
    siglongjmp(faulted, 1);
}

/* A read (or a write, with `write`) of `at`, and the signal it raises. */
static void access_at(const char *what, char *base, volatile char *at, int write) {
    printf("%s:\n", what);
    fault_base = base;
    if (sigsetjmp(faulted, 1) == 0) {
        char c = write ? (*at = 'w') : *at;
        printf("  no signal, byte %d\n", c);
    }
}

/* UFFDIO_POISON. */
static int case_poison(void) {
    struct sigaction sa = {0};
    sa.sa_sigaction = on_fault;
    sa.sa_flags = SA_SIGINFO | SA_NODEFER;
    sigaction(SIGBUS, &sa, NULL);
    sigaction(SIGSEGV, &sa, NULL);
    int fd = uffd(O_NONBLOCK);
    struct uffdio_api api = {UFFD_API, UFFD_FEATURE_POISON, 0};
    printf("api: %s", err(ioctl(fd, UFFDIO_API, &api)));
    printf(" poison=%d\n", (api.features & UFFD_FEATURE_POISON) != 0);
    char *base = anon(4 * PAGE);
    base[PAGE] = 'a';
    int64_t done;
    printf("not registered: %s", err(poison(fd, base, PAGE, 0, &done)));
    printf(" updated=%lld\n", (long long)done);
    uint64_t ioctls;
    printf("register: %s", err(reg(fd, base, 4 * PAGE, UFFDIO_REGISTER_MODE_MISSING, &ioctls)));
    printf(" poison=%d\n", (ioctls & POISON_IOCTL) != 0);
    printf("bad mode: %s\n", err(poison(fd, base, PAGE, 2, NULL)));
    printf("unaligned: %s\n", err(poison(fd, base + 1, PAGE, 0, NULL)));
    printf("empty: %s\n", err(poison(fd, base, 0, 0, NULL)));
    printf("up to a page: %s", err(poison(fd, base, 2 * PAGE, 0, &done)));
    printf(" updated=%lld\n", (long long)done);
    printf("again: %s", err(poison(fd, base, PAGE, 0, &done)));
    printf(" updated=%lld\n", (long long)done);
    /* A zero page does not replace the poison, and a copy does; a
       discard then empties the page for the steps below. */
    char src[PAGE];
    memset(src, 'c', sizeof src);
    printf("poison last: %s\n", err(poison(fd, base + 3 * PAGE, PAGE, 0, NULL)));
    printf("zeropage: %s\n", err(zeropage(fd, base + 3 * PAGE, PAGE, 0, NULL)));
    printf("copy: %s\n", err(copy(fd, base + 3 * PAGE, src, PAGE, 0, NULL)));
    access_at("copied", base, base + 3 * PAGE + 7, 0);
    printf("zeropage on it: %s\n", err(zeropage(fd, base + 3 * PAGE, PAGE, 0, NULL)));
    printf("copy on it: %s\n", err(copy(fd, base + 3 * PAGE, src, PAGE, 0, NULL)));
    printf("discard it: %s\n", err(madvise(base + 3 * PAGE, PAGE, MADV_DONTNEED)));
    printf("dontwake: %s", err(poison(fd, base + 2 * PAGE, PAGE, UFFDIO_POISON_MODE_DONTWAKE, &done)));
    printf(" updated=%lld\n", (long long)done);
    int pipes[2];
    pipe(pipes);
    printf("write from it: %s\n", err(write(pipes[1], base, 1)));
    long populated = madvise(base, PAGE, MADV_POPULATE_READ);
    printf("populate read: %ld errno=%d\n", populated, populated ? errno : 0);
    access_at("read", base, base + 5, 0);
    access_at("write", base, base + 2 * PAGE + 9, 1);
    access_at("filled page", base, base + PAGE, 0);
    mprotect(base, PAGE, PROT_READ);
    access_at("write refused", base, base, 1);
    mprotect(base, PAGE, PROT_NONE);
    access_at("read refused", base, base, 0);
    mprotect(base, PAGE, PROT_READ | PROT_WRITE);
    access_at("protection back", base, base, 0);
    fflush(stdout);
    pid_t child = fork();
    if (child == 0) {
        access_at("child", base, base, 0);
        _exit(0);
    }
    waitpid(child, NULL, 0);
    printf("unregister: %s\n", err(unreg(fd, base, 4 * PAGE)));
    access_at("unregistered", base, base, 0);
    /* The poison moves with mremap. */
    char *to = anon(2 * PAGE);
    char *moved = mremap(base, 2 * PAGE, 2 * PAGE, MREMAP_MAYMOVE | MREMAP_FIXED, to);
    printf("mremap: %d\n", moved == to);
    access_at("moved", moved, moved + 1, 0);
    access_at("moved, filled", moved, moved + PAGE, 0);
    printf("dontneed: %s\n", err(madvise(moved, PAGE, MADV_DONTNEED)));
    access_at("after dontneed", moved, moved, 0);
    access_at("before free", base, base + 2 * PAGE, 0);
    printf("free: %s\n", err(madvise(base + 2 * PAGE, PAGE, MADV_FREE)));
    access_at("after free", base, base + 2 * PAGE, 0);
    printf("register again: %s\n", err(reg(fd, base + 3 * PAGE, PAGE, UFFDIO_REGISTER_MODE_MISSING, NULL)));
    printf("poison: %s\n", err(poison(fd, base + 3 * PAGE, PAGE, 0, NULL)));
    /* A guard replaces the poison; removing it leaves an empty page, which
       takes poison again (a read would wait for the missing page). */
    printf("guard: %s\n", err(madvise(base + 3 * PAGE, PAGE, MADV_GUARD_INSTALL)));
    access_at("guarded", base, base + 3 * PAGE, 0);
    printf("unguard: %s\n", err(madvise(base + 3 * PAGE, PAGE, MADV_GUARD_REMOVE)));
    printf("poison again: %s\n", err(poison(fd, base + 3 * PAGE, PAGE, 0, NULL)));
    munmap(base + 3 * PAGE, PAGE);
    char *again = mmap(base + 3 * PAGE, PAGE, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    access_at("mapped again", base, again, 0);
    /* Shared memory: the poison is this mapping's, whatever the memory
       has, and a child's mapping does not get it. */
    char *shared = mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    fflush(stdout);
    child = fork();
    if (child == 0) {
        shared[0] = 's';
        _exit(0);
    }
    waitpid(child, NULL, 0);
    printf("register shared: %s\n", err(reg(fd, shared, PAGE, UFFDIO_REGISTER_MODE_MISSING, NULL)));
    printf("poison shared: %s", err(poison(fd, shared, PAGE, 0, &done)));
    printf(" updated=%lld\n", (long long)done);
    access_at("shared", shared, shared, 0);
    fflush(stdout);
    child = fork();
    if (child == 0) {
        access_at("shared, child", shared, shared, 0);
        _exit(0);
    }
    waitpid(child, NULL, 0);
    printf("dontneed shared: %s\n", err(madvise(shared, PAGE, MADV_DONTNEED)));
    access_at("shared after dontneed", shared, shared, 0);
    close(fd);
    return 0;
}

/* UFFDIO_MOVE: private anonymous pages move into a registered range that
   has none, page by page, and wake its faults. */
static int case_move(void) {
    int fd = uffd(O_NONBLOCK);
    struct uffdio_api api = {UFFD_API, UFFD_FEATURE_MOVE, 0};
    printf("api: %s", err(ioctl(fd, UFFDIO_API, &api)));
    printf(" move=%d\n", (api.features & UFFD_FEATURE_MOVE) != 0);
    char *dst = anon(6 * PAGE);
    char *src = anon(4 * PAGE);
    memset(src, 's', PAGE);
    memset(src + PAGE, 't', PAGE);
    int64_t done;
    printf("not registered: %s", err(move(fd, dst, src, PAGE, 0, &done)));
    printf(" move=%lld\n", (long long)done);
    uint64_t ioctls;
    printf("register: %s", err(reg(fd, dst, 6 * PAGE, UFFDIO_REGISTER_MODE_MISSING, &ioctls)));
    printf(" move=%d\n", (ioctls & MOVE_IOCTL) != 0);
    printf("bad mode: %s\n", err(move(fd, dst, src, PAGE, 4, NULL)));
    printf("unaligned: %s\n", err(move(fd, dst, src + 1, PAGE, 0, NULL)));
    printf("empty: %s\n", err(move(fd, dst, src, 0, 0, NULL)));
    printf("move: %s", err(move(fd, dst, src, PAGE, 0, &done)));
    printf(" move=%lld\n", (long long)done);
    printf("moved: %c %c, source %d\n", dst[0], dst[PAGE - 1], src[5]);
    printf("again: %s", err(move(fd, dst, src + PAGE, PAGE, 0, &done)));
    printf(" move=%lld\n", (long long)done);
    printf("hole: %s", err(move(fd, dst + PAGE, src + 2 * PAGE, PAGE, 0, &done)));
    printf(" move=%lld\n", (long long)done);
    printf("holes allowed: %s", err(move(fd, dst + PAGE, src + 2 * PAGE, PAGE,
                                         UFFDIO_MOVE_MODE_ALLOW_SRC_HOLES, &done)));
    printf(" move=%lld\n", (long long)done);
    printf("short: %s", err(move(fd, dst + PAGE, src + PAGE, 2 * PAGE, 0, &done)));
    printf(" move=%lld", (long long)done);
    printf(" byte=%c\n", dst[PAGE + 9]);

    /* A move into a missing page ends the fault that waits for it. */
    memset(src + 3 * PAGE, 'u', PAGE);
    struct toucher t = {dst + 2 * PAGE + 3, 0, 0, 0};
    pthread_t thread;
    pthread_create(&thread, NULL, touch, &t);
    wait_message(fd);
    message("fault", fd, dst, 0);
    printf("move it: %s\n", err(move(fd, dst + 2 * PAGE, src + 3 * PAGE, PAGE, 0, NULL)));
    pthread_join(thread, NULL);
    printf("seen: %c\n", t.seen);

    /* A page fork shares is EBUSY until a write gives it its own. */
    memset(src, 'v', PAGE);
    fflush(stdout);
    pid_t child = fork();
    if (child == 0)
        _exit(0);
    waitpid(child, NULL, 0);
    printf("shared by fork: %s\n", err(move(fd, dst + 3 * PAGE, src, PAGE, 0, NULL)));
    src[0] = 'w';
    printf("written: %s", err(move(fd, dst + 3 * PAGE, src, PAGE, 0, NULL)));
    printf(" byte=%c\n", dst[3 * PAGE]);

    /* The zero page moves as one. */
    volatile char zero = src[3 * PAGE];
    (void)zero;
    printf("zero page: %s", err(move(fd, dst + 4 * PAGE, src + 3 * PAGE, PAGE, 0, NULL)));
    printf(" byte=%d\n", dst[4 * PAGE]);
    dst[4 * PAGE] = 'z';

    /* The VMAs: the same protection, neither shared, both mapped. */
    memset(src + PAGE, 'x', PAGE);
    mprotect(src + PAGE, PAGE, PROT_READ);
    printf("read-only source: %s\n", err(move(fd, dst + 5 * PAGE, src + PAGE, PAGE, 0, NULL)));
    mprotect(src + PAGE, PAGE, PROT_READ | PROT_WRITE);
    char *shared = mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    shared[0] = 'h';
    printf("shared source: %s\n", err(move(fd, dst + 5 * PAGE, shared, PAGE, 0, NULL)));
    char *gone = mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    munmap(gone, PAGE);
    printf("unmapped source: %s\n", err(move(fd, dst + 5 * PAGE, gone, PAGE, 0, NULL)));
    printf("past the source: %s\n", err(move(fd, dst + 4 * PAGE, src + 3 * PAGE, 2 * PAGE, 0, NULL)));

    /* A guard at the source is EFAULT, at the destination EEXIST. */
    printf("guard source: %s\n", err(madvise(src + 2 * PAGE, PAGE, MADV_GUARD_INSTALL)));
    printf("from a guard: %s\n", err(move(fd, dst + 5 * PAGE, src + 2 * PAGE, PAGE,
                                          UFFDIO_MOVE_MODE_ALLOW_SRC_HOLES, NULL)));
    printf("guard destination: %s\n", err(madvise(dst + 5 * PAGE, PAGE, MADV_GUARD_INSTALL)));
    printf("onto a guard: %s\n", err(move(fd, dst + 5 * PAGE, src + PAGE, PAGE, 0, NULL)));
    printf("unregister: %s\n", err(unreg(fd, dst, 6 * PAGE)));
    printf("unregistered: %s\n", err(move(fd, dst + 5 * PAGE, src + PAGE, PAGE, 0, NULL)));
    close(fd);
    return 0;
}

/* A memfd of `pages` pages whose page 1 is written. */
static int shmem_file(int pages) {
    int file = syscall(SYS_memfd_create, "uffd", 0);
    ftruncate(file, pages * PAGE);
    pwrite(file, "b", 1, PAGE);
    return file;
}

/* A shmem file's mappings, shared and private: a hole waits, a page the
   file has does not, a shared fill goes to the file and a private one does
   not, the end of the file, and what cannot be registered. */
static int case_shmem(void) {
    struct sigaction sa = {0};
    sa.sa_sigaction = on_fault;
    sa.sa_flags = SA_SIGINFO | SA_NODEFER;
    sigaction(SIGBUS, &sa, NULL);
    int fd = ready(O_NONBLOCK, 0);
    char src[PAGE];
    memset(src, 'c', sizeof src);
    int64_t done;

    /* Shared: five pages over a file of four. */
    int file = shmem_file(4);
    char *shared = mmap(NULL, 5 * PAGE, PROT_READ | PROT_WRITE, MAP_SHARED, file, 0);
    uint64_t ioctls = 0;
    printf("register shared: %s", err(reg(fd, shared, 5 * PAGE, UFFDIO_REGISTER_MODE_MISSING, &ioctls)));
    printf(" ioctls=%d\n", (ioctls & RANGE_IOCTLS) == RANGE_IOCTLS);
    vma("shared", shared, shared);
    access_at("the file's page", shared, shared + PAGE, 0);
    struct toucher t = {shared + 9, 0, 0, 0};
    pthread_t thread;
    pthread_create(&thread, NULL, touch, &t);
    wait_message(fd);
    message("hole", fd, shared, 0);
    printf("copy: %s\n", err(copy(fd, shared, src, PAGE, 0, NULL)));
    pthread_join(thread, NULL);
    printf("seen: %c\n", t.seen);
    char byte = 0;
    pread(file, &byte, 1, 9);
    printf("the file has: %c\n", byte);
    printf("copy over the file's: %s", err(copy(fd, shared + PAGE, src, PAGE, 0, &done)));
    printf(" copy=%lld\n", (long long)done);
    printf("zeropage: %s\n", err(zeropage(fd, shared + 2 * PAGE, PAGE, 0, NULL)));
    struct stat st;
    fstat(file, &st);
    printf("blocks: %lld\n", (long long)st.st_blocks);
    printf("past the end: %s", err(copy(fd, shared + 4 * PAGE, src, PAGE, 0, &done)));
    printf(" copy=%lld\n", (long long)done);
    printf("zeropage past the end: %s\n", err(zeropage(fd, shared + 4 * PAGE, PAGE, 0, NULL)));
    access_at("past the end", shared, shared + 4 * PAGE, 0);
    pwrite(file, "d", 1, 3 * PAGE + 1);
    access_at("written later", shared, shared + 3 * PAGE + 1, 0);
    printf("unregister: %s\n", err(unreg(fd, shared, 5 * PAGE)));
    munmap(shared, 5 * PAGE);

    /* Private: a fill is the mapping's own; the file keeps its hole. */
    int other = shmem_file(3);
    char *private = mmap(NULL, 3 * PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE, other, 0);
    printf("register private: %s\n", err(reg(fd, private, 3 * PAGE, UFFDIO_REGISTER_MODE_MISSING, NULL)));
    vma("private", private, private);
    access_at("the file's private page", private, private + PAGE, 0);
    printf("copy over it: %s\n", err(copy(fd, private + PAGE, src, PAGE, 0, NULL)));
    t = (struct toucher){private + 2 * PAGE + 4, 1, 0, 0};
    pthread_create(&thread, NULL, touch, &t);
    wait_message(fd);
    message("private hole", fd, private, 0);
    printf("copy: %s\n", err(copy(fd, private + 2 * PAGE, src, PAGE, 0, NULL)));
    pthread_join(thread, NULL);
    printf("seen: %c\n", t.seen);
    byte = 'x';
    pread(other, &byte, 1, 2 * PAGE + 4);
    printf("the file has: %d\n", byte);
    printf("zeropage: %s\n", err(zeropage(fd, private, PAGE, 0, NULL)));
    access_at("zero", private, private + 5, 0);
    munmap(private, 3 * PAGE);

    /* What cannot be registered: a mapping that may not write the file,
       and System V shared memory. */
    char path[64];
    snprintf(path, sizeof path, "/proc/self/fd/%d", other);
    int reader = open(path, O_RDONLY);
    char *read_only = mmap(NULL, PAGE, PROT_READ, MAP_SHARED, reader, 0);
    printf("register read-only: %s\n", err(reg(fd, read_only, PAGE, UFFDIO_REGISTER_MODE_MISSING, NULL)));
    int id = shmget(IPC_PRIVATE, PAGE, IPC_CREAT | 0600);
    char *segment = shmat(id, NULL, 0);
    printf("register System V: %s\n", err(reg(fd, segment, PAGE, UFFDIO_REGISTER_MODE_MISSING, NULL)));
    shmdt(segment);
    shmctl(id, IPC_RMID, NULL);
    close(fd);
    return 0;
}

static long resume(int fd, void *at, size_t len, uint64_t mode, int64_t *done) {
    struct uffdio_continue c = {{(uintptr_t)at, len}, mode, 0x5a5a};
    long ret = ioctl(fd, UFFDIO_CONTINUE, &c);
    if (done)
        *done = c.mapped;
    return ret;
}

/* The minor mode: a page shmem's page cache has, which the registered
   mapping has not mapped, waits until UFFDIO_CONTINUE maps it; another
   mapping of the memfd fills the page cache. */
static int case_minor(void) {
    int fd = uffd(O_NONBLOCK);
    struct uffdio_api api = {UFFD_API, UFFD_FEATURE_MINOR_SHMEM, 0};
    printf("api: %s", err(ioctl(fd, UFFDIO_API, &api)));
    printf(" minor=%d\n", (api.features & UFFD_FEATURE_MINOR_SHMEM) != 0);
    char *private_anon = anon(PAGE);
    printf("private anonymous: %s\n",
           err(reg(fd, private_anon, PAGE, UFFDIO_REGISTER_MODE_MINOR, NULL)));
    int file = shmem_file(3);
    char *writer = mmap(NULL, 3 * PAGE, PROT_READ | PROT_WRITE, MAP_SHARED, file, 0);
    char *view = mmap(NULL, 4 * PAGE, PROT_READ | PROT_WRITE, MAP_SHARED, file, 0);
    uint64_t ioctls = 0;
    printf("register: %s", err(reg(fd, view, 4 * PAGE, UFFDIO_REGISTER_MODE_MINOR, &ioctls)));
    printf(" continue=%d\n", (ioctls & CONTINUE_IOCTL) != 0);
    vma("minor", view, view);

    /* A page the file has waits. */
    struct toucher t = {view + PAGE + 5, 0, 0, 0};
    pthread_t thread;
    pthread_create(&thread, NULL, touch, &t);
    wait_message(fd);
    message("minor fault", fd, view, 0);
    writer[PAGE + 5] = 'n';
    int64_t done;
    printf("bad mode: %s\n", err(resume(fd, view + PAGE, PAGE, 4, NULL)));
    printf("write-protecting: %s\n", err(resume(fd, view + PAGE, PAGE, UFFDIO_CONTINUE_MODE_WP, NULL)));
    printf("continue: %s", err(resume(fd, view + PAGE, PAGE, 0, &done)));
    printf(" mapped=%lld\n", (long long)done);
    pthread_join(thread, NULL);
    printf("seen: %c\n", t.seen);
    printf("again: %s", err(resume(fd, view + PAGE, PAGE, 0, &done)));
    printf(" mapped=%lld\n", (long long)done);
    /* A hole is brought in; then the other mapping sees it. */
    printf("hole: %d\n", view[7]);
    view[8] = 'h';
    printf("shared: %c\n", writer[8]);
    printf("continue a hole: %s", err(resume(fd, view + 2 * PAGE, PAGE, 0, &done)));
    printf(" mapped=%lld\n", (long long)done);
    printf("past the end: %s", err(resume(fd, view + 3 * PAGE, PAGE, 0, &done)));
    printf(" mapped=%lld\n", (long long)done);
    writer[2 * PAGE] = 'q';
    printf("continue, don't wake: %s\n",
           err(resume(fd, view + 2 * PAGE, PAGE, UFFDIO_CONTINUE_MODE_DONTWAKE, NULL)));
    printf("mapped: %c\n", view[2 * PAGE]);
    printf("unregister: %s\n", err(unreg(fd, view, 4 * PAGE)));

    /* A private mapping shows the page cache's page until it writes. */
    char *private = mmap(NULL, 3 * PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE, file, 0);
    printf("register private: %s\n",
           err(reg(fd, private, 3 * PAGE, UFFDIO_REGISTER_MODE_MISSING | UFFDIO_REGISTER_MODE_MINOR, NULL)));
    t = (struct toucher){private + PAGE + 5, 1, 0, 0};
    pthread_create(&thread, NULL, touch, &t);
    wait_message(fd);
    message("private minor fault", fd, private, 0);
    printf("continue: %s\n", err(resume(fd, private + PAGE, PAGE, 0, NULL)));
    pthread_join(thread, NULL);
    printf("seen: %c, the file has: %c\n", t.seen, writer[PAGE + 5]);
    close(fd);
    return 0;
}

/* Whether the page at `at` is present, a swap entry and write-protected,
   as /proc/self/pagemap has it (bits 63, 62 and 57). */
static void pagemap_show(const char *what, void *at) {
    int f = open("/proc/self/pagemap", O_RDONLY);
    uint64_t e = 0;
    pread(f, &e, sizeof e, (off_t)((uintptr_t)at / PAGE * sizeof e));
    close(f);
    printf("%s: present=%d swap=%d wp=%d\n", what, (int)(e >> 63 & 1), (int)(e >> 62 & 1),
           (int)(e >> 57 & 1));
}

/* A write to `at` by a thread of its own, which faults to `fd`: the
   message, then the end of the protection of its page, and what the
   thread wrote. */
static void write_fault(const char *what, int fd, char *base, char *at) {
    struct toucher t = {at, 1, 0, 0};
    pthread_t thread;
    pthread_create(&thread, NULL, touch, &t);
    protected_fault(what, fd, base, &t);
    pagemap_show(what, (void *)((uintptr_t)at & ~(uintptr_t)(PAGE - 1)));
    printf("unprotect: %s\n",
           err(protect(fd, (void *)((uintptr_t)at & ~(uintptr_t)(PAGE - 1)), PAGE, 0)));
    pthread_join(thread, NULL);
    printf("seen: %c\n", t.seen);
}

/* Write protection of shmem, whose pages that have no entry get markers,
   and of private anonymous memory's with WP_UNPOPULATED. */
static int case_wp_shmem(void) {
    int fd = uffd(O_NONBLOCK);
    struct uffdio_api api = {UFFD_API, UFFD_FEATURE_PAGEFAULT_FLAG_WP | UFFD_FEATURE_THREAD_ID, 0};
    printf("api: %s", err(ioctl(fd, UFFDIO_API, &api)));
    printf(" shmem=%d unpopulated=%d\n", (api.features & UFFD_FEATURE_WP_HUGETLBFS_SHMEM) != 0,
           (api.features & UFFD_FEATURE_WP_UNPOPULATED) != 0);
    int file = shmem_file(4);
    char *view = mmap(NULL, 4 * PAGE, PROT_READ | PROT_WRITE, MAP_SHARED, file, 0);
    char *other = mmap(NULL, 4 * PAGE, PROT_READ | PROT_WRITE, MAP_SHARED, file, 0);
    uint64_t ioctls = 0;
    printf("register: %s", err(reg(fd, view, 4 * PAGE, UFFDIO_REGISTER_MODE_WP, &ioctls)));
    printf(" writeprotect=%d\n", (ioctls & WRITEPROTECT_IOCTL) != 0);
    vma("shmem", view, view);
    view[0] = 'a';
    printf("protect: %s\n", err(protect(fd, view, 4 * PAGE, UFFDIO_WRITEPROTECT_MODE_WP)));
    pagemap_show("an entry", view);
    pagemap_show("the file's page", view + PAGE);
    pagemap_show("a hole", view + 2 * PAGE);
    /* A read of a page with a marker is no fault; its entry is protected. */
    printf("read: %c\n", view[PAGE]);
    pagemap_show("read", view + PAGE);
    write_fault("the file's page", fd, view, view + PAGE + 1);
    /* A hole's page is brought in, protected, before the write faults. */
    write_fault("a hole", fd, view, view + 2 * PAGE + 2);
    /* Another mapping of the file is not protected. */
    other[3 * PAGE] = 'o';
    pagemap_show("the other mapping's page", view + 3 * PAGE);
    /* MADV_DONTNEED keeps the protection of shmem's pages. */
    printf("dontneed: %s\n", err(madvise(view, 4 * PAGE, MADV_DONTNEED)));
    pagemap_show("after dontneed", view);
    pagemap_show("unprotected after dontneed", view + PAGE);
    printf("read after dontneed: %c\n", view[0]);
    write_fault("after dontneed", fd, view, view);
    /* A fill over a marker: a hole's copy replaces it; a page the page
       cache has is EEXIST, as is a poison. */
    printf("protect again: %s\n", err(protect(fd, view, 4 * PAGE, UFFDIO_WRITEPROTECT_MODE_WP)));
    printf("dontneed: %s\n", err(madvise(view, 4 * PAGE, MADV_DONTNEED)));
    char src[PAGE];
    memset(src, 'c', sizeof src);
    int64_t done;
    printf("copy over the page cache's: %s", err(copy(fd, view + PAGE, src, PAGE, 0, &done)));
    printf(" copy=%lld\n", (long long)done);
    printf("poison: %s\n", err(poison(fd, view + PAGE, PAGE, 0, NULL)));
    printf("unprotect: %s\n", err(protect(fd, view, 4 * PAGE, 0)));
    pagemap_show("unprotected", view + PAGE);
    printf("written: %c\n", (view[PAGE] = 'u'));
    /* The minor mode with write protection: UFFDIO_CONTINUE_MODE_WP maps
       the page protected. */
    printf("register minor: %s\n",
           err(reg(fd, view, 4 * PAGE, UFFDIO_REGISTER_MODE_MINOR | UFFDIO_REGISTER_MODE_WP, NULL)));
    printf("dontneed: %s\n", err(madvise(view, 4 * PAGE, MADV_DONTNEED)));
    struct toucher t = {view + PAGE + 5, 0, 0, 0};
    pthread_t thread;
    pthread_create(&thread, NULL, touch, &t);
    protected_fault("minor fault", fd, view, &t);
    printf("continue WP: %s", err(resume(fd, view + PAGE, PAGE, UFFDIO_CONTINUE_MODE_WP, &done)));
    printf(" mapped=%lld\n", (long long)done);
    pthread_join(thread, NULL);
    printf("seen: %d\n", t.seen);
    pagemap_show("continued", view + PAGE);
    write_fault("continued", fd, view, view + PAGE + 6);
    close(fd);
    pagemap_show("closed", view + 2 * PAGE);

    /* Private anonymous memory: with WP_UNPOPULATED its pages that have
       none are protected too. */
    fd = ready(O_NONBLOCK, UFFD_FEATURE_PAGEFAULT_FLAG_WP | UFFD_FEATURE_THREAD_ID |
                               UFFD_FEATURE_WP_UNPOPULATED);
    char *a = anon(3 * PAGE);
    printf("register anonymous: %s\n", err(reg(fd, a, 3 * PAGE, UFFDIO_REGISTER_MODE_WP, NULL)));
    printf("protect: %s\n", err(protect(fd, a, 3 * PAGE, UFFDIO_WRITEPROTECT_MODE_WP)));
    pagemap_show("unpopulated", a);
    printf("read: %d\n", a[0]);
    pagemap_show("read", a);
    write_fault("unpopulated", fd, a, a + PAGE + 3);
    printf("zeropage: %s\n", err(zeropage(fd, a + 2 * PAGE, PAGE, 0, NULL)));
    printf("copy: %s\n", err(copy(fd, a + 2 * PAGE, src, PAGE, 0, NULL)));
    pagemap_show("copied", a + 2 * PAGE);
    printf("written: %c\n", (a[2 * PAGE + 1] = 'v'));
    /* MADV_DONTNEED of anonymous memory drops the protection. */
    printf("protect again: %s\n", err(protect(fd, a, 3 * PAGE, UFFDIO_WRITEPROTECT_MODE_WP)));
    printf("dontneed: %s\n", err(madvise(a + PAGE, 2 * PAGE, MADV_DONTNEED)));
    pagemap_show("after dontneed", a + PAGE);
    printf("written: %c\n", (a[PAGE] = 'd'));
    /* A child has no markers; an mremap takes them away. */
    printf("protect again: %s\n", err(protect(fd, a, 3 * PAGE, UFFDIO_WRITEPROTECT_MODE_WP)));
    fflush(stdout);
    pid_t child = fork();
    if (child == 0) {
        pagemap_show("child", a + 2 * PAGE);
        printf("child wrote: %c\n", (a[2 * PAGE] = 'k'));
        _exit(0);
    }
    waitpid(child, NULL, 0);
    pagemap_show("parent", a + 2 * PAGE);
    char *to = anon(3 * PAGE);
    char *moved = mremap(a, 3 * PAGE, 3 * PAGE, MREMAP_MAYMOVE | MREMAP_FIXED, to);
    printf("moved: %d\n", moved == to);
    pagemap_show("moved", to + 2 * PAGE);
    printf("written: %c\n", (to[2 * PAGE] = 'm'));
    close(fd);
    return 0;
}

/* Only the uffd-wp bit of the page at `at` in /proc/self/pagemap: a
   private file page MADV_DONTNEED dropped is read again at once here,
   where Linux has no entry until an access. */
static void wp_show(const char *what, void *at) {
    int f = open("/proc/self/pagemap", O_RDONLY);
    uint64_t e = 0;
    pread(f, &e, sizeof e, (off_t)((uintptr_t)at / PAGE * sizeof e));
    close(f);
    printf("%s: wp=%d\n", what, (int)(e >> 57 & 1));
}

/* WP_ASYNC: a write to a protected page clears its protection and goes
   on, of any memory registered for write protection alone. */
static int case_wp_async(void) {
    int sync = ready(O_NONBLOCK, UFFD_FEATURE_PAGEFAULT_FLAG_WP);
    int fd = uffd(O_NONBLOCK);
    struct uffdio_api api = {UFFD_API, UFFD_FEATURE_WP_ASYNC, 0};
    printf("api: %s", err(ioctl(fd, UFFDIO_API, &api)));
    printf(" async=%d\n", (api.features & UFFD_FEATURE_WP_ASYNC) != 0);
    fdinfo("async", fd);
    /* Private anonymous memory, whose pages with no entry get markers. */
    char *a = anon(3 * PAGE);
    a[0] = 'a';
    printf("register: %s\n", err(reg(fd, a, 3 * PAGE, UFFDIO_REGISTER_MODE_WP, NULL)));
    printf("protect: %s\n", err(protect(fd, a, 3 * PAGE, UFFDIO_WRITEPROTECT_MODE_WP)));
    pagemap_show("an entry", a);
    pagemap_show("unpopulated", a + PAGE);
    a[0] = 'b';
    a[PAGE] = 'c';
    pagemap_show("written", a);
    pagemap_show("written unpopulated", a + PAGE);
    pagemap_show("untouched", a + 2 * PAGE);
    printf("read: %c%c\n", a[0], a[PAGE]);
    struct pollfd waiting = {fd, POLLIN, 0};
    printf("poll: %d\n", poll(&waiting, 1, 0));
    /* A system call's write goes on too. */
    printf("protect again: %s\n", err(protect(fd, a, 3 * PAGE, UFFDIO_WRITEPROTECT_MODE_WP)));
    int p[2];
    pipe(p);
    write(p[1], "s", 1);
    printf("read(2): %s\n", err(read(p[0], a + 2 * PAGE, 1)));
    pagemap_show("read(2)", a + 2 * PAGE);
    pagemap_show("still protected", a);
    printf("dontneed: %s\n", err(madvise(a, 3 * PAGE, MADV_DONTNEED)));
    pagemap_show("after dontneed", a);
    /* The missing mode with it takes private anonymous memory only. */
    char *b = anon(PAGE);
    printf("register missing: %s\n",
           err(reg(fd, b, PAGE, UFFDIO_REGISTER_MODE_MISSING | UFFDIO_REGISTER_MODE_WP, NULL)));
    printf("unregister: %s\n", err(unreg(fd, b, PAGE)));

    /* A file's private mapping, which only WP_ASYNC registers. */
    char path[] = "/tmp/uffd-async-XXXXXX";
    int file = mkstemp(path);
    int readonly = open(path, O_RDONLY);
    unlink(path);
    char bytes[PAGE];
    memset(bytes, 'f', sizeof bytes);
    for (int i = 0; i < 3; i++)
        write(file, bytes, sizeof bytes);
    char *f = mmap(NULL, 3 * PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE, file, 0);
    printf("register file without async: %s\n",
           err(reg(sync, f, 3 * PAGE, UFFDIO_REGISTER_MODE_WP, NULL)));
    printf("register file with missing: %s\n",
           err(reg(fd, f, 3 * PAGE, UFFDIO_REGISTER_MODE_MISSING | UFFDIO_REGISTER_MODE_WP, NULL)));
    uint64_t ioctls = 0;
    printf("register file: %s", err(reg(fd, f, 3 * PAGE, UFFDIO_REGISTER_MODE_WP, &ioctls)));
    printf(" writeprotect=%d\n", (ioctls & WRITEPROTECT_IOCTL) != 0);
    vma("private file", f, f);
    printf("read: %c\n", f[0]);
    printf("protect: %s\n", err(protect(fd, f, 3 * PAGE, UFFDIO_WRITEPROTECT_MODE_WP)));
    pagemap_show("private read", f);
    pagemap_show("private unread", f + PAGE);
    f[0] = 'g';
    f[PAGE] = 'h';
    pagemap_show("private written", f);
    pagemap_show("private written unread", f + PAGE);
    pagemap_show("private untouched", f + 2 * PAGE);
    char c = 0;
    pread(file, &c, 1, 0);
    printf("file: %c\n", c);
    int64_t done = 0;
    printf("copy: %s\n", err(copy(fd, f + 2 * PAGE, bytes, PAGE, 0, &done)));
    /* MADV_DONTNEED drops the copies, and keeps the protection of the
       pages that still had it. */
    printf("dontneed: %s\n", err(madvise(f, 3 * PAGE, MADV_DONTNEED)));
    wp_show("after dontneed", f);
    wp_show("written after dontneed", f + PAGE);
    wp_show("protected after dontneed", f + 2 * PAGE);
    printf("read after dontneed: %c%c%c\n", f[0], f[PAGE], f[2 * PAGE]);
    wp_show("read after dontneed", f + 2 * PAGE);
    f[2 * PAGE] = 'i';
    wp_show("written after dontneed", f + 2 * PAGE);
    printf("unregister: %s\n", err(unreg(fd, f, 3 * PAGE)));

    /* A file's shared mapping: the write reaches the file. */
    char *s = mmap(NULL, 2 * PAGE, PROT_READ | PROT_WRITE, MAP_SHARED, file, 0);
    printf("register shared file: %s\n", err(reg(fd, s, 2 * PAGE, UFFDIO_REGISTER_MODE_WP, NULL)));
    printf("protect: %s\n", err(protect(fd, s, 2 * PAGE, UFFDIO_WRITEPROTECT_MODE_WP)));
    pagemap_show("shared unread", s + PAGE);
    s[PAGE] = 'k';
    pagemap_show("shared written", s + PAGE);
    pread(file, &c, 1, PAGE);
    printf("file: %c\n", c);
    /* One that may not write the file still cannot be registered. */
    char *r = mmap(NULL, PAGE, PROT_READ, MAP_SHARED, readonly, 0);
    printf("register read-only: %s\n", err(reg(fd, r, PAGE, UFFDIO_REGISTER_MODE_WP, NULL)));

    /* System V shared memory. */
    int id = shmget(IPC_PRIVATE, PAGE, IPC_CREAT | 0600);
    char *segment = shmat(id, NULL, 0);
    shmctl(id, IPC_RMID, NULL);
    printf("register sysv: %s\n", err(reg(fd, segment, PAGE, UFFDIO_REGISTER_MODE_WP, NULL)));
    printf("protect: %s\n", err(protect(fd, segment, PAGE, UFFDIO_WRITEPROTECT_MODE_WP)));
    pagemap_show("sysv", segment);
    segment[0] = 'v';
    pagemap_show("sysv written", segment);
    printf("poll: %d\n", poll(&waiting, 1, 0));
    close(fd);
    close(sync);
    return 0;
}

/* A thread that reads `want` messages of `fd`, which blocks. */
struct events {
    int fd, want;
    struct uffd_msg msg[4];
    pthread_t thread;
};

static void *read_events(void *arg) {
    struct events *e = arg;
    for (int i = 0; i < e->want; i++) {
        if (read(e->fd, &e->msg[i], sizeof e->msg[i]) != sizeof e->msg[i]) {
            printf("read: %s\n", strerror(errno));
            e->want = i;
            break;
        }
    }
    return NULL;
}

static void expect(struct events *e, int fd, int want) {
    e->fd = fd;
    e->want = want;
    memset(e->msg, 0, sizeof e->msg);
    pthread_create(&e->thread, NULL, read_events, e);
}

/* The messages the thread read: their events, and their ranges as
   offsets from `base`. */
static void seen(const char *what, struct events *e, char *base) {
    pthread_join(e->thread, NULL);
    for (int i = 0; i < e->want; i++) {
        struct uffd_msg *m = &e->msg[i];
        long from = (long)(m->flags - (uintptr_t)base);
        long to = (long)(m->address - (uintptr_t)base);
        switch (m->event) {
        case UFFD_EVENT_REMAP:
            printf("%s: remap %ld -> %ld len %llu\n", what, from, to,
                   (unsigned long long)m->ptid | (unsigned long long)m->pad << 32);
            break;
        case UFFD_EVENT_REMOVE:
        case UFFD_EVENT_UNMAP:
            printf("%s: %s [%ld, %ld) rest=%u\n", what,
                   m->event == UFFD_EVENT_REMOVE ? "remove" : "unmap", from, to, m->ptid);
            break;
        case UFFD_EVENT_FORK:
            printf("%s: fork ufd>2=%d rest=%llu\n", what, (int)(uint32_t)m->flags > 2,
                   (unsigned long long)(m->flags >> 32) | (unsigned long long)m->address);
            break;
        default:
            printf("%s: event %#x\n", what, m->event);
        }
    }
}

static void *unmap_page(void *at) {
    munmap(at, PAGE);
    return NULL;
}

static int case_events(void) {
    uint64_t all = UFFD_FEATURE_EVENT_FORK | UFFD_FEATURE_EVENT_REMAP | UFFD_FEATURE_EVENT_REMOVE |
                   UFFD_FEATURE_EVENT_UNMAP;
    struct uffdio_api api = {UFFD_API, all, 0};
    int fd = uffd(0);
    printf("api: %s", err(ioctl(fd, UFFDIO_API, &api)));
    printf(" events=%d\n", (api.features & all) == all);
    char *base = anon(8 * PAGE);
    printf("register: %s\n", err(reg(fd, base, 4 * PAGE, UFFDIO_REGISTER_MODE_MISSING, NULL)));
    struct events e;
    /* A discard tells of each range it drops, before it does. */
    expect(&e, fd, 1);
    printf("dontneed: %s\n", err(madvise(base + PAGE, 2 * PAGE, MADV_DONTNEED)));
    seen("dontneed", &e, base);
    /* A move keeps the registration: the move, then the range it left. */
    expect(&e, fd, 2);
    void *moved = mremap(base, 2 * PAGE, 2 * PAGE, MREMAP_MAYMOVE | MREMAP_FIXED, base + 6 * PAGE);
    printf("mremap: %ld\n", moved == MAP_FAILED ? -1L : (long)((char *)moved - base));
    seen("mremap", &e, base);
    vma("moved", base, base + 6 * PAGE);
    /* munmap and a fixed mapping over registered memory unmap it. */
    expect(&e, fd, 1);
    printf("munmap: %s\n", err(munmap(base + 2 * PAGE, 4 * PAGE)));
    seen("munmap", &e, base);
    expect(&e, fd, 1);
    void *over = mmap(base + 6 * PAGE, PAGE, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    printf("mmap fixed: %ld\n", over == MAP_FAILED ? -1L : (long)((char *)over - base));
    seen("mmap", &e, base);
    /* fork waits for its event, whose file is the child's context: the
       child's fault on its registered page reaches it. */
    expect(&e, fd, 1);
    fflush(stdout);
    pid_t child = fork();
    if (child == 0) {
        printf("child read: %c\n", base[7 * PAGE]);
        _exit(0);
    }
    seen("fork", &e, base);
    int ufd = (int)(uint32_t)e.msg[0].flags;
    struct uffd_msg msg;
    printf("child fault: %s", err(read(ufd, &msg, sizeof msg)));
    printf(" event=%#x at=%ld\n", msg.event, (long)(msg.address - (uintptr_t)base));
    char page[PAGE];
    memset(page, 'c', PAGE);
    printf("child copy: %s\n", err(copy(ufd, base + 7 * PAGE, page, PAGE, 0, NULL)));
    int status;
    waitpid(child, &status, 0);
    printf("child: %d\n", WEXITSTATUS(status));
    char path[64], link[64] = {0};
    snprintf(path, sizeof path, "/proc/self/fd/%d", ufd);
    readlink(path, link, sizeof link - 1);
    printf("handed over: %s cloexec=%d\n", link, (fcntl(ufd, F_GETFD) & FD_CLOEXEC) != 0);
    close(ufd);
    /* A context without the features is told nothing. */
    int quiet = ready(O_NONBLOCK, 0);
    char *other = anon(2 * PAGE);
    printf("register quiet: %s\n", err(reg(quiet, other, 2 * PAGE, UFFDIO_REGISTER_MODE_MISSING, NULL)));
    printf("munmap quiet: %s\n", err(munmap(other, PAGE)));
    printf("read quiet: %s\n", err(read(quiet, &msg, sizeof msg)));
    /* While an unmap waits for its event, the fills are EAGAIN. */
    int waiting = ready(O_NONBLOCK, UFFD_FEATURE_EVENT_UNMAP);
    char *area = anon(2 * PAGE);
    printf("register waiting: %s\n", err(reg(waiting, area, 2 * PAGE, UFFDIO_REGISTER_MODE_MISSING, NULL)));
    pthread_t unmapper;
    pthread_create(&unmapper, NULL, unmap_page, area);
    struct pollfd p = {waiting, POLLIN, 0};
    int polled = poll(&p, 1, 5000);
    printf("poll: %d %#x\n", polled, p.revents);
    int64_t done = 0;
    printf("zeropage: %s", err(zeropage(waiting, area + PAGE, PAGE, 0, &done)));
    printf(" %lld\n", (long long)done);
    printf("copy: %s", err(copy(waiting, area + PAGE, page, PAGE, 0, &done)));
    printf(" %lld\n", (long long)done);
    printf("writeprotect: %s\n", err(protect(waiting, area + PAGE, PAGE, 0)));
    printf("read: %s", err(read(waiting, &msg, sizeof msg)));
    printf(" event=%#x [%ld, %ld)\n", msg.event, (long)(msg.flags - (uintptr_t)area),
           (long)(msg.address - (uintptr_t)area));
    pthread_join(unmapper, NULL);
    printf("zeropage after: %s\n", err(zeropage(waiting, area + PAGE, PAGE, 0, NULL)));
    return 0;
}

int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "";
    setvbuf(stdout, NULL, _IOLBF, 0);
    alarm(20);
    if (!strcmp(mode, "userfaultfd-calls")) return case_calls();
    if (!strcmp(mode, "userfaultfd-faults")) return case_faults();
    if (!strcmp(mode, "userfaultfd-signals")) return case_signals();
    if (!strcmp(mode, "userfaultfd-sigbus")) return case_sigbus();
    if (!strcmp(mode, "userfaultfd-shared")) return case_shared();
    if (!strcmp(mode, "userfaultfd-wp")) return case_wp();
    if (!strcmp(mode, "userfaultfd-poison")) return case_poison();
    if (!strcmp(mode, "userfaultfd-shmem")) return case_shmem();
    if (!strcmp(mode, "userfaultfd-minor")) return case_minor();
    if (!strcmp(mode, "userfaultfd-wp-shmem")) return case_wp_shmem();
    if (!strcmp(mode, "userfaultfd-wp-async")) return case_wp_async();
    if (!strcmp(mode, "userfaultfd-move")) return case_move();
    if (!strcmp(mode, "userfaultfd-events")) return case_events();
    printf("unknown mode %s\n", mode);
    return 2;
}
