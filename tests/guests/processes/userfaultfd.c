/* userfaultfd, compared with Linux: the calls' errors and their order,
   UFFDIO_API and the ranges UFFDIO_REGISTER makes (the VMAs of
   /proc/self/maps and the `um` of smaps), and the faults of a thread on
   missing pages: the messages a read gives, UFFDIO_COPY, UFFDIO_ZEROPAGE,
   UFFDIO_WAKE and UFFDIO_UNREGISTER ending the wait, the features
   THREAD_ID, EXACT_ADDRESS and SIGBUS, a signal during the wait, closing
   the file, fork, and shared anonymous memory.

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
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#define UFFD_API 0xaaULL
#define UFFD_USER_MODE_ONLY 1
#define UFFD_EVENT_PAGEFAULT 0x12
#define UFFD_PAGEFAULT_FLAG_WRITE 1
#define UFFD_FEATURE_EVENT_FORK (1ULL << 1)
#define UFFD_FEATURE_MISSING_SHMEM (1ULL << 5)
#define UFFD_FEATURE_SIGBUS (1ULL << 7)
#define UFFD_FEATURE_THREAD_ID (1ULL << 8)
#define UFFD_FEATURE_EXACT_ADDRESS (1ULL << 11)
#define UFFDIO_REGISTER_MODE_MISSING 1ULL
#define UFFDIO_COPY_MODE_DONTWAKE 1ULL
#define UFFDIO_ZEROPAGE_MODE_DONTWAKE 1ULL

#define UFFDIO_API 0xc018aa3f
#define UFFDIO_REGISTER 0xc020aa00
#define UFFDIO_UNREGISTER 0x8010aa01
#define UFFDIO_WAKE 0x8010aa02
#define UFFDIO_COPY 0xc028aa03
#define UFFDIO_ZEROPAGE 0xc020aa04

#define RANGE_IOCTLS ((1ULL << 2) | (1ULL << 3) | (1ULL << 4))
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

static long zeropage(int fd, void *dst, size_t len, uint64_t mode, int64_t *done) {
    struct uffdio_zeropage z = {{(uintptr_t)dst, len}, mode, 0x5a5a};
    long ret = ioctl(fd, UFFDIO_ZEROPAGE, &z);
    if (done)
        *done = z.zeropage;
    return ret;
}

/* `len` bytes of private anonymous memory between two pages that cannot be
   accessed, so that its VMAs merge with no other. */
static void *anon(size_t len) {
    char *area = mmap(NULL, len + 2 * PAGE, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    mprotect(area + PAGE, len, PROT_READ | PROT_WRITE);
    return area + PAGE;
}

/* The VmFlags of the VMA at `at` have `um`; the VMA's bounds as offsets
   from `base`. */
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
            printf("%s: [%ld, %ld) um=%d\n", what, (long)(start - (uintptr_t)base),
                   (long)(end - (uintptr_t)base), strstr(line, " um") != NULL);
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

int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "";
    setvbuf(stdout, NULL, _IOLBF, 0);
    alarm(20);
    if (!strcmp(mode, "userfaultfd-calls")) return case_calls();
    if (!strcmp(mode, "userfaultfd-faults")) return case_faults();
    if (!strcmp(mode, "userfaultfd-signals")) return case_signals();
    if (!strcmp(mode, "userfaultfd-sigbus")) return case_sigbus();
    if (!strcmp(mode, "userfaultfd-shared")) return case_shared();
    printf("unknown mode %s\n", mode);
    return 2;
}
