/* userfaultfd, compared with Linux: the calls' errors and their order,
   UFFDIO_API and the ranges UFFDIO_REGISTER makes (the VMAs of
   /proc/self/maps and the `um` of smaps), and the faults of a thread on
   missing pages: the messages a read gives, UFFDIO_COPY, UFFDIO_ZEROPAGE,
   UFFDIO_WAKE and UFFDIO_UNREGISTER ending the wait, the features
   THREAD_ID, EXACT_ADDRESS and SIGBUS, a signal during the wait, closing
   the file, fork, and shared anonymous memory; the kernel's own faults
   (get_user_pages): process_vm_readv and process_vm_writev, whose pages
   fault in before any is copied, MADV_POPULATE_READ and _WRITE, mlock,
   futex words, /proc/self/mem and ptrace, which do not wait, another
   process's memory, and a copy whose userfaultfd is closed; and write protection:
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
   waits for its event to be read; and PAGEMAP_SCAN, the ioctl of
   /proc/self/pagemap: its errors, the categories of present, zero, file,
   shared, guard and empty pages, the regions it joins, a buffer or a page
   limit that stops it short, inverted and any-of masks, and with
   WP_ASYNC the written pages it finds and write-protects, the fast path
   without a buffer, and the VMAs it may not protect. It asks only for
   categories on which Linux 7.0 and master agree: WRITTEN only in VMAs
   registered for write protection whose pages all have entries or
   markers.

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
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/uio.h>
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

/* /dev/userfaultfd (userfaultfd_misc): a root misc device of mode 0600,
   whose only operation, USERFAULTFD_IOC_NEW, makes a context of the flags
   it is given with no capability; and vm.unprivileged_userfaultfd, read
   alone, as the native run's is the runner's own. */
static void dev_calls(void) {
    int dev = open("/dev/userfaultfd", O_RDWR | O_CLOEXEC);
    printf("dev open: %d\n", dev >= 0);
    if (dev < 0) return;
    struct stat st;
    fstat(dev, &st);
    printf("dev mode: 0%o uid %u major %u\n", st.st_mode, st.st_uid, major(st.st_rdev));
    int made = ioctl(dev, _IO(0xAA, 0x00), O_CLOEXEC | O_NONBLOCK);
    printf("dev new: %d\n", made >= 0);
    printf("dev new F_GETFL: 0%o\n", fcntl(made, F_GETFL));
    struct uffdio_api api = {UFFD_API, 0, 0};
    printf("dev new API: %s\n", err(ioctl(made, UFFDIO_API, &api)));
    close(made);
    printf("dev new bad flags: %s\n", err(ioctl(dev, _IO(0xAA, 0x00), 0x10)));
    printf("dev other ioctl: %s\n", err(ioctl(dev, _IO(0xAA, 0x01), 0)));
    char byte;
    printf("dev read: %s\n", err(read(dev, &byte, 1)));
    printf("dev write: %s\n", err(write(dev, &byte, 1)));
    close(dev);
    /* Another user may not open it. */
    pid_t child = fork();
    if (child == 0) {
        if (setresuid(1000, 1000, 1000)) _exit(2);
        _exit(open("/dev/userfaultfd", O_RDWR) < 0 && errno == EACCES ? 0 : 1);
    }
    int status = 0;
    waitpid(child, &status, 0);
    printf("dev other user: %d\n", WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    int sysctl = open("/proc/sys/vm/unprivileged_userfaultfd", O_RDONLY);
    char text[8] = {0};
    long n = read(sysctl, text, sizeof text);
    close(sysctl);
    printf("sysctl: %ld bytes, a bit %d\n", n, n == 2 && (text[0] == '0' || text[0] == '1') && text[1] == '\n');
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
    dev_calls();
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

/* What read_pipe reads, and where. */
struct pipe_read {
    int pipe;
    char *at;
    long got;
    volatile pid_t tid;
};

static void *read_pipe(void *with) {
    struct pipe_read *r = with;
    r->tid = (pid_t)syscall(SYS_gettid);
    r->got = read(r->pipe, r->at, 5);
    return NULL;
}

/* A system call's own copy to a registered page that has none waits for
   it as an instruction does (handle_userfault from a kernel fault, a write
   one for read's copy), and a signal that is not fatal does not end the
   wait, as do_user_addr_fault retries a kernel fault after one; a context
   of user faults alone leaves the copy EFAULT. */
static void kernel_copy(void) {
    int fd = ready(O_NONBLOCK, UFFD_FEATURE_THREAD_ID);
    char *base = anon(PAGE);
    reg(fd, base, PAGE, UFFDIO_REGISTER_MODE_MISSING, NULL);
    int pipes[2];
    pipe(pipes);
    write(pipes[1], "hello", 5);
    struct pipe_read r = {pipes[0], base + 16, 0, 0};
    signalled = 0;
    pthread_t thread;
    pthread_create(&thread, NULL, read_pipe, &r);
    printf("kernel copy polled: %d\n", wait_message(fd));
    while (!r.tid)
        usleep(1000);
    wait_blocked(r.tid);
    message("kernel copy fault", fd, base, r.tid);
    syscall(SYS_tgkill, getpid(), r.tid, SIGUSR1);
    usleep(20000);
    char src[PAGE];
    memset(src, 'k', sizeof src);
    int64_t done;
    printf("kernel copy fill: %s\n", err(copy(fd, base, src, PAGE, 0, &done)));
    pthread_join(thread, NULL);
    printf("kernel copy: read %ld bytes %.5s after %c signalled %d\n", r.got, base + 16, base[21], signalled);
    close(fd);
    int user = ready(O_NONBLOCK | UFFD_USER_MODE_ONLY, 0);
    char *other = anon(PAGE);
    reg(user, other, PAGE, UFFDIO_REGISTER_MODE_MISSING, NULL);
    write(pipes[1], "hello", 5);
    printf("user mode only copy: %s\n", err(read(pipes[0], other, 5)));
    close(user);
    close(pipes[0]);
    close(pipes[1]);
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
    kernel_copy();
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
static void wp_mode_replaced(void);

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
    wp_mode_replaced();
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

    /* A file of a tmpfs mount, /dev/shm, is shmem's: its hole waits too. */
    char tmpfs_path[] = "/dev/shm/uffd-shmem-XXXXXX";
    int tmpfs = mkstemp(tmpfs_path);
    if (tmpfs < 0 || unlink(tmpfs_path) || ftruncate(tmpfs, 2 * PAGE)) {
        printf("tmpfs file: errno %d\n", errno);
        return 3;
    }
    char *mapped = mmap(NULL, 2 * PAGE, PROT_READ | PROT_WRITE, MAP_SHARED, tmpfs, 0);
    if (mapped == MAP_FAILED) {
        printf("tmpfs map: errno %d\n", errno);
        return 4;
    }
    printf("register tmpfs: %s\n", err(reg(fd, mapped, 2 * PAGE, UFFDIO_REGISTER_MODE_MISSING, NULL)));
    t = (struct toucher){mapped + 3, 0, 0, 0};
    pthread_create(&thread, NULL, touch, &t);
    wait_message(fd);
    message("tmpfs hole", fd, mapped, 0);
    printf("copy: %s\n", err(copy(fd, mapped, src, PAGE, 0, NULL)));
    pthread_join(thread, NULL);
    printf("seen: %c\n", t.seen);
    byte = 0;
    pread(tmpfs, &byte, 1, 3);
    printf("the file has: %c\n", byte);
    munmap(mapped, 2 * PAGE);
    close(tmpfs);
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

/* The signals the guard install below took, and where the last one
   leaves it. */
static volatile sig_atomic_t alarms;
static sigjmp_buf alarmed;
static void on_alarm(int sig) {
    (void)sig;
    if (++alarms == 2) siglongjmp(alarmed, 1);
}

/* Whether the page at `at` is a guard page in /proc/self/pagemap. */
static int guarded(void *at) {
    int f = open("/proc/self/pagemap", O_RDONLY);
    uint64_t e = 0;
    pread(f, &e, sizeof e, (off_t)((uintptr_t)at / PAGE * sizeof e));
    close(f);
    return (int)(e >> 58 & 1);
}

/* MADV_GUARD_INSTALL over shmem whose second page has a uffd-wp marker,
   once its zap leaves one for a protected entry: Linux's
   madvise_guard_install puts a guard on the first page, stops at the
   marker, which its zap keeps (zap_install_uffd_wp_if_needed), and
   restarts the call (ERESTARTNOINTR) until a signal comes, and after its
   handler too, without SA_RESTART. The second signal's handler leaves. */
static void guard_over_marker(void) {
    int fd = ready(O_NONBLOCK, UFFD_FEATURE_PAGEFAULT_FLAG_WP);
    int file = shmem_file(3);
    char *view = mmap(NULL, 3 * PAGE, PROT_READ | PROT_WRITE, MAP_SHARED, file, 0);
    printf("register for the guard: %s\n", err(reg(fd, view, 3 * PAGE, UFFDIO_REGISTER_MODE_WP, NULL)));
    view[PAGE] = 'w';
    printf("protect the last two: %s\n", err(protect(fd, view + PAGE, 2 * PAGE, UFFDIO_WRITEPROTECT_MODE_WP)));
    struct sigaction sa = {0}, old;
    sa.sa_handler = on_alarm;
    sigaction(SIGALRM, &sa, &old);
    struct itimerval every = {{0, 50000}, {0, 50000}}, off = {{0, 0}, {0, 0}};
    alarms = 0;
    long ret = 1;
    if (sigsetjmp(alarmed, 1) == 0) {
        setitimer(ITIMER_REAL, &every, NULL);
        ret = madvise(view, 3 * PAGE, MADV_GUARD_INSTALL);
    }
    setitimer(ITIMER_REAL, &off, NULL);
    sigaction(SIGALRM, &old, NULL);
    printf("guard over a marker: returned %s signals %d\n", ret == 1 ? "no" : err(ret), (int)alarms);
    for (int i = 0; i < 3; i++) {
        char what[32];
        snprintf(what, sizeof what, "page %d guard=%d", i, guarded(view + i * PAGE));
        pagemap_show(what, view + i * PAGE);
    }
    close(fd);
    close(file);
}

/* The pipe a SIGUSR1 handler writes to, to tell that it ran. */
static int handled_pipe = -1;
static void on_usr1(int sig) {
    (void)sig;
    write(handled_pipe, "h", 1);
}

/* The same install through process_madvise, in a child of its own (a
   fork copies no marker of shmem): Linux's vector_madvise tries again
   until a fatal signal, and runs no handler meanwhile, so a SIGUSR1 is
   not taken, the call does not return, and SIGKILL ends it. */
static void guard_over_marker_vectored(void) {
    int pipes[2];
    if (pipe(pipes)) return;
    fflush(stdout);
    pid_t child = fork();
    if (child == 0) {
        close(pipes[0]);
        int fd = ready(O_NONBLOCK, UFFD_FEATURE_PAGEFAULT_FLAG_WP);
        int file = shmem_file(3);
        char *view = mmap(NULL, 3 * PAGE, PROT_READ | PROT_WRITE, MAP_SHARED, file, 0);
        reg(fd, view, 3 * PAGE, UFFDIO_REGISTER_MODE_WP, NULL);
        view[PAGE] = 'w';
        protect(fd, view + PAGE, 2 * PAGE, UFFDIO_WRITEPROTECT_MODE_WP);
        handled_pipe = pipes[1];
        struct sigaction sa = {0};
        sa.sa_handler = on_usr1;
        sigaction(SIGUSR1, &sa, NULL);
        int pidfd = (int)syscall(434 /* pidfd_open */, getpid(), 0);
        struct iovec iov = {view, 3 * PAGE};
        write(pipes[1], "r", 1);
        syscall(440 /* process_madvise */, pidfd, &iov, 1, MADV_GUARD_INSTALL, 0);
        write(pipes[1], "!", 1);
        _exit(0);
    }
    close(pipes[1]);
    char got[8] = {0};
    read(pipes[0], got, 1);
    usleep(100000);
    kill(child, SIGUSR1);
    usleep(100000);
    kill(child, SIGKILL);
    int status = 0;
    waitpid(child, &status, 0);
    long more = read(pipes[0], got + 1, sizeof got - 2);
    close(pipes[0]);
    printf("vectored guard over a marker: ready %c after it \"%s\" killed %d\n", got[0],
           more > 0 ? got + 1 : "", WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
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

/* A thread's write of `at`: whether it faults to `fd` (within half a
   second), whose protection of the page then ends. */
static void write_or_fault(const char *what, int fd, char *at) {
    struct toucher t = {at, 1, 0, 0};
    pthread_t thread;
    pthread_create(&thread, NULL, touch, &t);
    struct pollfd waiting = {fd, POLLIN, 0};
    int faulted = poll(&waiting, 1, 500) == 1;
    if (faulted) {
        struct uffd_msg msg;
        read(fd, &msg, sizeof msg);
        protect(fd, (void *)((uintptr_t)at & ~(uintptr_t)(PAGE - 1)), PAGE, 0);
    }
    pthread_join(thread, NULL);
    printf("%s: faulted %d seen %c\n", what, faulted, t.seen);
}

/* A registration that replaces the write-protect mode changes the VMA's
   flags alone (userfaultfd_register_range): the entries keep
   _PAGE_UFFD_WP, which the pagemap shows and which protects nothing; the
   mode registered again protects the page again, unless a write made the
   entry writable meanwhile (wp_page_reuse keeps the bit). */
static void wp_mode_replaced(void) {
    int fd = ready(O_NONBLOCK, UFFD_FEATURE_PAGEFAULT_FLAG_WP);
    char *a = anon(2 * PAGE);
    printf("register two: %s\n", err(reg(fd, a, 2 * PAGE, UFFDIO_REGISTER_MODE_WP, NULL)));
    a[0] = 'x';
    a[PAGE] = 'y';
    printf("protect two: %s\n", err(protect(fd, a, 2 * PAGE, UFFDIO_WRITEPROTECT_MODE_WP)));
    printf("register missing alone: %s\n", err(reg(fd, a, 2 * PAGE, UFFDIO_REGISTER_MODE_MISSING, NULL)));
    pagemap_show("replaced", a);
    write_or_fault("write after the mode went", fd, a + PAGE);
    pagemap_show("written after the mode went", a + PAGE);
    printf("register write protection again: %s\n", err(reg(fd, a, 2 * PAGE, UFFDIO_REGISTER_MODE_WP, NULL)));
    write_or_fault("unwritten page", fd, a);
    write_or_fault("page written meanwhile", fd, a + PAGE);
    pagemap_show("page written meanwhile", a + PAGE);
    close(fd);
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
    guard_over_marker();
    guard_over_marker_vectored();
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

#define PAGEMAP_SCAN 0xc0606610
#define PAGE_IS_WPALLOWED (1 << 0)
#define PAGE_IS_WRITTEN (1 << 1)
#define PAGE_IS_FILE (1 << 2)
#define PAGE_IS_PRESENT (1 << 3)
#define PAGE_IS_SWAPPED (1 << 4)
#define PAGE_IS_PFNZERO (1 << 5)
#define PAGE_IS_GUARD (1 << 8)
#define PM_SCAN_WP_MATCHING 1
#define PM_SCAN_CHECK_WPASYNC 2

struct page_region {
    uint64_t start, end, categories;
};

struct pm_scan_arg {
    uint64_t size, flags, start, end, walk_end, vec, vec_len, max_pages, category_inverted,
        category_mask, category_anyof_mask, return_mask;
};

/* A request over `len` bytes at `at` for `vec_len` regions. */
static struct pm_scan_arg scan_arg(void *at, size_t len, struct page_region *vec,
                                   uint64_t vec_len) {
    struct pm_scan_arg a = {sizeof a, 0, (uintptr_t)at, (uintptr_t)at + len, 0x5a5a,
                            (uintptr_t)vec, vec_len, 0, 0, 0, 0, 0};
    return a;
}

/* PAGEMAP_SCAN of `a` on `pm`: its result, walk_end and the regions, as
   offsets from `base` in pages; a buffer out of reach is not written. */
static void scan_show(const char *what, int pm, char *base, struct pm_scan_arg *a) {
    struct page_region *vec = (struct page_region *)(uintptr_t)a->vec;
    if (a->vec == (uintptr_t)-4096)
        vec = NULL;
    for (uint64_t i = 0; vec && i < a->vec_len; i++)
        vec[i] = (struct page_region){1, 1, 0x5a5a};
    long r = ioctl(pm, PAGEMAP_SCAN, a);
    if (a->walk_end == 0x5a5a)
        printf("%s: %s walk_end unset", what, err(r));
    else
        printf("%s: %s walk_end=%ld", what, err(r), (long)(a->walk_end - (uintptr_t)base) / PAGE);
    for (long i = 0; vec && i < r; i++)
        printf(" [%ld,%ld)%#llx", (long)(vec[i].start - (uintptr_t)base) / PAGE,
               (long)(vec[i].end - (uintptr_t)base) / PAGE, (unsigned long long)vec[i].categories);
    printf("\n");
}

static int case_scan(void) {
    int pm = open("/proc/self/pagemap", O_RDONLY);
    struct page_region vec[8];
    const uint64_t kinds =
        PAGE_IS_PRESENT | PAGE_IS_FILE | PAGE_IS_PFNZERO | PAGE_IS_SWAPPED | PAGE_IS_GUARD;
    /* Private anonymous memory: written, read, empty and a guard. */
    char *a = anon(5 * PAGE);
    a[0] = 'a';
    a[PAGE] = 'b';
    volatile char c = a[2 * PAGE];
    (void)c;
    printf("guard: %s\n", err(madvise(a + 4 * PAGE, PAGE, MADV_GUARD_INSTALL)));

    struct pm_scan_arg r = scan_arg(a, 5 * PAGE, vec, 8);
    r.size = 88;
    scan_show("size", pm, a, &r);
    r = scan_arg(a, 5 * PAGE, vec, 8);
    r.flags = 4;
    scan_show("flags", pm, a, &r);
    r = scan_arg(a, 5 * PAGE, vec, 8);
    r.return_mask = 1 << 10;
    scan_show("category", pm, a, &r);
    r = scan_arg(a + 1, 5 * PAGE, vec, 8);
    scan_show("unaligned", pm, a, &r);
    r = scan_arg(a, 5 * PAGE, NULL, 8);
    scan_show("no buffer", pm, a, &r);
    r = scan_arg(a + PAGE, 0, vec, 8);
    r.end = (uintptr_t)a;
    scan_show("end before start", pm, a, &r);
    r = scan_arg(a, 5 * PAGE, (struct page_region *)(uintptr_t)-4096, 8);
    scan_show("buffer out of reach", pm, a, &r);
    r = scan_arg(a, 0, vec, 8);
    scan_show("empty", pm, a, &r);
    r = scan_arg(a, 5 * PAGE, vec, 0);
    r.return_mask = kinds;
    scan_show("no regions", pm, a, &r);

    r = scan_arg(a, 5 * PAGE, vec, 8);
    r.category_anyof_mask = PAGE_IS_PRESENT | PAGE_IS_SWAPPED;
    r.return_mask = kinds;
    scan_show("kinds", pm, a, &r);
    r.return_mask = PAGE_IS_PRESENT | PAGE_IS_SWAPPED;
    scan_show("joined", pm, a, &r);
    r.return_mask = kinds;
    r.end = (uintptr_t)a + 5 * PAGE - 100;
    scan_show("end within a page", pm, a, &r);
    r = scan_arg(a, 5 * PAGE, vec, 1);
    r.category_anyof_mask = PAGE_IS_PRESENT | PAGE_IS_SWAPPED;
    r.return_mask = kinds;
    scan_show("one region", pm, a, &r);
    r = scan_arg(a, 5 * PAGE, vec, 8);
    r.category_mask = PAGE_IS_PRESENT;
    r.return_mask = PAGE_IS_PRESENT;
    r.max_pages = 1;
    scan_show("one page", pm, a, &r);
    r.max_pages = 2;
    scan_show("two pages", pm, a, &r);
    r = scan_arg(a, 5 * PAGE, vec, 8);
    r.category_inverted = PAGE_IS_PRESENT;
    r.category_mask = PAGE_IS_PRESENT;
    r.return_mask = kinds;
    scan_show("not present", pm, a, &r);
    r = scan_arg(a - PAGE, 7 * PAGE, vec, 8);
    r.category_mask = PAGE_IS_PFNZERO;
    r.return_mask = kinds;
    scan_show("zero", pm, a, &r);

    /* A file's private mapping, read and written, and shared memory. */
    char path[] = "/tmp/uffd-scan-XXXXXX";
    int file = mkstemp(path);
    unlink(path);
    char bytes[2 * PAGE];
    memset(bytes, 'f', sizeof bytes);
    write(file, bytes, sizeof bytes);
    char *f = mmap(NULL, 2 * PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE, file, 0);
    c = f[0];
    f[PAGE] = 'g';
    r = scan_arg(f, 2 * PAGE, vec, 8);
    r.category_mask = PAGE_IS_PRESENT;
    r.return_mask = kinds;
    scan_show("private file", pm, f, &r);
    char *s = mmap(NULL, 2 * PAGE, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    s[0] = 's';
    c = s[PAGE];
    r = scan_arg(s, 2 * PAGE, vec, 8);
    r.category_mask = PAGE_IS_PRESENT;
    r.return_mask = kinds;
    scan_show("shared", pm, s, &r);
    r.flags = PM_SCAN_WP_MATCHING;
    scan_show("protect unregistered", pm, s, &r);
    r.flags = PM_SCAN_CHECK_WPASYNC;
    scan_show("check unregistered", pm, s, &r);

    /* With WP_ASYNC and WP_UNPOPULATED, every page of the range has an
       entry or a marker once protected. */
    int fd = ready(O_NONBLOCK, UFFD_FEATURE_WP_ASYNC | UFFD_FEATURE_WP_UNPOPULATED);
    if (fd < 0)
        return 0;
    char *w = anon(4 * PAGE);
    w[0] = 'w';
    printf("register: %s\n", err(reg(fd, w, 4 * PAGE, UFFDIO_REGISTER_MODE_WP, NULL)));
    printf("protect: %s\n", err(protect(fd, w, 4 * PAGE, UFFDIO_WRITEPROTECT_MODE_WP)));
    struct pm_scan_arg written = scan_arg(w, 4 * PAGE, vec, 8);
    written.category_mask = PAGE_IS_WRITTEN;
    written.return_mask = PAGE_IS_WRITTEN;
    scan_show("none written", pm, w, &written);
    w[0] = 'x';
    w[2 * PAGE] = 'y';
    r = scan_arg(w, 4 * PAGE, vec, 8);
    r.return_mask = PAGE_IS_WPALLOWED | PAGE_IS_WRITTEN | PAGE_IS_PRESENT | PAGE_IS_SWAPPED;
    scan_show("all", pm, w, &r);
    scan_show("written", pm, w, &written);
    written.flags = PM_SCAN_WP_MATCHING | PM_SCAN_CHECK_WPASYNC;
    scan_show("protect written", pm, w, &written);
    pagemap_show("protected again", w);
    written.flags = 0;
    scan_show("after", pm, w, &written);
    w[PAGE] = 'z';
    w[3 * PAGE] = 'z';
    written.flags = PM_SCAN_WP_MATCHING;
    written.vec_len = 1;
    scan_show("protect one region", pm, w, &written);
    written.flags = 0;
    written.vec_len = 8;
    scan_show("one left", pm, w, &written);
    w[0] = 'q';
    r = scan_arg(w, 4 * PAGE, NULL, 0);
    r.flags = PM_SCAN_WP_MATCHING;
    r.category_mask = PAGE_IS_WRITTEN;
    scan_show("protect without regions", pm, w, &r);
    scan_show("none left", pm, w, &written);
    r = scan_arg(w, 4 * PAGE, vec, 8);
    r.category_mask = PAGE_IS_WPALLOWED;
    r.return_mask = PAGE_IS_WPALLOWED;
    scan_show("allowed", pm, w, &r);
    r = scan_arg(w - PAGE, 6 * PAGE, vec, 8);
    r.category_mask = PAGE_IS_WRITTEN;
    r.return_mask = PAGE_IS_WRITTEN;
    w[PAGE] = 'r';
    r.flags = PM_SCAN_CHECK_WPASYNC;
    scan_show("check beyond", pm, w, &r);
    r.flags = PM_SCAN_WP_MATCHING;
    scan_show("protect beyond", pm, w, &r);
    close(fd);
    close(pm);
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
    /* The copy wakes the child, which prints as this does: told only after
       it has ended, so that its line always comes first. */
    char copied[64];
    snprintf(copied, sizeof copied, "%s", err(copy(ufd, base + 7 * PAGE, page, PAGE, 0, NULL)));
    int status;
    waitpid(child, &status, 0);
    printf("child copy: %s\n", copied);
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

/* A system call another thread makes. */
struct sys {
    long nr, args[6], ret;
    int error;
    volatile pid_t tid;
};

static void *make(void *with) {
    struct sys *s = with;
    s->tid = (pid_t)syscall(SYS_gettid);
    errno = 0;
    s->ret = syscall(s->nr, s->args[0], s->args[1], s->args[2], s->args[3], s->args[4], s->args[5]);
    s->error = errno;
    return NULL;
}

/* Makes `s` in a thread, and fills the page of `base` its fault names with
   `fill` `times` times, or with 0 unmaps the page and wakes it, or with no `fill`
   closes `fd`. */
static void served(const char *name, int fd, char *base, struct sys s, char fill, int times) {
    pthread_t thread;
    pthread_create(&thread, NULL, make, &s);
    while (!s.tid)
        usleep(1000);
    char src[PAGE];
    memset(src, fill, sizeof src);
    for (int i = 0; i < times || (!times && !i); i++) {
        printf("%s polled: %d\n", name, wait_message(fd));
        struct uffd_msg msg;
        long n = read(fd, &msg, sizeof msg);
        long at = (long)(msg.address - (uintptr_t)base);
        printf("%s fault: %ld flags %#llx at %ld thread %d\n", name, n, (unsigned long long)msg.flags,
               at, msg.ptid == (uint32_t)s.tid);
        /* The queues of futexes are free meanwhile. */
        int other = 0;
        syscall(SYS_futex, &other, 129 /* FUTEX_WAKE_PRIVATE */, 1, NULL, NULL, 0);
        if (times)
            printf("%s fill: %s\n", name, err(copy(fd, base + at, src, PAGE, 0, NULL)));
        else if (fill) {
            /* The unmap leaves the wait, as the context has no events. */
            printf("%s unmap: %s\n", name, err(munmap(base + at, PAGE)));
            ioctl(fd, UFFDIO_WAKE, &(struct uffdio_range){(uintptr_t)base + at, PAGE});
        } else
            close(fd);
    }
    pthread_join(thread, NULL);
    printf("%s: %ld %s\n", name, s.ret, s.ret < 0 ? strerror(s.error) : "");
}

/* Another process's memory: process_vm_readv waits for the page there,
   whose handler is in that process, and ptrace's peek and poke fail. */
static void other_process(void) {
    char *base = anon(2 * PAGE);
    int up[2];
    pipe(up);
    fflush(stdout);
    pid_t child = fork();
    if (child == 0) {
        int fd = ready(O_NONBLOCK, 0);
        reg(fd, base, 2 * PAGE, UFFDIO_REGISTER_MODE_MISSING, NULL);
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        write(up[1], "r", 1);
        wait_message(fd);
        struct uffd_msg msg;
        char src[PAGE];
        memset(src, 'c', sizeof src);
        if (read(fd, &msg, sizeof msg) == sizeof msg)
            copy(fd, (char *)(uintptr_t)msg.address, src, PAGE, 0, NULL);
        raise(SIGSTOP);
        _exit(0);
    }
    char buf[8] = "";
    read(up[0], buf, 1);
    struct iovec local = {buf, 4}, remote = {base, 4};
    printf("other readv: %s", err(process_vm_readv(child, &local, 1, &remote, 1, 0)));
    printf(" %s\n", buf);
    int status;
    waitpid(child, &status, 0);
    errno = 0;
    long word = ptrace(PTRACE_PEEKDATA, child, base + PAGE, NULL);
    printf("peek: %ld %s\n", word, strerror(errno));
    printf("poke: %s\n", err(ptrace(PTRACE_POKEDATA, child, base + PAGE, NULL)));
    errno = 0;
    word = ptrace(PTRACE_PEEKDATA, child, base, NULL);
    printf("peek filled: %#lx %s\n", word, strerror(errno));
    kill(child, SIGKILL);
    waitpid(child, &status, 0);
    close(up[0]);
    close(up[1]);
}

static int case_gup(void) {
    int fd = ready(O_NONBLOCK, UFFD_FEATURE_THREAD_ID);
    char *base = anon(16 * PAGE);
    printf("register: %s\n", err(reg(fd, base, 16 * PAGE, UFFDIO_REGISTER_MODE_MISSING, NULL)));
    char buf[8] = "outside";
    struct iovec local = {buf, 6}, remote = {base + 8, 6};
    long pid = getpid();
    struct sys readv = {SYS_process_vm_readv, {pid, (long)&local, 1, (long)&remote, 1, 0}, 0, 0, 0};
    struct sys writev = {SYS_process_vm_writev, {pid, (long)&local, 1, (long)&remote, 1, 0}, 0, 0, 0};
    served("readv", fd, base, readv, 'r', 1);
    printf("buf: %s\n", buf);
    remote.iov_base = base + PAGE + 8;
    served("writev", fd, base, writev, 'w', 1);
    printf("page: %.4s\n", base + PAGE + 10);
    /* Every page of the remote buffer faults in, whatever room is left. */
    remote = (struct iovec){base + PAGE, 3 * PAGE};
    served("readv whole", fd, base, readv, 'a', 2);
    struct sys populate = {SYS_madvise, {(long)base + 4 * PAGE, PAGE, MADV_POPULATE_READ, 0, 0, 0}, 0, 0, 0};
    served("populate read", fd, base, populate, 'p', 1);
    populate.args[0] += PAGE;
    populate.args[2] = MADV_POPULATE_READ + 1;
    served("populate write", fd, base, populate, 'q', 1);
    struct sys lock = {SYS_mlock, {(long)base + 6 * PAGE, 2 * PAGE, 0, 0, 0, 0}, 0, 0, 0};
    served("mlock", fd, base, lock, 'l', 2);
    printf("pages: %c %c %c %c\n", base[4 * PAGE], base[5 * PAGE], base[6 * PAGE], base[7 * PAGE]);
    munlock(base + 6 * PAGE, 2 * PAGE);
    populate.args[0] = (long)base + 8 * PAGE;
    served("populate unmapped", fd, base, populate, 'u', 0);
    /* A futex word: FUTEX_WAIT's read of a private one, a shared one's key,
       and FUTEX_WAKE_OP, whose fault does not wait. */
    struct sys futex = {SYS_futex, {(long)base + 9 * PAGE, 128, 7, 0, 0, 0}, 0, 0, 0};
    served("futex wait", fd, base, futex, 'f', 1);
    futex = (struct sys){SYS_futex, {(long)base + 10 * PAGE, 132, 1, 1, (long)base, 7}, 0, 0, 0};
    served("futex requeue", fd, base, futex, 'f', 1);
    futex = (struct sys){SYS_futex, {(long)base + 11 * PAGE, 1, 1, 0, 0, 0}, 0, 0, 0};
    served("futex wake shared", fd, base, futex, 'f', 1);
    printf("futex wake op: %s\n",
           err(syscall(SYS_futex, base, 133, 1, 1, base + 12 * PAGE, 0)));
    /* /proc/self/mem does not wait. */
    int mem = open("/proc/self/mem", O_RDWR);
    off_t at = (off_t)(uintptr_t)base + 12 * PAGE;
    printf("mem read: %s\n", err(pread(mem, buf, 4, at)));
    printf("mem write: %s\n", err(pwrite(mem, buf, 4, at)));
    int pipes[2];
    pipe(pipes);
    struct sys out = {SYS_write, {pipes[1], (long)base + 12 * PAGE, 4, 0, 0, 0}, 0, 0, 0};
    served("closed", fd, base, out, 0, 0);
    printf("closed byte: %d\n", base[12 * PAGE]);
    /* A context of user faults alone. */
    int user = ready(O_NONBLOCK | UFFD_USER_MODE_ONLY, 0);
    char *other = anon(4 * PAGE);
    reg(user, other, 4 * PAGE, UFFDIO_REGISTER_MODE_MISSING, NULL);
    remote = (struct iovec){other, 6};
    printf("user readv: %s\n", err(process_vm_readv((pid_t)pid, &local, 1, &remote, 1, 0)));
    printf("user writev: %s\n", err(process_vm_writev((pid_t)pid, &local, 1, &remote, 1, 0)));
    printf("user populate read: %s\n", err(madvise(other, PAGE, MADV_POPULATE_READ)));
    printf("user populate write: %s\n", err(madvise(other, PAGE, MADV_POPULATE_READ + 1)));
    printf("user mlock: %s\n", err(mlock(other, PAGE)));
    munlock(other, PAGE);
    printf("user futex: %s\n", err(syscall(SYS_futex, other, 0, 7, NULL, NULL, 0)));
    unsigned char in = 1;
    mincore(other, PAGE, &in);
    printf("user missing: %d\n", !(in & 1));
    /* A forced write meets write protection, and a forced read does not. */
    int wp = ready(O_NONBLOCK, UFFD_FEATURE_PAGEFAULT_FLAG_WP);
    char *guarded = anon(PAGE);
    memcpy(guarded, "here", 4);
    reg(wp, guarded, PAGE, UFFDIO_REGISTER_MODE_WP, NULL);
    printf("protect: %s\n", err(protect(wp, guarded, PAGE, UFFDIO_WRITEPROTECT_MODE_WP)));
    at = (off_t)(uintptr_t)guarded;
    printf("mem read protected: %s\n", err(pread(mem, buf, 4, at)));
    printf("mem write protected: %s\n", err(pwrite(mem, "over", 4, at)));
    printf("unprotect: %s\n", err(protect(wp, guarded, PAGE, 0)));
    printf("mem write: %s", err(pwrite(mem, "over", 4, at)));
    printf(" %.4s\n", guarded);
    other_process();
    return 0;
}

static volatile sig_atomic_t frame_handled;

static void on_frame(int sig) {
    (void)sig;
    frame_handled = 1;
}

static volatile int frame_done;

/* Takes a signal on an alternate stack no page of which is there. */
static void *frame(void *stack) {
    stack_t alt = {.ss_sp = stack, .ss_size = 16 * PAGE, .ss_flags = 0};
    sigaltstack(&alt, NULL);
    syscall(SYS_tgkill, getpid(), syscall(SYS_gettid), SIGUSR2);
    alt.ss_flags = SS_DISABLE;
    sigaltstack(&alt, NULL);
    frame_done = 1;
    return NULL;
}

/* What waits for a pipe a vmsplice to the page `to` holds: its FIONREAD,
   F_GETPIPE_SZ and the close of its other end (pipe_release), not a poll. */
static void held_pipe(int fd, char *to, const char *src) {
    int pipes[2], unread = -1;
    pipe(pipes);
    write(pipes[1], "uvwxyz", 6);
    struct iovec part = {to, 3};
    struct sys calls[4] = {
        {SYS_vmsplice, {pipes[0], (long)&part, 1, 0, 0, 0}, -100, 0, 0},
        {SYS_ioctl, {pipes[0], FIONREAD, (long)&unread, 0, 0, 0}, -100, 0, 0},
        {SYS_fcntl, {pipes[0], 1032 /* F_GETPIPE_SZ */, 0, 0, 0, 0}, -100, 0, 0},
        {SYS_close, {pipes[1], 0, 0, 0, 0, 0}, -100, 0, 0},
    };
    pthread_t threads[4];
    for (int i = 0; i < 4; i++) {
        pthread_create(&threads[i], NULL, make, &calls[i]);
        if (i == 0)
            printf("held polled: %d\n", wait_message(fd));
        while (!calls[i].tid)
            usleep(1000);
    }
    struct uffd_msg msg;
    read(fd, &msg, sizeof msg);
    usleep(100000);
    struct pollfd p = {pipes[0], POLLIN, 0};
    printf("held: FIONREAD %ld size %ld close %ld", calls[1].ret, calls[2].ret, calls[3].ret);
    int n = poll(&p, 1, 0);
    printf(" poll %d %#x\n", n, (unsigned)p.revents);
    copy(fd, to, src, PAGE, 0, NULL);
    for (int i = 0; i < 4; i++)
        pthread_join(threads[i], NULL);
    printf("let go: vmsplice %ld FIONREAD %ld %d size %ld close %ld", calls[0].ret, calls[1].ret, unread,
           calls[2].ret, calls[3].ret);
    n = poll(&p, 1, 0);
    printf(" poll %d %#x\n", n, (unsigned)p.revents);
    close(pipes[0]);
}

/* A process killed as its vmsplice (`spliced`) or read holds a pipe lets go
   of it: the bytes are there for another's read. */
static void killed_holder(int spliced) {
    int pipes[2], blocked[2];
    pipe(pipes);
    pipe(blocked);
    write(pipes[1], "klmnop", 6);
    fflush(stdout);
    pid_t kid = fork();
    if (kid == 0) {
        int fd = ready(O_NONBLOCK, 0);
        char *page = anon(PAGE);
        reg(fd, page, PAGE, UFFDIO_REGISTER_MODE_MISSING, NULL);
        struct iovec part = {page, 3};
        struct sys call = {SYS_vmsplice, {pipes[0], (long)&part, 1, 0, 0, 0}, 0, 0, 0};
        if (!spliced)
            call = (struct sys){SYS_read, {pipes[0], (long)page, 3, 0, 0, 0}, 0, 0, 0};
        pthread_t thread;
        pthread_create(&thread, NULL, make, &call);
        wait_message(fd);
        write(blocked[1], "b", 1);
        for (;;)
            pause();
    }
    char buf[8] = "";
    read(blocked[0], buf, 1);
    kill(kid, SIGKILL);
    int status = 0;
    long reaped = waitpid(kid, &status, 0);
    memset(buf, 0, sizeof buf);
    long n = read(pipes[0], buf, 6);
    printf("%s killed: %d signal %d left %ld %s\n", spliced ? "vmsplice" : "read", reaped == kid,
           WTERMSIG(status), n, buf);
    for (int i = 0; i < 2; i++) {
        close(pipes[i]);
        close(blocked[i]);
    }
}

/* A read copies out and a write copies in with the pipe held: another
   waits for them. What cannot be copied stays in the pipe. */
static void held_copies(int fd, char *to, const char *src) {
    int pipes[2];
    pipe(pipes);
    for (int writes = 0; writes < 2; writes++) {
        char buf[16] = "";
        write(pipes[1], "stuvwx", 6);
        struct sys first = {writes ? SYS_write : SYS_read, {pipes[writes], (long)to + writes * PAGE, 3}, 0, 0, 0};
        struct sys second = {writes ? SYS_write : SYS_read, {pipes[writes], (long)(writes ? "!" : buf), writes ? 1 : 3}, -100, 0, 0};
        pthread_t threads[2];
        pthread_create(&threads[0], NULL, make, &first);
        printf("copy polled: %d\n", wait_message(fd));
        struct uffd_msg msg;
        read(fd, &msg, sizeof msg);
        pthread_create(&threads[1], NULL, make, &second);
        while (!second.tid)
            usleep(1000);
        usleep(100000);
        printf("%s waits: %d", writes ? "write" : "read", second.ret == -100);
        copy(fd, to + writes * PAGE, src, PAGE, 0, NULL);
        pthread_join(threads[0], NULL);
        pthread_join(threads[1], NULL);
        printf(" first %ld second %ld %s\n", first.ret, second.ret, writes ? "" : buf);
    }
    char buf[4096];
    printf("left %ld\n", (long)read(pipes[0], buf, sizeof buf));
    /* A bad buffer past the bytes there is no matter. */
    write(pipes[1], "yz0123", 6);
    struct iovec parts[2] = {{buf, 3}, {(char *)8, 64}};
    printf("readv part: %s", err(readv(pipes[0], parts, 2)));
    parts[0].iov_len = 6;
    printf(" whole %ld\n", (long)readv(pipes[0], parts, 2));
    parts[0].iov_len = 4096;
    printf("writev part: %ld", (long)writev(pipes[1], parts, 2));
    parts[0].iov_len = 100;
    printf(" %s", err(writev(pipes[1], parts, 2)));
    printf(" left %ld\n", (long)read(pipes[0], buf, sizeof buf));
    close(pipes[0]);
    close(pipes[1]);
}

/* Copies of the kernel's that wait with something held, or on the way back
   to the program. */
static int case_held(void) {
    int fd = ready(O_NONBLOCK, 0);
    char *base = anon(32 * PAGE);
    reg(fd, base, 32 * PAGE, UFFDIO_REGISTER_MODE_MISSING, NULL);
    /* vmsplice holds its pipe as it copies (pipe_lock): a read meanwhile
       takes what comes after. */
    int pipes[2];
    pipe(pipes);
    write(pipes[1], "abcdef", 6);
    struct iovec to = {base + 8, 3};
    struct sys splice = {SYS_vmsplice, {pipes[0], (long)&to, 1, 0, 0, 0}, 0, 0, 0};
    char buf[8] = "";
    struct sys reader = {SYS_read, {pipes[0], (long)buf, 3, 0, 0, 0}, 0, 0, 0};
    pthread_t splicer, second;
    pthread_create(&splicer, NULL, make, &splice);
    printf("vmsplice polled: %d\n", wait_message(fd));
    struct uffd_msg msg;
    read(fd, &msg, sizeof msg);
    pthread_create(&second, NULL, make, &reader);
    while (!reader.tid)
        usleep(1000);
    usleep(100000);
    char src[PAGE];
    memset(src, 0, sizeof src);
    copy(fd, base, src, PAGE, 0, NULL);
    pthread_join(splicer, NULL);
    pthread_join(second, NULL);
    printf("vmsplice: %ld %s read: %ld %s\n", splice.ret, base + 8, reader.ret, buf);
    /* What cannot be copied stays in the pipe, a buffer at a time. */
    write(pipes[1], "ghijkl", 6);
    struct iovec parts[2] = {{buf, 3}, {(char *)1, 3}};
    printf("vmsplice part: %s", err(syscall(SYS_vmsplice, pipes[0], parts, 2, 0)));
    memset(buf, 0, sizeof buf);
    printf(" left %ld %s\n", (long)read(pipes[0], buf, 6), buf);
    held_pipe(fd, base + 20 * PAGE, src);
    killed_holder(1);
    killed_holder(0);
    held_copies(fd, base + 21 * PAGE, src);
    /* A signal's frame. */
    struct sigaction sa = {0};
    sa.sa_handler = on_frame;
    sa.sa_flags = SA_ONSTACK;
    sigaction(SIGUSR2, &sa, NULL);
    pthread_t framed;
    pthread_create(&framed, NULL, frame, base + PAGE);
    int faults = 0;
    while (!frame_done) {
        struct pollfd p = {fd, POLLIN, 0};
        if (poll(&p, 1, 10) != 1 || read(fd, &msg, sizeof msg) != sizeof msg)
            continue;
        faults++;
        copy(fd, (char *)(uintptr_t)(msg.address & ~(uint64_t)(PAGE - 1)), src, PAGE, 0, NULL);
    }
    pthread_join(framed, NULL);
    printf("frame: handled %d faulted %d\n", (int)frame_handled, faults > 0);
    return 0;
}

/* What a fault that a userfaultfd served counts as. A fault of the
   thread's own code is tried again once the wait ends, which counts as a
   minor fault whether it brings the page in or not: its first try ran
   under the VMA's lock, whose retry is not FAULT_FLAG_TRIED. A fault of
   the kernel's copy for a read(2) or a write(2) is not tried under that
   lock first, so its retry is FAULT_FLAG_TRIED: a major fault. A
   get_user_pages population that waited finds the page there and counts
   nothing, nor does a write to a page a fill left writable. A wait that a
   signal ends is not tried again (fault_signal_pending) and counts
   nothing; the access faults again once the handler returns. The faulting
   thread reads its own getrusage(RUSAGE_THREAD) and page-faults,
   minor-faults and major-faults events around the one access. */
struct counted {
    char *at;
    int how; /* 0 a read, 1 a write, 2 MADV_POPULATE_WRITE, 3 read(2) into it, 4 write(2) from it */
    volatile int ready;
    volatile pid_t tid;
    int again; /* a signal's wait: whether the access faulted again */
    long minor, major;
    long long faults, minor_events, major_events;
};

/* The pipe that read(2) and write(2) of the page use. */
static int kernel_pipe[2];

static long software_event(int config) {
    uint64_t attr[16] = {0};
    attr[0] = 1 | (uint64_t)sizeof attr << 32; /* PERF_TYPE_SOFTWARE, size */
    attr[1] = (uint64_t)config;
    return syscall(SYS_perf_event_open, attr, 0, -1, -1, 0);
}

/* Touches the stack below the caller's, where a signal frame goes: its
   size follows the CPU's XSAVE features, and a first touch of a stack
   page in the measured access would count. */
__attribute__((noinline)) static void touch_stack(void) {
    volatile char below[64 * 1024];
    for (size_t i = 0; i < sizeof below; i += 4096) below[i] = 0;
}

static void *counted_access(void *arg) {
    struct counted *c = arg;
    touch_stack();
    int events[3] = {(int)software_event(2), (int)software_event(5), (int)software_event(6)};
    long long before[3] = {0}, after[3] = {0};
    struct rusage was, now;
    for (int i = 0; i < 3; i++) read(events[i], &before[i], 8);
    getrusage(RUSAGE_THREAD, &was);
    c->tid = (pid_t)syscall(SYS_gettid);
    c->ready = 1;
    if (c->how == 0) (void)*(volatile char *)c->at;
    if (c->how == 1) *(volatile char *)c->at = 'w';
    if (c->how == 2) madvise(c->at, PAGE, 23 /* MADV_POPULATE_WRITE */);
    if (c->how == 3 && read(kernel_pipe[0], c->at, 1) != 1) printf("read(2) failed\n");
    if (c->how == 4 && write(kernel_pipe[1], c->at, 1) != 1) printf("write(2) failed\n");
    getrusage(RUSAGE_THREAD, &now);
    for (int i = 0; i < 3; i++) read(events[i], &after[i], 8);
    c->minor = now.ru_minflt - was.ru_minflt;
    c->major = now.ru_majflt - was.ru_majflt;
    c->faults = after[0] - before[0];
    c->minor_events = after[1] - before[1];
    c->major_events = after[2] - before[2];
    for (int i = 0; i < 3; i++) close(events[i]);
    return NULL;
}

/* Runs `c` in a thread, serves its fault with `serve` once the userfaultfd
   has it, and prints the counts. */
static void counted(const char *what, int fd, struct counted *c, void (*serve)(int fd, struct counted *c)) {
    pthread_t thread;
    pthread_create(&thread, NULL, counted_access, c);
    int waited = wait_message(fd) == 1;
    struct uffd_msg msg;
    waited &= read(fd, &msg, sizeof msg) == sizeof msg;
    serve(fd, c);
    pthread_join(thread, NULL);
    printf("%s: waited %d minflt %ld majflt %ld page-faults %lld minor-faults %lld major-faults %lld\n", what,
           waited, c->minor, c->major, c->faults, c->minor_events, c->major_events);
}

static char filler[PAGE];
static void by_copy(int fd, struct counted *c) {
    copy(fd, c->at, filler, PAGE, 0, NULL);
}
static void by_zeropage(int fd, struct counted *c) {
    zeropage(fd, c->at, PAGE, 0, NULL);
}
static void by_unprotect(int fd, struct counted *c) {
    protect(fd, c->at, PAGE, 0);
}
static void by_continue(int fd, struct counted *c) {
    resume(fd, c->at, PAGE, 0, NULL);
}
static void by_unregister(int fd, struct counted *c) {
    unreg(fd, c->at, PAGE);
}
/* A signal ends the wait; the fault the access then takes again is
   served by a copy. */
static void by_signal_then_copy(int fd, struct counted *c) {
    wait_blocked(c->tid);
    syscall(SYS_tgkill, getpid(), c->tid, SIGUSR1);
    struct uffd_msg msg;
    c->again = wait_message(fd) == 1 && read(fd, &msg, sizeof msg) == sizeof msg;
    by_copy(fd, c);
}

/* Fields `from` and the one after of /proc/self/stat, counted from 1:
   majflt is 12 and cmajflt 13. */
static void stat_fields(int from, long *first, long *second) {
    char line[1024] = {0};
    int fd = open("/proc/self/stat", O_RDONLY);
    read(fd, line, sizeof line - 1);
    close(fd);
    /* The fields after the name, which ends at the last ')', start at 3. */
    char *at = strrchr(line, ')') + 2;
    for (int field = 3; field < from; field++) at = strchr(at, ' ') + 1;
    sscanf(at, "%ld %ld", first, second);
}

/* A child takes one major fault, which its wait and the parent's
   RUSAGE_CHILDREN and cmajflt then give. A fork without
   UFFD_FEATURE_EVENT_FORK leaves the child none of its parent's
   registrations, so it makes its own. */
static void reaped_major(void) {
    fflush(stdout);
    pid_t child = fork();
    if (child == 0) {
        int fd = ready(O_NONBLOCK, 0);
        char *at = anon(PAGE);
        reg(fd, at, PAGE, UFFDIO_REGISTER_MODE_MISSING, NULL);
        write(kernel_pipe[1], "k", 1);
        counted("child read(2), copy", fd, &(struct counted){.at = at, .how = 3}, by_copy);
        fflush(stdout);
        _exit(0);
    }
    struct rusage waited, children;
    int status;
    wait4(child, &status, 0, &waited);
    getrusage(RUSAGE_CHILDREN, &children);
    long cmajflt, unused;
    stat_fields(13, &cmajflt, &unused);
    printf("reaped: wait4 majflt %ld RUSAGE_CHILDREN majflt %ld cmajflt %ld\n", waited.ru_majflt,
           children.ru_majflt, cmajflt);
}

static int case_major(void) {
    memset(filler, 'f', sizeof filler);
    int fd = ready(O_NONBLOCK, UFFD_FEATURE_PAGEFAULT_FLAG_WP | UFFD_FEATURE_MINOR_SHMEM);
    char *base = anon(8 * PAGE);
    reg(fd, base, 8 * PAGE, UFFDIO_REGISTER_MODE_MISSING | UFFDIO_REGISTER_MODE_WP, NULL);
    counted("read, zeropage", fd, &(struct counted){.at = base, .how = 0}, by_zeropage);
    counted("write, copy", fd, &(struct counted){.at = base + PAGE, .how = 1}, by_copy);
    copy(fd, base + 2 * PAGE, filler, PAGE, UFFDIO_COPY_MODE_WP, NULL);
    counted("protected write, unprotect", fd, &(struct counted){.at = base + 2 * PAGE, .how = 1}, by_unprotect);
    counted("populate, copy", fd, &(struct counted){.at = base + 3 * PAGE, .how = 2}, by_copy);
    counted("read, unregister", fd, &(struct counted){.at = base + 4 * PAGE, .how = 0}, by_unregister);
    struct sigaction handler = {0};
    handler.sa_handler = on_signal;
    sigaction(SIGUSR1, &handler, NULL);
    /* The handler's code and data are touched first here: the loader
       counts no fault where Linux faults on the first touch of a page of
       the program. */
    raise(SIGUSR1);
    signalled = 0;
    struct counted waits = {.at = anon(PAGE), .how = 0};
    reg(fd, waits.at, PAGE, UFFDIO_REGISTER_MODE_MISSING, NULL);
    counted("read, signal, copy", fd, &waits, by_signal_then_copy);
    printf("signal: handled %d faulted again %d\n", signalled, waits.again);
    pipe(kernel_pipe);
    write(kernel_pipe[1], "k", 1);
    counted("read(2), copy", fd, &(struct counted){.at = base + 5 * PAGE, .how = 3}, by_copy);
    write(kernel_pipe[1], "k", 1);
    counted("read(2), unregister", fd, &(struct counted){.at = base + 6 * PAGE, .how = 3}, by_unregister);
    counted("write(2), zeropage", fd, &(struct counted){.at = base + 7 * PAGE, .how = 4}, by_zeropage);
    char drained;
    read(kernel_pipe[0], &drained, 1);
    /* The process's are its threads', the three above among them. */
    struct rusage self;
    getrusage(RUSAGE_SELF, &self);
    long majflt, cmajflt;
    stat_fields(12, &majflt, &cmajflt);
    printf("process: RUSAGE_SELF majflt at least 3 %d, /proc/self/stat majflt the same %d, cmajflt %ld\n",
           self.ru_majflt >= 3, majflt == self.ru_majflt, cmajflt);
    reaped_major();
    /* shmem_file's second page is in the page cache. */
    int file = shmem_file(2);
    char *view = mmap(NULL, 2 * PAGE, PROT_READ | PROT_WRITE, MAP_SHARED, file, 0);
    reg(fd, view, 2 * PAGE, UFFDIO_REGISTER_MODE_MINOR, NULL);
    counted("minor, continue", fd, &(struct counted){.at = view + PAGE, .how = 0}, by_continue);
    /* Without a wait, as the page is there: a minor fault. */
    char *again = anon(PAGE);
    reg(fd, again, PAGE, UFFDIO_REGISTER_MODE_MISSING, NULL);
    copy(fd, again, filler, PAGE, 0, NULL);
    struct counted c = {.at = again, .how = 1};
    counted_access(&c);
    printf("filled before: minflt %ld majflt %ld page-faults %lld minor-faults %lld major-faults %lld\n", c.minor,
           c.major, c.faults, c.minor_events, c.major_events);
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
    if (!strcmp(mode, "userfaultfd-gup")) return case_gup();
    if (!strcmp(mode, "userfaultfd-held")) return case_held();
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
    if (!strcmp(mode, "userfaultfd-scan")) return case_scan();
    if (!strcmp(mode, "userfaultfd-major")) return case_major();
    printf("unknown mode %s\n", mode);
    return 2;
}
