/* The page faults of instructions that read and write their memory operand,
   compared with Linux: one fault, a write, on a page that is not there, also
   when the instruction then writes nothing new (a shift by 0, a compare that
   fails). Each form prints the minor faults it takes on an untouched private
   page, the error code of its SIGSEGV where nothing may be accessed, and
   the faults a userfaultfd reports for it with how many of them were writes.
   Loads and stores are there to compare with. */
#define _GNU_SOURCE
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <ucontext.h>
#include <unistd.h>

#define PAGE 4096
#define UFFD_USER_MODE_ONLY 1
#define UFFD_API 0xaa
#define UFFDIO_API _IOWR(0xaa, 0x3f, struct uffdio_api)
#define UFFDIO_REGISTER _IOWR(0xaa, 0x00, struct uffdio_register)
#define UFFDIO_COPY _IOWR(0xaa, 0x03, struct uffdio_copy)
#define UFFD_WRITE 1

/* The structures of <linux/userfaultfd.h>, which musl does not have. */
struct uffdio_api {
    uint64_t api, features, ioctls;
};
struct uffdio_register {
    uint64_t start, len, mode, ioctls;
};
struct uffdio_copy {
    uint64_t dst, src, len, mode;
    int64_t copy;
};
struct uffd_msg {
    uint8_t event, reserved1;
    uint16_t reserved2;
    uint32_t reserved3;
    uint64_t flags, address;
    uint32_t ptid, pad;
};

/* %0 is the operand's address, in the first page; eax is 7, ecx is 1. */
#define FORMS(X) \
    X(load, "movb (%0), %%al") X(store, "movb $1, (%0)") X(cmp, "cmpb $1, (%0)") X(test, "testb $1, (%0)") \
    X(add_imm8, "addb $1, (%0)") X(add_reg8, "addb %%al, (%0)") X(add16, "addw $1, (%0)") \
    X(add32, "addl $1, (%0)") X(add64, "addq $1, (%0)") X(add_reg64, "addq %%rax, (%0)") \
    X(sub, "subl $1, (%0)") X(adc, "adcl $1, (%0)") X(sbb, "sbbl $1, (%0)") X(and, "andl $1, (%0)") \
    X(or, "orl $1, (%0)") X(xor, "xorl $1, (%0)") X(inc, "incl (%0)") X(dec, "decl (%0)") \
    X(not, "notl (%0)") X(neg, "negl (%0)") X(shl, "shll $1, (%0)") X(shl_cl, "shll %%cl, (%0)") \
    X(shl_0, "movb $0, %%cl; shll %%cl, (%0)") X(shr, "shrw $2, (%0)") X(sar, "sarq $3, (%0)") \
    X(rol, "roll $1, (%0)") X(ror, "rorb $1, (%0)") X(rcl, "rcll $3, (%0)") X(rcr, "rcrl $3, (%0)") \
    X(shld, "shldl $1, %%eax, (%0)") X(shrd, "shrdl %%cl, %%eax, (%0)") X(bt, "btl $1, (%0)") \
    X(bts, "btsl $1, (%0)") X(btr, "btrl $1, (%0)") X(btc, "btcl %%ecx, (%0)") \
    X(xadd, "xaddl %%eax, (%0)") X(cmpxchg_equal, "movl $0, %%eax; cmpxchgl %%ecx, (%0)") \
    X(cmpxchg_other, "cmpxchgl %%ecx, (%0)") X(cmpxchg8b, "cmpxchg8b (%0)") \
    X(cmpxchg16b, "cmpxchg16b (%0)") X(xchg, "xchgl %%eax, (%0)") X(lock_add, "lock addl $1, (%0)") \
    X(lock_inc, "lock incl (%0)") X(lock_not, "lock notl (%0)") X(lock_bts, "lock btsl $1, (%0)") \
    X(lock_xadd, "lock xaddl %%eax, (%0)") X(lock_cmpxchg, "lock cmpxchgl %%ecx, (%0)") \
    X(setz, "setz (%0)") X(two_pages, "addl $1, 4094(%0)")
#define DEFINE(name, code)                                                                              \
    static void form_##name(char *p) {                                                                  \
        __asm__ volatile("movl $7, %%eax; movl $1, %%ecx;" code                                         \
                         : : "r"(p) : "rax", "rbx", "rcx", "rdx", "memory", "cc");                      \
    }
FORMS(DEFINE)
#define ROW(name, code) {#name, form_##name},
static const struct {
    const char *name;
    void (*run)(char *);
} forms[] = {FORMS(ROW)};

static sigjmp_buf back;
static volatile long error_code;
static void on_segv(int number, siginfo_t *info, void *context) {
    (void)number;
    (void)info;
    error_code = (long)((ucontext_t *)context)->uc_mcontext.gregs[REG_ERR];
    siglongjmp(back, 1);
}

static long faults(void) {
    struct rusage usage;
    getrusage(RUSAGE_SELF, &usage);
    return usage.ru_minflt;
}

static char *pages(int prot) {
    char *p = mmap(NULL, 2 * PAGE, prot, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    madvise(p, 2 * PAGE, MADV_NOHUGEPAGE);
    return p;
}

struct work {
    void (*run)(char *);
    char *at;
};
static void *toucher(void *arg) {
    struct work *work = arg;
    work->run(work->at);
    return NULL;
}

/* The faults a userfaultfd reports, and how many were writes. */
static void reported(void (*run)(char *), int *reports, int *writes) {
    char filler[PAGE] = {0};
    char *p = pages(PROT_READ | PROT_WRITE);
    int fd = (int)syscall(SYS_userfaultfd, O_CLOEXEC | O_NONBLOCK | UFFD_USER_MODE_ONLY);
    struct uffdio_api api = {.api = UFFD_API};
    struct uffdio_register range = {.start = (uintptr_t)p, .len = 2 * PAGE, .mode = 1};
    if (fd < 0 || ioctl(fd, UFFDIO_API, &api) || ioctl(fd, UFFDIO_REGISTER, &range)) {
        *reports = *writes = -1;
        return;
    }
    struct work work = {run, p};
    pthread_t thread;
    pthread_create(&thread, NULL, toucher, &work);
    *reports = *writes = 0;
    while (pthread_tryjoin_np(thread, NULL)) {
        struct pollfd ready = {fd, POLLIN, 0};
        struct uffd_msg msg;
        if (poll(&ready, 1, 10) != 1 || read(fd, &msg, sizeof msg) != sizeof msg) continue;
        ++*reports;
        *writes += !!(msg.flags & UFFD_WRITE);
        struct uffdio_copy copy = {.dst = msg.address & ~(uint64_t)(PAGE - 1),
                                   .src = (uintptr_t)filler, .len = PAGE};
        ioctl(fd, UFFDIO_COPY, &copy);
    }
    close(fd);
    munmap(p, 2 * PAGE);
}

int main(void) {
    alarm(30);
    struct sigaction action = {.sa_sigaction = on_segv, .sa_flags = SA_SIGINFO};
    sigaction(SIGSEGV, &action, NULL);
    for (unsigned i = 0; i < sizeof forms / sizeof *forms; i++) {
        /* Once where the pages are there, for the code's own faults. */
        char *p = pages(PROT_READ | PROT_WRITE);
        memset(p, 0, 2 * PAGE);
        forms[i].run(p);
        munmap(p, 2 * PAGE);
        p = pages(PROT_READ | PROT_WRITE);
        long before = faults();
        forms[i].run(p);
        int taken = (int)(faults() - before);
        munmap(p, 2 * PAGE);
        p = pages(PROT_NONE);
        error_code = -1;
        if (!sigsetjmp(back, 1)) forms[i].run(p);
        munmap(p, 2 * PAGE);
        int reports, writes;
        reported(forms[i].run, &reports, &writes);
        printf("%s: faults %d error %ld reported %d writes %d\n", forms[i].name, taken, error_code, reports, writes);
    }
    return 0;
}
