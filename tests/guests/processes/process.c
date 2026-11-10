#define _GNU_SOURCE
#include <cpuid.h>
#include <ucontext.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <link.h>
#include <signal.h>
#include <poll.h>
#include <setjmp.h>
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <stddef.h>
#include <sys/mman.h>
#include <sys/sendfile.h>
#include <sys/resource.h>
#include <sys/vfs.h>
#include <sys/prctl.h>
#include <sys/time.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/msg.h>
#include <grp.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/un.h>
#include <sys/sysinfo.h>
#include <sys/stat.h>
#include <sys/times.h>
#include <sys/utsname.h>
#include <sys/syscall.h>
#include <sys/select.h>
#include <sys/uio.h>
#include <sys/timerfd.h>
#include <sys/wait.h>
#include <unistd.h>
#ifndef F_SETPIPE_SZ
#define F_SETPIPE_SZ 1031
#define F_GETPIPE_SZ 1032
#endif
#ifndef SYS_pidfd_open
#define SYS_pidfd_open 434
#endif
#ifndef SYS_pidfd_send_signal
#define SYS_pidfd_send_signal 424
#endif
#ifndef P_PIDFD
#define P_PIDFD 3
#endif
#ifndef PIDFD_NONBLOCK
#define PIDFD_NONBLOCK O_NONBLOCK
#endif

static void result(const char *name, long value) { printf("%s=%ld\n", name, value); }
static pid_t child(void) { return syscall(SYS_fork); }

/* The namespaces case. Natively every change happens in a child that has
   unshared first, so the host's own namespaces stay as they are. */
#define NS_NEWTIME 0x80
#define NS_SYS_CLONE3 435
#define NS_SYS_SETNS 308
static const char *ns_kinds[] = {"net", "uts", "ipc", "pid", "pid_for_children", "user", "mnt",
                                 "cgroup", "time", "time_for_children"};
/* What /proc/<who>/ns/<kind> reads, or "" with errno set. */
static const char *ns_link(const char *who, const char *kind, char *buf, size_t size) {
    char path[96];
    snprintf(path, sizeof path, "/proc/%s/ns/%s", who, kind);
    ssize_t n = readlink(path, buf, size - 1);
    buf[n < 0 ? 0 : n] = 0;
    return buf;
}
/* Whether a link reads "<name>:[<digits>]", its namespace's kind. */
static int ns_named(const char *link, const char *name) {
    size_t length = strlen(name);
    if (strncmp(link, name, length) || link[length] != ':' || link[length + 1] != '[') return 0;
    const char *digit = link + length + 2;
    if (*digit < '0' || *digit > '9') return 0;
    while (*digit >= '0' && *digit <= '9') digit++;
    return digit[0] == ']' && digit[1] == 0;
}
static int ns_same(const char *who, const char *kind, const char *other_who, const char *other_kind) {
    char a[64], b[64];
    ns_link(who, kind, a, sizeof a);
    ns_link(other_who, other_kind, b, sizeof b);
    return a[0] && !strcmp(a, b);
}
static int ns_open(const char *who, const char *kind) {
    char path[96];
    snprintf(path, sizeof path, "/proc/%s/ns/%s", who, kind);
    return open(path, O_RDONLY | O_CLOEXEC);
}
/* The names as the case started, which are the host's natively and so
   are compared, never printed. */
static struct utsname ns_before;
static void ns_names(const char *label) {
    struct utsname names;
    uname(&names);
    printf("%s: nodename=%s\n", label, names.nodename);
}
static void ns_kept(const char *label) {
    struct utsname names;
    uname(&names);
    printf("%s: kept=%d\n", label,
           !strcmp(names.nodename, ns_before.nodename) && !strcmp(names.domainname, ns_before.domainname));
}
static long ns_setns(int fd, long type) {
    errno = 0;
    long r = syscall(NS_SYS_SETNS, fd, type);
    return r < 0 ? -errno : r;
}
static int ns_spin_go;
static void *ns_spinner(void *unused) {
    (void)unused;
    while (!__atomic_load_n(&ns_spin_go, __ATOMIC_SEQ_CST)) sched_yield();
    return NULL;
}
static char ns_thread_link[64];
static char ns_thread_name[65];
static volatile int ns_thread_done;
static long ns_thread_set;
static int ns_thread(void *unused) {
    (void)unused;
    struct utsname names;
    ns_thread_set = syscall(SYS_sethostname, "thread-host", 11);
    syscall(SYS_uname, &names);
    memcpy(ns_thread_name, names.nodename, sizeof ns_thread_name);
    long n = syscall(SYS_readlink, "/proc/thread-self/ns/uts", ns_thread_link, sizeof ns_thread_link - 1);
    ns_thread_link[n < 0 ? 0 : n] = 0;
    ns_thread_done = 1;
    return 0;
}
static int ns_exit_child(void *unused) {
    (void)unused;
    _exit(0);
}
static int ns_uts_child(void *unused) {
    (void)unused;
    long r = syscall(SYS_sethostname, "clone-host", 10);
    printf("clone-child: sethostname=%ld\n", r);
    ns_names("clone-child");
    fflush(stdout);
    _exit(0);
}
/* The return value of a call and its errno. */
static void outcome(const char *name, long value) {
    printf("%s=%ld errno=%d\n", name, value, value < 0 ? errno : 0);
}


/* Landlock: raw system calls (444 to 446), ABI 8 rights only, which a newer
   kernel shares. */
#define LL_EXECUTE (1ULL << 0)
#define LL_WRITE_FILE (1ULL << 1)
#define LL_READ_FILE (1ULL << 2)
#define LL_READ_DIR (1ULL << 3)
#define LL_REMOVE_DIR (1ULL << 4)
#define LL_REMOVE_FILE (1ULL << 5)
#define LL_MAKE_DIR (1ULL << 7)
#define LL_MAKE_REG (1ULL << 8)
#define LL_MAKE_SOCK (1ULL << 9)
#define LL_MAKE_FIFO (1ULL << 10)
#define LL_MAKE_SYM (1ULL << 12)
#define LL_REFER (1ULL << 13)
#define LL_TRUNCATE (1ULL << 14)
#define LL_IOCTL_DEV (1ULL << 15)
#define LL_FS ((1ULL << 16) - 1)
#define LL_BIND_TCP (1ULL << 0)
#define LL_CONNECT_TCP (1ULL << 1)
struct ll_path_beneath { unsigned long long allowed; int parent_fd; } __attribute__((packed));
struct ll_ruleset_attr { unsigned long long fs, net; };
struct ll_net_port { unsigned long long allowed, port; };
#define LL_SCOPE_ABSTRACT_UNIX (1ULL << 0)
#define LL_SCOPE_SIGNAL (1ULL << 1)
#define LL_LOG_SAME_EXEC_OFF (1U << 0)
#define LL_LOG_NEW_EXEC_ON (1U << 1)
#define LL_LOG_SUBDOMAINS_OFF (1U << 2)
#define LL_TSYNC (1U << 3)
struct ll_scoped_attr { unsigned long long fs, net, scoped; };
/* An open's outcome: 0, or the errno. */
static int ll_open(const char *path, int flags) {
    int fd = open(path, flags, 0600);
    if (fd < 0)
        return errno;
    close(fd);
    return 0;
}
static int ll_call(long r) { return r < 0 ? errno : 0; }
static long ll_net_ruleset(unsigned long long fs, unsigned long long net) {
    struct ll_ruleset_attr attr = {fs, net};
    return syscall(444, &attr, sizeof attr, 0);
}
static long ll_port(long ruleset, unsigned long long port, unsigned long long allowed) {
    struct ll_net_port rule = {allowed, port};
    return syscall(445, ruleset, 2, &rule, 0);
}
static long ll_scoped(unsigned long long fs, unsigned long long scoped) {
    struct ll_scoped_attr attr = {fs, 0, scoped};
    return syscall(444, &attr, sizeof attr, 0);
}
/* A sibling thread for TSYNC: it first enforces a layer of its own that
   handles WRITE_FILE, then waits for a byte, opens `ll_target` for reading
   and `ll_writable` for writing, and reports both errnos. */
static long ll_ruleset(unsigned long long handled);
static const char *ll_target, *ll_writable;
static int ll_go[2], ll_done[2], ll_ready[2];
static void *ll_thread_open(void *unused) {
    (void)unused;
    long own = ll_ruleset(1ULL << 1);
    int r = ll_call(syscall(446, own, 0));
    close(own);
    if (write(ll_ready[1], &r, sizeof r) != sizeof r)
        return NULL;
    char byte;
    if (read(ll_go[0], &byte, 1) != 1)
        return NULL;
    int found[2] = {ll_open(ll_target, O_RDONLY), ll_open(ll_writable, O_WRONLY)};
    if (write(ll_done[1], found, sizeof found) != sizeof found)
        return NULL;
    return NULL;
}
/* What the sibling thread found, after it is told to look. */
static void ll_ask_thread(int found[2]) {
    found[0] = found[1] = -1;
    if (write(ll_go[1], "x", 1) != 1 || read(ll_done[0], found, 2 * sizeof *found) != 2 * sizeof *found)
        found[0] = found[1] = -1;
}
/* A thread that enforces a ruleset scoping signals for itself alone, then
   signals the thread that made it (erratum 2: threads of one process may). */
static pid_t ll_main_tid;
static void *ll_thread_signal(void *out) {
    long r = ll_scoped(0, LL_SCOPE_SIGNAL);
    syscall(446, r, 0);
    close(r);
    *(int *)out = ll_call(syscall(SYS_tgkill, getpid(), ll_main_tid, 0));
    return NULL;
}
static long ll_ruleset(unsigned long long handled) {
    return syscall(444, &handled, sizeof handled, 0);
}
static long ll_rule(long ruleset, const char *path, unsigned long long allowed) {
    struct ll_path_beneath rule = {allowed, open(path, O_PATH | O_CLOEXEC)};
    long r = syscall(445, ruleset, 1, &rule, 0);
    close(rule.parent_fd);
    return r;
}
static long ll_enforce(long ruleset) {
    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    long r = syscall(446, ruleset, 0);
    close(ruleset);
    return r;
}
/* get_mempolicy's mode and first node word, with flags and an address. */
static void policy(const char *name, unsigned long maxnode, void *addr, unsigned long flags) {
    int mode = -1;
    unsigned long nodes[2] = {~0UL, ~0UL};
    errno = 0;
    long r = syscall(SYS_get_mempolicy, &mode, nodes, maxnode, addr, flags);
    printf("%s=%ld errno=%d mode=%d nodes=%#lx next=%#lx\n", name, r, r < 0 ? errno : 0, mode,
           nodes[0], nodes[1]);
}
/* set_mempolicy with the node mask's first word. */
static void set_policy(const char *name, long mode, unsigned long nodes, unsigned long maxnode) {
    unsigned long mask[32] = {nodes};
    outcome(name, syscall(SYS_set_mempolicy, mode, mask, maxnode));
}
static void *policy_thread(void *arg) {
    (void)arg;
    policy("thread-inherits", 65, NULL, 0);
    set_policy("thread-sets", 2, 1, 65);
    return NULL;
}
/* Touching a page that may lie past the end of its mapped file. */
static sigjmp_buf bus_return;
static volatile int bus_code;
static volatile uintptr_t bus_addr;
static void on_bus(int sig, siginfo_t *info, void *context) {
    (void)sig;
    (void)context;
    bus_code = info->si_code;
    bus_addr = (uintptr_t)info->si_addr;
    siglongjmp(bus_return, 1);
}
/* What touching `at` does: its byte, or the SIGBUS code and address. */
static void touch(const char *name, volatile char *at, int write) {
    if (sigsetjmp(bus_return, 1)) {
        printf("%s: sigbus code=%d at=%d\n", name, bus_code, bus_addr == (uintptr_t)at);
        return;
    }
    if (write)
        *at = 'w';
    printf("%s: byte=%d\n", name, *at);
}
static long send_to(int socket, const char *data, size_t len, int flags, const void *address, long address_len) {
    errno = 0;
    return syscall(SYS_sendto, socket, data, len, flags, address, address_len);
}
static long receive_from(int socket, char *buf, size_t len, int flags, void *address, void *address_len) {
    errno = 0;
    return syscall(SYS_recvfrom, socket, buf, len, flags, address, address_len);
}
/* sendmsg of `len` bytes with `count` descriptors in one SCM_RIGHTS message. */
/* recvmsg of at most `len` bytes with `flags`; the descriptor it passes,
   if any, goes to `fd` (else -1), and msg_flags to `got_flags`. */
static long receive_fd(int socket, char *data, size_t len, int flags, int *fd, int *got_flags) {
    struct iovec iov = {data, len};
    union { char bytes[CMSG_SPACE(sizeof(int))]; struct cmsghdr align; } control;
    struct msghdr message = {.msg_iov = &iov, .msg_iovlen = 1, .msg_control = control.bytes,
                             .msg_controllen = sizeof control.bytes};
    errno = 0;
    long n = recvmsg(socket, &message, flags);
    struct cmsghdr *header = n < 0 ? NULL : CMSG_FIRSTHDR(&message);
    *fd = header && header->cmsg_type == SCM_RIGHTS ? *(int *)CMSG_DATA(header) : -1;
    *got_flags = n < 0 ? 0 : message.msg_flags;
    return n;
}
/* What `fd` polls as, for the garbage collector's case. */
static void gc_state(const char *name, int fd) {
    struct pollfd p = {.fd = fd, .events = POLLIN | POLLOUT};
    poll(&p, 1, 0);
    printf("%s revents=%#x\n", name, (unsigned)p.revents);
}
/* An AF_UNIX socket goes, which runs Linux's garbage collector, and a wait
   for it to finish: until `fd` hangs up, for at most 2 seconds, or 200 ms
   with no `fd`. */
static void gc_trigger(int fd) {
    int t[2];
    socketpair(AF_UNIX, SOCK_STREAM, 0, t);
    close(t[0]);
    close(t[1]);
    for (int waited = 0; fd >= 0 && waited < 2000; waited += 10) {
        struct pollfd p = {.fd = fd, .events = POLLIN};
        if (poll(&p, 1, 0) == 1 && p.revents & POLLHUP) return;
        usleep(10000);
    }
    if (fd < 0) usleep(200000);
}
/* An abstract AF_UNIX address for `name`, this process's own, into `a`;
   its length. */
static socklen_t unix_abstract(struct sockaddr_un *a, const char *name) {
    memset(a, 0, sizeof *a);
    a->sun_family = AF_UNIX;
    int n = snprintf(a->sun_path + 1, sizeof a->sun_path - 1, "paludarium-%d-%s", getpid(), name);
    return (socklen_t)(sizeof(sa_family_t) + 1 + n);
}
static void unix_call(const char *name, long r) {
    printf("%s=%ld errno=%d\n", name, r, r < 0 ? errno : 0);
    errno = 0;
}
/* A socket's name or its peer's: whether it is `want`'s, or its length. */
static void unix_name(const char *name, int fd, int peer, const struct sockaddr_un *want, socklen_t want_len) {
    struct sockaddr_un a;
    memset(&a, 0x55, sizeof a);
    socklen_t len = sizeof a;
    long r = peer ? getpeername(fd, (void *)&a, &len) : getsockname(fd, (void *)&a, &len);
    /* A name holds this process's ID, so only an unnamed one's length is
       printed. */
    printf("%s=%ld errno=%d family=%d", name, r, r < 0 ? errno : 0, a.sun_family);
    if (r == 0 && want) printf(" same=%d", len == want_len && !memcmp(&a, want, len));
    else if (r == 0) printf(" len=%u", (unsigned)len);
    printf("\n");
    errno = 0;
}
static void unix_poll(const char *name, int fd) {
    struct pollfd p = {.fd = fd, .events = POLLIN | POLLOUT | POLLRDHUP};
    poll(&p, 1, 0);
    printf("%s revents=%#x\n", name, (unsigned)p.revents);
}
/* Receives a datagram on `fd` with recvfrom, `room` bytes for the address:
   its length and data, and whether the address is `want`'s, or the length
   of an unnamed one. */
static void unix_from(const char *name, int fd, socklen_t room, const struct sockaddr_un *want, socklen_t want_len) {
    struct sockaddr_un from;
    char buf[16];
    memset(&from, 0x55, sizeof from);
    socklen_t len = room;
    long n = recvfrom(fd, buf, sizeof buf, MSG_DONTWAIT, (void *)&from, &len);
    printf("%s=%ld errno=%d data=%.*s", name, n, n < 0 ? errno : 0, n > 0 ? (int)n : 0, buf);
    if (n >= 0 && want)
        printf(" same=%d", len == want_len && !memcmp(&from, want, room < want_len ? room : want_len));
    else if (n >= 0) printf(" len=%u", (unsigned)len);
    printf(" untouched=%d\n", room < sizeof from && ((unsigned char *)&from)[room] == 0x55);
    errno = 0;
}
/* Whether descriptors `a` and `b` are the same file. */
static int same_file(int a, int b) {
    struct stat x, y;
    return a >= 0 && b >= 0 && !fstat(a, &x) && !fstat(b, &y) && x.st_ino == y.st_ino && x.st_dev == y.st_dev;
}
static long send_fds(int socket, const char *data, size_t len, const int *fds, int count) {
    struct iovec iov = {(void *)data, len};
    union { char bytes[CMSG_SPACE(sizeof(int) * 4)]; struct cmsghdr align; } control;
    struct msghdr message = {.msg_iov = &iov, .msg_iovlen = 1};
    if (count) {
        message.msg_control = control.bytes;
        message.msg_controllen = CMSG_SPACE(sizeof(int) * count);
        struct cmsghdr *header = CMSG_FIRSTHDR(&message);
        header->cmsg_level = SOL_SOCKET;
        header->cmsg_type = SCM_RIGHTS;
        header->cmsg_len = CMSG_LEN(sizeof(int) * count);
        memcpy(CMSG_DATA(header), fds, sizeof(int) * count);
    }
    errno = 0;
    return sendmsg(socket, &message, 0);
}
/* Sends `data` on `socket` from a child after `ms` milliseconds; the
   caller reaps it. */
static pid_t send_later(int socket, const char *data, int ms) {
    fflush(stdout);
    pid_t pid = fork();
    if (pid == 0) {
        usleep(ms * 1000);
        send(socket, data, strlen(data), 0);
        _exit(0);
    }
    return pid;
}
#ifndef SIOCINQ
#define SIOCINQ FIONREAD
#endif
#ifndef SIOCOUTQ
#define SIOCOUTQ TIOCOUTQ
#endif
/* fionread: ioctl `request` of `fd` with an int, and what it gave. */
static void ioctl_int(const char *name, int fd, unsigned long request) {
    int value = -7;
    errno = 0;
    int r = ioctl(fd, request, &value);
    printf("  %s=%d errno=%d value=%d\n", name, r, errno, value);
}
#ifndef FIGETBSZ
#define FIGETBSZ _IO(0x00, 2)
#endif
#ifndef FIOQSIZE
#define FIOQSIZE 0x5460
#endif
/* generic-ioctl: the descriptor flag and the status flags of `fd` after
   ioctl `request` with the int `value`. */
static void ioctl_flags(const char *name, int fd, unsigned long request, int value) {
    errno = 0;
    int r = ioctl(fd, request, &value);
    int e = errno;
    printf("  %s=%d errno=%d cloexec=%d nonblock=%d async=%d\n", name, r, e,
           fcntl(fd, F_GETFD) & FD_CLOEXEC, !!(fcntl(fd, F_GETFL) & O_NONBLOCK),
           !!(fcntl(fd, F_GETFL) & O_ASYNC));
}
/* setsockopt of the int SOL_SOCKET option `opt` to `value` with `size`
   bytes, then what getsockopt reads back. */
static void int_option(const char *name, int fd, int opt, int value, socklen_t size) {
    errno = 0;
    long n = setsockopt(fd, SOL_SOCKET, opt, &value, size);
    int e = n < 0 ? errno : 0;
    int got = -7;
    socklen_t len = sizeof got;
    getsockopt(fd, SOL_SOCKET, opt, &got, &len);
    printf("  set %s %d=%ld errno=%d got=%d\n", name, value, n, e, got);
}
/* proc-block-size: what a path's stat, lstat, statx and statfs give for
   its block size, and statfs its type. */
static void path_block_size(const char *name, const char *path) {
    struct stat st = {0}, link = {0};
    /* statx itself, which musl before 1.2.5 has no wrapper for:
       stx_blksize is the u32 at 4. */
    unsigned char sx[256] = {0};
    struct statfs fs = {0};
    errno = 0;
    int s = stat(path, &st);
    int se = errno;
    errno = 0;
    int l = lstat(path, &link);
    int le = errno;
    errno = 0;
    int x = (int)syscall(SYS_statx, AT_FDCWD, path, 0, 0x7ff, sx);
    unsigned blksize;
    memcpy(&blksize, sx + 4, sizeof blksize);
    int xe = errno;
    errno = 0;
    int f = statfs(path, &fs);
    int fe = errno;
    printf("  %s: stat=%d/%d %ld lstat=%d/%d %ld statx=%d/%d %u statfs=%d/%d %#lx %ld\n", name, s, se,
           (long)st.st_blksize, l, le, (long)link.st_blksize, x, xe, blksize, f, fe,
           (unsigned long)fs.f_type, (long)fs.f_bsize);
}
/* proc-block-size: the same through a descriptor: fstat, FIGETBSZ and
   fstatfs. */
static void descriptor_block_size(const char *name, int fd) {
    struct stat st = {0};
    struct statfs fs = {0};
    int block = -7;
    errno = 0;
    int s = fstat(fd, &st);
    int se = errno;
    errno = 0;
    int b = ioctl(fd, FIGETBSZ, &block);
    int be = errno;
    errno = 0;
    int f = fstatfs(fd, &fs);
    int fe = errno;
    printf("  %s: fstat=%d/%d %ld figetbsz=%d/%d %d fstatfs=%d/%d %#lx %ld\n", name, s, se, (long)st.st_blksize, b,
           be, block, f, fe, (unsigned long)fs.f_type, (long)fs.f_bsize);
}
/* socket-timestamp: the option numbers, as x86-64 Linux has them. */
#define TS_OLD 29
#define TS_NS_OLD 35
#define TS_NEW 63
#define TS_NS_NEW 64
/* socket-timestamping: SO_TIMESTAMPING and its _NEW form. */
#define TSG_OLD 37
#define TSG_NEW 65
/* Both forms of SO_TIMESTAMPING as getsockopt reads them: the flags, the
   PTP clock and the length. */
static void stamping_options(const char *name, int fd) {
    const int names[] = {TSG_OLD, TSG_NEW};
    printf("  %s:", name);
    for (int i = 0; i < 2; i++) {
        int got[2] = {-7, -7};
        socklen_t len = sizeof got;
        errno = 0;
        int r = getsockopt(fd, SOL_SOCKET, names[i], got, &len);
        printf(" [%d errno=%d %#x %d len=%u]", r, r ? errno : 0, got[0], got[1], (unsigned)len);
    }
    printf("\n");
}
/* setsockopt(SO_TIMESTAMPING or its _NEW form) with `flags`, as an int of
   `size` bytes. */
static void stamping_option(const char *name, int fd, int opt, int flags, socklen_t size) {
    errno = 0;
    int r = setsockopt(fd, SOL_SOCKET, opt, &flags, size);
    printf("  set %s %#x=%d errno=%d\n", name, flags, r, r ? errno : 0);
}
/* The four timestamp options as getsockopt reads them. */
static void timestamp_options(const char *name, int fd) {
    const int names[] = {TS_OLD, TS_NS_OLD, TS_NEW, TS_NS_NEW};
    printf("  %s:", name);
    for (int i = 0; i < 4; i++) {
        int got = -7;
        socklen_t len = sizeof got;
        getsockopt(fd, SOL_SOCKET, names[i], &got, &len);
        printf(" %d", got);
    }
    printf("\n");
}
static long long real_ns(void) {
    struct timespec t;
    clock_gettime(CLOCK_REALTIME, &t);
    return t.tv_sec * 1000000000LL + t.tv_nsec;
}
/* recvmsg with `room` bytes of control (none at all for 0) and `flags`:
   what came, CTRUNC, msg_controllen, and each control message's type and
   length, and for a timestamp where it falls against the real times
   `sent` (taken after the send) and `asked` (before this call), and
   whether its fraction fits its unit. The last timestamp's nanoseconds go
   to `*stamp`. */
static void receive_stamped(const char *name, int fd, size_t room, int flags, long long sent,
                            long long *stamp) {
    char data[8] = {0};
    union { char bytes[256]; struct cmsghdr align; } control;
    memset(control.bytes, 0, sizeof control.bytes);
    struct iovec iov = {data, sizeof data};
    struct msghdr message = {.msg_iov = &iov, .msg_iovlen = 1,
                             .msg_control = room ? control.bytes : NULL, .msg_controllen = room};
    long long asked = real_ns();
    errno = 0;
    long n = recvmsg(fd, &message, flags);
    printf("  %s=%ld errno=%d ctrunc=%d controllen=%zu", name, n, n < 0 ? errno : 0,
           n >= 0 && (message.msg_flags & MSG_CTRUNC) != 0, n >= 0 ? (size_t)message.msg_controllen : 0);
    if (n >= 0 && room)
        for (struct cmsghdr *h = CMSG_FIRSTHDR(&message); h; h = CMSG_NXTHDR(&message, h)) {
            printf(" [%d len=%zu", h->cmsg_type, (size_t)h->cmsg_len);
            int ts = h->cmsg_type == TS_OLD || h->cmsg_type == TS_NEW;
            int ns = h->cmsg_type == TS_NS_OLD || h->cmsg_type == TS_NS_NEW;
            if ((ts || ns) && h->cmsg_len >= CMSG_LEN(16)) {
                long long v[2];
                memcpy(v, CMSG_DATA(h), sizeof v);
                long long unit = ts ? 1000 : 1, at = v[0] * 1000000000LL + v[1] * unit;
                /* A timeval holds microseconds: compare in them. */
                long long a = at / unit, s = sent / unit, q = asked / unit;
                printf(" %s fits=%d", a <= s ? "sent" : a >= q ? "read" : "between",
                       v[1] >= 0 && v[1] < 1000000000LL / unit);
                if (stamp) *stamp = at;
            }
            if ((h->cmsg_type == TSG_OLD || h->cmsg_type == TSG_NEW) && h->cmsg_len >= CMSG_LEN(48)) {
                long long v[6];
                memcpy(v, CMSG_DATA(h), sizeof v);
                long long at = v[0] * 1000000000LL + v[1];
                printf(" %s fits=%d rest=%d", at <= sent ? "sent" : at >= asked ? "read" : "between",
                       v[1] >= 0 && v[1] < 1000000000LL, !(v[2] | v[3] | v[4] | v[5]));
            }
            printf("]");
        }
    printf("\n");
}
/* recvmsg of at most `len` bytes with `flags`: what came, msg_flags, the
   socket's SO_PEEK_OFF after it, and whether it waited 700 ms or more, which
   a call that does not wait never takes, even on a slow emulated run.
   The time counts from `from` where given: a test host's clock moves at
   once by a child's sleep, which may come before the call starts. */
static void receive_waited_from(const char *name, int fd, size_t len, int flags,
                                const struct timespec *from) {
    char data[16] = {0};
    struct iovec iov = {data, len};
    struct msghdr message = {.msg_iov = &iov, .msg_iovlen = 1};
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    if (from) t0 = *from;
    errno = 0;
    long n = recvmsg(fd, &message, flags);
    int e = n < 0 ? errno : 0;
    clock_gettime(CLOCK_MONOTONIC, &t1);
    long ms = (t1.tv_sec - t0.tv_sec) * 1000 + (t1.tv_nsec - t0.tv_nsec) / 1000000;
    int offset = -7;
    socklen_t size = sizeof offset;
    getsockopt(fd, SOL_SOCKET, SO_PEEK_OFF, &offset, &size);
    printf("  %s=%ld errno=%d data=%.*s flags=%#x off=%d waited=%d\n", name, n, e,
           n > 0 ? (int)(n < (long)len ? n : (long)len) : 0, data, n < 0 ? 0 : message.msg_flags, offset, ms >= 700);
}
static void receive_waited(const char *name, int fd, size_t len, int flags) {
    receive_waited_from(name, fd, len, flags, NULL);
}
/* The child whose messages socket-credentials receives. */
static pid_t credentials_child;
/* A process ID as socket-credentials prints it, free of the IDs a run
   gets: this process, its child, or the number (0 for none). */
static void print_pid(const char *name, pid_t pid) {
    if (pid == getpid())
        printf(" %s=self", name);
    else if (pid == credentials_child && pid)
        printf(" %s=child", name);
    else
        printf(" %s=%d", name, pid);
}
/* A user or group ID: this process's own, or the number (65534 for none). */
static void print_id(const char *name, unsigned id, unsigned own) {
    if (id == own)
        printf(" %s=own", name);
    else
        printf(" %s=%u", name, id);
}
#ifndef SO_PASSPIDFD
#define SO_PASSPIDFD 76
#endif
#ifndef SO_PASSRIGHTS
#define SO_PASSRIGHTS 83
#endif
/* socket-passrights: a sendmsg of `len` bytes of `data` with `flags`,
   passing `fd` unless it is negative; prints what it returns. */
static void rights_send(const char *name, int socket, const char *data, size_t len, int flags, int fd) {
    struct iovec iov = {(void *)data, len};
    union { char bytes[CMSG_SPACE(sizeof(int))]; struct cmsghdr align; } control;
    struct msghdr message = {.msg_iov = &iov, .msg_iovlen = 1};
    if (fd >= 0) {
        message.msg_control = control.bytes;
        message.msg_controllen = sizeof control.bytes;
        struct cmsghdr *header = CMSG_FIRSTHDR(&message);
        header->cmsg_level = SOL_SOCKET;
        header->cmsg_type = SCM_RIGHTS;
        header->cmsg_len = CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(header), &fd, sizeof fd);
    }
    errno = 0;
    long n = sendmsg(socket, &message, flags | MSG_NOSIGNAL | MSG_DONTWAIT);
    printf("  %s: sent=%ld errno=%d\n", name, n, n < 0 ? errno : 0);
}
/* socket-passrights: a recvmsg of up to 8 bytes with `flags`; prints the
   bytes and how many descriptors came, which it closes. */
static void rights_receive(const char *name, int socket, int flags) {
    char data[8];
    struct iovec iov = {data, sizeof data};
    union { char bytes[CMSG_SPACE(sizeof(int) * 4)]; struct cmsghdr align; } control;
    struct msghdr message = {.msg_iov = &iov, .msg_iovlen = 1, .msg_control = control.bytes,
                             .msg_controllen = sizeof control.bytes};
    errno = 0;
    long n = recvmsg(socket, &message, flags | MSG_DONTWAIT);
    int fds = 0;
    if (n >= 0)
        for (struct cmsghdr *h = CMSG_FIRSTHDR(&message); h; h = CMSG_NXTHDR(&message, h))
            if (h->cmsg_level == SOL_SOCKET && h->cmsg_type == SCM_RIGHTS)
                for (size_t at = 0; CMSG_LEN(at) < h->cmsg_len; at += sizeof(int)) {
                    int fd;
                    memcpy(&fd, CMSG_DATA(h) + at, sizeof fd);
                    close(fd);
                    fds++;
                }
    printf("  %s: n=%ld errno=%d data=%.*s fds=%d flags=%#x\n", name, n, n < 0 ? errno : 0,
           n > 0 ? (int)n : 0, data, fds, message.msg_flags);
}
/* socket-passsec: the flags that a socket a listener accepts takes from
   it, as getsockopt reads them: SO_PASSCRED, SO_PASSSEC, SO_PASSPIDFD. */
static void passing(const char *name, int fd) {
    const int names[] = {SO_PASSCRED, SO_PASSSEC, SO_PASSPIDFD};
    printf("  %s:", name);
    for (int i = 0; i < 3; i++) {
        int got = -7;
        socklen_t len = sizeof got;
        errno = 0;
        long n = getsockopt(fd, SOL_SOCKET, names[i], &got, &len);
        printf(" %ld/%d/%d", n, n < 0 ? errno : 0, got);
    }
    printf("\n");
}
/* socket-passsec: a recvmsg of one byte with `room` bytes of control
   buffer (none for 0): what it returns, its flags, how much control it
   used and the control messages' types. */
static void passsec_receive(const char *name, int fd, size_t room) {
    char byte, control[256];
    struct iovec iov = {&byte, 1};
    struct msghdr m = {0};
    m.msg_iov = &iov;
    m.msg_iovlen = 1;
    m.msg_control = room ? control : NULL;
    m.msg_controllen = room;
    errno = 0;
    long n = recvmsg(fd, &m, MSG_DONTWAIT);
    printf("  %s: n=%ld errno=%d flags=%#x controllen=%zu", name, n, n < 0 ? errno : 0,
           m.msg_flags, (size_t)m.msg_controllen);
    if (room)
        for (struct cmsghdr *h = CMSG_FIRSTHDR(&m); h; h = CMSG_NXTHDR(&m, h))
            printf(" [%d %d len=%zu]", h->cmsg_level, h->cmsg_type, (size_t)h->cmsg_len);
    printf("\n");
}
#ifndef SO_PEERPIDFD
#define SO_PEERPIDFD 77
#endif
#ifndef SCM_PIDFD
#define SCM_PIDFD 4
#endif
/* socket-pidfd: the lowest descriptor number free now. */
static int lowest_free(void) {
    int fd = dup(0);
    close(fd);
    return fd;
}
/* socket-pidfd: what a pidfd is: close-on-exec, signalable, and whether
   its process has exited (readable). The rest, as numbers or kinds. */
static void pidfd_kind(int fd) {
    struct pollfd p = {fd, POLLIN, 0};
    printf(" cloexec=%d signal=%ld exited=%d", fcntl(fd, F_GETFD) & FD_CLOEXEC,
           syscall(SYS_pidfd_send_signal, fd, 0, NULL, 0), poll(&p, 1, 0) == 1);
}
/* socket-pidfd: receives one byte with a control buffer of `room` bytes
   (none for 0) and prints its control messages in order: SCM_PIDFD's with
   what the pidfd is (pidfd_kind), or the negative errno it carries. The
   pidfds are closed after. */
static void pidfd_received(const char *name, int fd, size_t room) {
    char data[8];
    union { struct cmsghdr align; char bytes[256]; } control;
    struct iovec iov = {data, sizeof data};
    struct msghdr m = {.msg_iov = &iov, .msg_iovlen = 1, .msg_control = room ? control.bytes : NULL,
                       .msg_controllen = room};
    int before = lowest_free();
    errno = 0;
    long n = recvmsg(fd, &m, MSG_DONTWAIT);
    printf("  %s=%ld errno=%d flags=%#x:", name, n, n < 0 ? errno : 0, (unsigned)m.msg_flags);
    int opened[8], count = 0;
    for (struct cmsghdr *c = CMSG_FIRSTHDR(&m); c; c = CMSG_NXTHDR(&m, c)) {
        if (c->cmsg_type == SCM_PIDFD && c->cmsg_len >= CMSG_LEN(sizeof(int))) {
            int pidfd;
            memcpy(&pidfd, CMSG_DATA(c), sizeof pidfd);
            printf(" [pidfd");
            if (pidfd >= 0) {
                pidfd_kind(pidfd);
                if (count < 8) opened[count++] = pidfd;
            } else {
                printf(" error=%d", pidfd);
            }
            printf("]");
        } else {
            printf(" [%s len=%u]", c->cmsg_type == SCM_CREDENTIALS ? "credentials" : c->cmsg_type == SCM_RIGHTS ? "rights" : "other",
                   (unsigned)c->cmsg_len);
            if (c->cmsg_type == SCM_RIGHTS && count < 8) memcpy(&opened[count++], CMSG_DATA(c), sizeof(int));
        }
    }
    /* A pidfd whose message did not fit is still installed. */
    printf(" installed=%d\n", lowest_free() != before);
    for (int i = 0; i < count; i++) close(opened[i]);
    if (lowest_free() != before) close(before);
}
/* sendmsg of `data` with one SCM_CREDENTIALS message of `pid`, `uid` and
   `gid`, whose cmsg_len is `cmsg_len`. */
static long send_credentials(int socket, const char *data, pid_t pid, uid_t uid, gid_t gid, size_t cmsg_len) {
    struct iovec iov = {(void *)data, strlen(data)};
    union { char bytes[CMSG_SPACE(sizeof(struct ucred))]; struct cmsghdr align; } control;
    memset(&control, 0, sizeof control);
    struct msghdr message = {.msg_iov = &iov, .msg_iovlen = 1, .msg_control = control.bytes,
                             .msg_controllen = sizeof control.bytes};
    struct cmsghdr *header = CMSG_FIRSTHDR(&message);
    header->cmsg_level = SOL_SOCKET;
    header->cmsg_type = SCM_CREDENTIALS;
    header->cmsg_len = cmsg_len;
    struct ucred credentials = {pid, uid, gid};
    memcpy(CMSG_DATA(header), &credentials, sizeof credentials);
    errno = 0;
    return sendmsg(socket, &message, 0);
}
/* recvmsg of at most 8 bytes with `room` control bytes (no buffer for 0)
   and `flags`, without waiting; prints the data, msg_flags, msg_controllen
   and each control message, as much of its credentials as it holds, and
   whether its descriptors are open, which it then closes. */
static void receive_credentials(int socket, size_t room, int flags) {
    char data[8] = {0};
    struct iovec iov = {data, sizeof data};
    union { char bytes[128]; struct cmsghdr align; } control;
    memset(&control, 0x55, sizeof control);
    struct msghdr message = {.msg_iov = &iov, .msg_iovlen = 1, .msg_control = room ? control.bytes : NULL,
                             .msg_controllen = room};
    errno = 0;
    long n = recvmsg(socket, &message, flags | MSG_DONTWAIT);
    printf("  recv=%ld errno=%d data=%.*s flags=%#x controllen=%zu", n, n < 0 ? errno : 0, n > 0 ? (int)n : 0, data,
           n < 0 ? 0 : message.msg_flags, n < 0 ? 0 : (size_t)message.msg_controllen);
    size_t at = 0;
    while (n >= 0 && at + sizeof(struct cmsghdr) <= message.msg_controllen) {
        struct cmsghdr *header = (struct cmsghdr *)(control.bytes + at);
        size_t len = header->cmsg_len;
        printf(" [%d,%d,%zu", header->cmsg_level, header->cmsg_type, len);
        if (header->cmsg_type == SCM_CREDENTIALS) {
            struct ucred credentials;
            memcpy(&credentials, CMSG_DATA(header), sizeof credentials);
            if (len >= CMSG_LEN(4))
                print_pid("pid", credentials.pid);
            if (len >= CMSG_LEN(8))
                print_id("uid", credentials.uid, getuid());
            if (len >= CMSG_LEN(12))
                print_id("gid", credentials.gid, getgid());
        } else if (header->cmsg_type == SCM_RIGHTS) {
            for (size_t i = 0; len >= CMSG_LEN(4 * (i + 1)); i++) {
                int fd;
                memcpy(&fd, CMSG_DATA(header) + 4 * i, sizeof fd);
                printf(" open=%d", fcntl(fd, F_GETFD) >= 0);
                close(fd);
            }
        }
        printf("]");
        if (len < sizeof(struct cmsghdr))
            break;
        at += CMSG_ALIGN(len);
    }
    putchar('\n');
}
/* Sends `data` from a child of this process, which then exits. */
static void send_from_child(int socket, const char *data) {
    fflush(stdout);
    pid_t pid = fork();
    if (pid == 0) {
        send(socket, data, strlen(data), 0);
        _exit(0);
    }
    credentials_child = pid;
    waitpid(pid, NULL, 0);
}
/* recvmsg into `len` bytes with `room` control bytes (no buffer for 0);
   prints what came, the descriptors as offsets from `base` with their
   close-on-exec flags, and keeps the first one in *first. */
static void receive_fds(const char *name, int socket, size_t len, size_t room, int flags, int base, int *first) {
    char data[16] = {0};
    struct iovec iov = {data, len};
    union { char bytes[64]; struct cmsghdr align; } control;
    struct sockaddr_storage address;
    struct msghdr message = {.msg_name = &address, .msg_namelen = sizeof address, .msg_iov = &iov, .msg_iovlen = 1,
                             .msg_control = room ? control.bytes : NULL, .msg_controllen = room, .msg_flags = 0x1234};
    errno = 0;
    long got = recvmsg(socket, &message, flags);
    printf("%s=%ld errno=%d namelen=%d flags=%#x controllen=%zu data=%.*s", name, got, errno,
           message.msg_namelen, message.msg_flags, (size_t)message.msg_controllen, got > 0 ? (int)got : 0, data);
    if (got >= 0)
        for (struct cmsghdr *header = CMSG_FIRSTHDR(&message); header; header = CMSG_NXTHDR(&message, header)) {
            printf(" [%zu %d %d", (size_t)header->cmsg_len, header->cmsg_level, header->cmsg_type);
            for (size_t at = 0; CMSG_LEN(at) < header->cmsg_len; at += sizeof(int)) {
                int fd;
                memcpy(&fd, CMSG_DATA(header) + at, sizeof fd);
                printf(" +%d cloexec=%d", fd - base, fcntl(fd, F_GETFD));
                if (first && at == 0) *first = fd;
            }
            printf("]");
        }
    printf("\n");
}
/* sendmsg with a hand-made control buffer or address; prints the result. */
static void send_raw(const char *name, int socket, void *address, socklen_t address_len, void *control, size_t control_len) {
    struct iovec iov = {"z", 1};
    struct msghdr message = {.msg_name = address, .msg_namelen = address_len, .msg_iov = &iov, .msg_iovlen = 1,
                             .msg_control = control, .msg_controllen = control_len};
    errno = 0;
    long sent = sendmsg(socket, &message, 0);
    printf("%s=%ld errno=%d\n", name, sent, errno);
}
/* What a member of an orphaned process group received: bit 0 SIGHUP,
   bit 1 SIGCONT, bit 2 SIGHUP from the kernel (SI_KERNEL, no sender). */
static volatile sig_atomic_t hangup_flags;
static void hangup_seen(int number, siginfo_t *info, void *context) {
    (void)context;
    if (number == SIGHUP) hangup_flags |= 1 | (info->si_code == SI_KERNEL && info->si_pid == 0 ? 4 : 0);
    if (number == SIGCONT) hangup_flags |= 2;
    if (number == SIGUSR1) _exit(hangup_flags);
}
/* Watches for the signals, stops itself if asked, and exits with what came. */
static void hangup_member(int stop, int ready) {
    struct sigaction action = {.sa_sigaction = hangup_seen, .sa_flags = SA_SIGINFO};
    sigaction(SIGHUP, &action, NULL);
    sigaction(SIGCONT, &action, NULL);
    sigaction(SIGUSR1, &action, NULL);
    if (write(ready, "x", 1) != 1) _exit(70);
    if (stop) {
        /* Not raise(): after a raw fork musl's cached tid is the parent's. */
        kill(getpid(), SIGSTOP);
        for (int tries = 0; hangup_flags != 7 && tries < 1000; tries++) sched_yield();
        _exit(hangup_flags);
    }
    for (;;) pause();
}
static int thread_ready[2], thread_block[2];
static int discard_go[2], discard_done[2];
/* Reports whether SIGUSR2 is pending for this thread, before and after the
   main thread makes it ignored. */
static void *discard_reader(void *unused) {
    (void)unused;
    char byte;
    sigset_t pending;
    for (int round = 0; round < 2; round++) {
        if (read(discard_go[0], &byte, 1) != 1) return NULL;
        sigpending(&pending);
        result(round ? "thread-after" : "thread-before", sigismember(&pending, SIGUSR2));
        fflush(stdout);
        if (write(discard_done[1], "x", 1) != 1) return NULL;
    }
    return NULL;
}
static volatile sig_atomic_t received;
static void interrupted(int number) { (void)number; received++; }
/* wait-restart: the handler answers the child once the parent waits. */
static volatile sig_atomic_t wait_started;
static int wait_answer = -1;
static void wait_signalled(int number) {
    (void)number;
    received++;
    if (wait_started && write(wait_answer, "a", 1) != 1) received = -100;
}
/* signal-io: takes the queued SIGIO, SIGURG and SIGRTMIN+5 that the mode
   keeps blocked, oldest first within each, and prints them. */
#define IO_RT (SIGRTMIN + 5)
static void io_taken(const char *name) {
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGIO);
    sigaddset(&set, SIGURG);
    sigaddset(&set, IO_RT);
    struct timespec zero = {0, 0};
    siginfo_t info;
    int number;
    printf("  %s:", name);
    while ((number = sigtimedwait(&set, &info, &zero)) > 0)
        printf(" [%s code=%d band=%#lx fd=%d]", number == SIGIO ? "io" : number == SIGURG ? "urg" : "rt",
               info.si_code, (long)info.si_band, info.si_fd);
    printf("\n");
}
/* Counts the queued IO_RT signals with code `code` and takes the rest. */
static int io_count(int code) {
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, IO_RT);
    struct timespec zero = {0, 0};
    siginfo_t info;
    int count = 0;
    while (sigtimedwait(&set, &info, &zero) > 0) count += info.si_code == code;
    return count;
}
/* F_GETOWN, named rather than printed, so the output keeps no IDs. */
static const char *io_owner(int fd) {
    int owner = fcntl(fd, F_GETOWN);
    return owner == 0 ? "none" : owner == getpid() ? "self" : owner == -getpgrp() ? "group" : "other";
}
/* Waits a while, in a way that a test host's clock, which a sleep moves
   at once, cannot skip: the sleep for Linux, the loop for the emulator. */
static void io_pause(void) {
    usleep(100000);
    for (volatile long k = 0; k < 500000; k++) {}
}
static void io_async(int fd, int number) {
    fcntl(fd, F_SETOWN, getpid());
    fcntl(fd, F_SETSIG, number);
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_ASYNC);
}
/* signal-restart: SIGALRM feeds the call it interrupts, writing a byte
   to restart_fd or, with restart_drain, emptying it, so that a restarted
   call ends at once. */
static int restart_fd = -1, restart_drain;
static void restart_feed(int number) {
    (void)number;
    received++;
    static char sink[4096];
    if (restart_drain) {
        while (read(restart_fd, sink, sizeof sink) > 0) {}
    } else if (restart_fd >= 0 && write(restart_fd, "x", 1) != 1) {
        received = -100;
    }
}
/* Fills `fd` until a write of one byte would block, then makes it block. */
static void restart_fill(int fd) {
    static char chunk[4096];
    fcntl(fd, F_SETFL, O_NONBLOCK);
    while (write(fd, chunk, sizeof chunk) > 0) {}
    while (write(fd, chunk, 1) > 0) {}
    fcntl(fd, F_SETFL, 0);
}
static volatile sig_atomic_t usr2_blocked_in_handler = -1;
static void note_mask(int number) {
    (void)number;
    sigset_t now;
    sigprocmask(SIG_BLOCK, NULL, &now);
    usr2_blocked_in_handler = sigismember(&now, SIGUSR2);
    received++;
}
/* A child that sends `number` to its parent every 20 ms until killed. */
static pid_t pester(int number) {
    pid_t parent = getpid(), pid = child();
    if (pid == 0) {
        struct timespec nap = {0, 20000000};
        for (;;) {
            kill(parent, number);
            nanosleep(&nap, NULL);
        }
    }
    return pid;
}
static int vm_value;
static int vm_child(void *unused) { (void)unused; vm_value = 23; return 4; }
/* CLONE_SIGHAND children: one installs a SIGUSR1 handler, one execs. */
static int sighand_child(void *unused) {
    (void)unused;
    struct sigaction action = {0};
    action.sa_handler = interrupted;
    return sigaction(SIGUSR1, &action, NULL) ? 1 : 5;
}
static char *sighand_self;
static int sighand_exec(void *unused) {
    (void)unused;
    char *args[] = { "process", "sighand-exec-child", sighand_self, NULL };
    char *env[] = { NULL };
    execve(sighand_self, args, env);
    return 92;
}
static void *blocked_sibling(void *unused) {
    (void)unused;
    char byte;
    if (write(thread_ready[1], "x", 1) != 1) _exit(85);
    read(thread_block[0], &byte, 1);
    _exit(84);
}
static char thread_name[16];
static void *name_reader(void *unused) {
    (void)unused;
    prctl(PR_GET_NAME, thread_name);
    prctl(PR_SET_NAME, "worker");
    return NULL;
}
/* The kernel's struct sigevent, with the SIGEV_THREAD_ID target. */
struct thread_event { long value; int signo; int notify; int tid; int pad[11]; };
static int timer_report[2];
static void *timer_waiter(void *unused) {
    (void)unused;
    int tid = syscall(SYS_gettid);
    write(timer_report[1], &tid, sizeof tid);
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGUSR1);
    siginfo_t info;
    int got[3] = {sigwaitinfo(&set, &info), info.si_code, info.si_value.sival_int};
    write(timer_report[1], got, sizeof got);
    return NULL;
}
static int tid_report[2], tid_release[2];
static void *parked(void *unused) {
    (void)unused;
    int tid = syscall(SYS_gettid);
    write(tid_report[1], &tid, sizeof tid);
    char byte;
    read(tid_release[0], &byte, 1);
    return NULL;
}
/* A child that exits with `code` once a byte arrives on `gate`. */
static pid_t gated(int gate[2], int code) {
    pipe(gate);
    pid_t pid = child();
    if (pid == 0) {
        char byte;
        close(gate[1]);
        read(gate[0], &byte, 1);
        _exit(code);
    }
    close(gate[0]);
    return pid;
}
struct clone3_args { unsigned long long flags, pidfd, child_tid, parent_tid, exit_signal, stack, stack_size, tls; };
static long clone3(void *args, unsigned long size) { return syscall(435, args, size); }
static long clone3_error(struct clone3_args args) {
    errno = 0;
    long r = clone3(&args, sizeof args);
    if (r == 0) _exit(99);
    return r < 0 ? -errno : 1000;
}
static int reaped(long pid) {
    int status = 0;
    waitpid(pid, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}
/* The pid-set-tid case: clone3 with `flags`, `exit_signal` and the numbers
   `tids` of set_tid, from the innermost PID namespace out. The child's PID,
   0 in the child, or -errno. */
static long settid_clone(unsigned long long flags, int exit_signal, const pid_t *tids, int count) {
    struct {
        unsigned long long flags, pidfd, child_tid, parent_tid, exit_signal, stack, stack_size, tls, set_tid,
            set_tid_size;
    } args = {flags, 0, 0, 0, (unsigned)exit_signal, 0, 0, 0, (unsigned long)tids, (unsigned)count};
    fflush(stdout);
    errno = 0;
    long r = syscall(435, &args, sizeof args);
    return r < 0 ? -errno : r;
}
/* An error of settid_clone, whose child (when there is one) exits. */
static long settid_error(unsigned long long flags, int exit_signal, const pid_t *tids, int count) {
    long r = settid_clone(flags, exit_signal, tids, count);
    if (r == 0) _exit(99);
    if (r > 0) waitpid(r, NULL, __WALL);
    return r < 0 ? r : 1000;
}
/* The numbers of line `name` of /proc/self/status, at most 4; how many. */
static int settid_numbers(const char *name, long *numbers) {
    FILE *file = fopen("/proc/self/status", "r");
    char line[256];
    int count = 0;
    size_t length = strlen(name);
    while (file && fgets(line, sizeof line, file)) {
        if (strncmp(line, name, length) || line[length] != ':') continue;
        char *at = line + length + 1, *end;
        while (count < 4) {
            long value = strtol(at, &end, 10);
            if (end == at) break;
            numbers[count++] = value;
            at = end;
        }
        break;
    }
    if (file) fclose(file);
    return count;
}
/* /proc/self/stat's PID, process group and session, as /proc's PID
   namespace numbers them. */
static void settid_stat(long *pid, long *group, long *session) {
    char buf[512] = {0};
    FILE *file = fopen("/proc/self/stat", "r");
    if (file) {
        if (!fgets(buf, sizeof buf, file)) buf[0] = 0;
        fclose(file);
    }
    char *close = strrchr(buf, ')');
    *pid = strtol(buf, NULL, 10);
    *group = *session = -1;
    if (close) sscanf(close + 2, "%*c %*d %ld %ld", group, session);
}
/* The NS* lines of /proc/self/status: how many numbers each has, and
   whether the first of each is what /proc/self/stat gives. */
static void settid_lines(const char *who) {
    long pid, group, session, numbers[4];
    settid_stat(&pid, &group, &session);
    const char *names[] = {"NStgid", "NSpid", "NSpgid", "NSsid"};
    long firsts[] = {pid, pid, group, session};
    printf("%s:", who);
    for (int i = 0; i < 4; i++) {
        int count = settid_numbers(names[i], numbers);
        printf(" %s=%d/%d", names[i], count, count > 0 && numbers[0] == firsts[i]);
        for (int j = 1; j < count; j++) printf(",%ld", numbers[j]);
    }
    /* In Linux's place, right after Groups. */
    FILE *file = fopen("/proc/self/status", "r");
    char line[256];
    int after = 0;
    while (file && fgets(line, sizeof line, file)) {
        if (strncmp(line, "Groups:", 7)) continue;
        after = fgets(line, sizeof line, file) && !strncmp(line, "NStgid:", 7);
        break;
    }
    if (file) fclose(file);
    printf(" after-groups=%d\n", after);
}
/* The net-namespaces case: a request of the loopback interface on `fd`,
   its result (the flags, or the index) or -errno. */
static long netns_lo(int fd, unsigned long request, const char *name, short flags) {
    struct ifreq request_of = {0};
    strncpy(request_of.ifr_name, name, IFNAMSIZ - 1);
    request_of.ifr_flags = flags;
    errno = 0;
    if (ioctl(fd, request, &request_of) < 0) return -errno;
    if (request == SIOCGIFFLAGS) return request_of.ifr_flags & (IFF_UP | IFF_LOOPBACK | IFF_RUNNING);
    if (request == SIOCGIFINDEX) return request_of.ifr_ifindex;
    return 0;
}
static struct sockaddr_in netns_v4(const char *ip, int port) {
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_port = htons(port)};
    inet_pton(AF_INET, ip, &address.sin_addr);
    return address;
}
static long netns_result(long r) { return r < 0 ? -errno : r; }
/* The netlink case: NETLINK_ROUTE's layouts, written out, as musl-gcc has
   no kernel headers. */
#define NL_AF_NETLINK 16
#define NL_ROUTE 0
#define NL_F_REQUEST 0x1
#define NL_F_ACK 0x4
#define NL_F_DUMP 0x300
struct nl_header {
    unsigned len;
    unsigned short type, flags;
    unsigned seq, pid;
};
struct nl_address {
    unsigned short family, pad;
    unsigned pid, groups;
};
static unsigned nl_seq = 100;
/* Sends a request of `type` and `flags` with `payload` on `fd`; its
   sequence number, or -errno. */
static long nl_send(int fd, unsigned short type, unsigned short flags, const void *payload, size_t len) {
    char buf[256] = {0};
    struct nl_header *h = (void *)buf;
    h->len = sizeof *h + len;
    h->type = type;
    h->flags = flags;
    h->seq = ++nl_seq;
    memcpy(buf + sizeof *h, payload, len);
    struct nl_address kernel = {.family = NL_AF_NETLINK};
    if (sendto(fd, buf, h->len, 0, (void *)&kernel, sizeof kernel) < 0) return -errno;
    return h->seq;
}
/* The attributes of `len` bytes at `at`: calls `each` for every one. */
static void nl_attributes(const unsigned char *at, int len, void (*each)(unsigned short, const unsigned char *, int)) {
    while (len >= 4) {
        unsigned short alen, type;
        memcpy(&alen, at, 2);
        memcpy(&type, at + 2, 2);
        if (alen < 4 || alen > len) break;
        each(type & 0x3fff, at + 4, alen - 4);
        int step = (alen + 3) & ~3;
        at += step;
        len -= step;
    }
}
static void nl_link_attribute(unsigned short type, const unsigned char *v, int len) {
    unsigned value = 0;
    if (len == 4) memcpy(&value, v, 4);
    switch (type) {
    case 3: printf(" name=%.*s", len, v); break;
    case 4: printf(" mtu=%u", value); break;
    case 13: printf(" txqlen=%u", value); break;
    case 16: printf(" operstate=%u", v[0]); break;
    case 17: printf(" linkmode=%u", v[0]); break;
    case 6: printf(" qdisc=%.*s", len, v); break;
    case 27: printf(" group=%u", value); break;
    case 33: printf(" carrier=%u", v[0]); break;
    case 1: printf(" address=%d", len); break;
    case 2: printf(" broadcast=%d", len); break;
    case 7: printf(" stats=%d", len); break;
    case 23: printf(" stats64=%d", len); break;
    }
}
static void nl_address_attribute(unsigned short type, const unsigned char *v, int len) {
    char text[64] = "";
    unsigned value = 0;
    if (len == 4) memcpy(&value, v, 4);
    printf(" %u", type);
    if ((type == 1 || type == 2) && (len == 4 || len == 16)) {
        inet_ntop(len == 4 ? AF_INET : AF_INET6, v, text, sizeof text);
        printf("=%s", text);
    } else if (type == 3) {
        printf("=%.*s", len, v);
    } else if (type == 8) {
        printf("=%#x", value);
    } else if (type == 11) {
        printf("=%u", v[0]);
    } else if (type == 6 && len == 16) {
        unsigned lifetimes[2];
        memcpy(lifetimes, v, 8);
        printf("=%#x,%#x", lifetimes[0], lifetimes[1]);
    }
}
/* Receives on `fd` until NLMSG_DONE or an error: prints each message of
   the answer to request `seq` from `port`, whatever datagrams carry them,
   and returns how many came, or -errno. */
static long nl_answer(int fd, long seq, unsigned port, const char *label) {
    long messages = 0;
    for (;;) {
        static char buf[16384];
        struct nl_address from = {0};
        struct iovec iov = {buf, sizeof buf};
        struct msghdr msg = {.msg_name = &from, .msg_namelen = sizeof from, .msg_iov = &iov, .msg_iovlen = 1};
        long peeked = recv(fd, buf, 1, MSG_PEEK | MSG_TRUNC | MSG_DONTWAIT);
        if (peeked < 0) return messages ? messages : -errno;
        long n = recvmsg(fd, &msg, MSG_DONTWAIT);
        if (n < 0) return -errno;
        if (n != peeked || from.family != NL_AF_NETLINK || from.pid != 0 || msg.msg_namelen != sizeof from ||
            msg.msg_flags)
            printf("%s: datagram n=%ld peeked=%ld from=%u namelen=%u flags=%#x\n", label, n, peeked, from.pid,
                   msg.msg_namelen, msg.msg_flags);
        for (char *at = buf; at + sizeof(struct nl_header) <= buf + n;) {
            struct nl_header *h = (void *)at;
            if (h->len < sizeof *h || at + h->len > buf + n) break;
            messages++;
            unsigned char *body = (void *)(h + 1);
            int body_len = h->len - sizeof *h;
            /* Only `lo`: Linux may have fallback tunnels in every
               namespace, as its ipip and gre modules make them. */
            int index = 1;
            if ((h->type == 16 && body_len >= 16) || (h->type == 20 && body_len >= 8)) memcpy(&index, body + 4, 4);
            at += (h->len + 3) & ~3;
            if (index != 1) continue;
            printf("%s: type=%u flags=%#x seq=%d port=%d", label, h->type, h->flags, h->seq == seq, h->pid == port);
            if (h->type == 2) {
                printf(" len=%u", h->len);
                int error;
                memcpy(&error, body, 4);
                printf(" error=%d echo=%d\n", error, body_len - 4);
                return messages;
            }
            if (h->type == 3) {
                printf(" len=%u", h->len);
                int done;
                memcpy(&done, body, 4);
                printf(" done=%d\n", done);
                return messages;
            }
            if (h->type == 16 && body_len >= 16) {
                unsigned short type;
                int index;
                unsigned flags, change;
                memcpy(&type, body + 2, 2);
                memcpy(&index, body + 4, 4);
                memcpy(&flags, body + 8, 4);
                memcpy(&change, body + 12, 4);
                printf(" family=%u arphrd=%u index=%d flags=%#x change=%#x", body[0], type, index, flags, change);
                nl_attributes(body + 16, body_len - 16, nl_link_attribute);
            } else if (h->type == 20 && body_len >= 8) {
                int index;
                memcpy(&index, body + 4, 4);
                printf(" family=%u prefix=%u flags=%#x scope=%u index=%d attributes", body[0], body[1], body[2],
                       body[3], index);
                nl_attributes(body + 8, body_len - 8, nl_address_attribute);
            }
            printf("\n");
        }
    }
}
/* What getifaddrs gives, one line each. */
static void nl_getifaddrs(const char *label) {
    struct ifaddrs *list, *i;
    if (getifaddrs(&list) < 0) {
        printf("%s: getifaddrs=%d\n", label, -errno);
        return;
    }
    for (i = list; i; i = i->ifa_next) {
        if (strcmp(i->ifa_name, "lo")) continue;
        char address[64] = "-", mask[64] = "-";
        int family = i->ifa_addr ? i->ifa_addr->sa_family : -1;
        if (family == AF_INET) {
            inet_ntop(AF_INET, &((struct sockaddr_in *)i->ifa_addr)->sin_addr, address, sizeof address);
            inet_ntop(AF_INET, &((struct sockaddr_in *)i->ifa_netmask)->sin_addr, mask, sizeof mask);
        } else if (family == AF_INET6) {
            inet_ntop(AF_INET6, &((struct sockaddr_in6 *)i->ifa_addr)->sin6_addr, address, sizeof address);
            inet_ntop(AF_INET6, &((struct sockaddr_in6 *)i->ifa_netmask)->sin6_addr, mask, sizeof mask);
        }
        printf("%s: %s family=%d flags=%#x address=%s mask=%s data=%d\n", label, i->ifa_name, family,
               i->ifa_flags & (IFF_UP | IFF_LOOPBACK | IFF_RUNNING), address, mask, i->ifa_data != NULL);
    }
    freeifaddrs(list);
}
/* An `ifinfomsg` for interface `index`, setting `flags` of `change`. */
struct nl_link {
    unsigned char family, pad;
    unsigned short type;
    int index;
    unsigned flags, change;
};
/* The pid-namespaces case: the SIGUSR1s the init of a nested PID
   namespace handled, and the sender the last one showed. */
static volatile sig_atomic_t pidns_usr1, pidns_from = -1;
static void pidns_handler(int signal, siginfo_t *info, void *context) {
    (void)signal;
    (void)context;
    pidns_usr1++;
    pidns_from = info->si_pid;
}
/* The init of the namespace: what it is and sees, the signals it drops
   and takes, an orphan it adopts; then it exits, leaving a process. It
   tells the maker on `done` when to signal it, and waits on `go`. */
static int pidns_init(int outer, int go, int done) {
    struct sigaction action = {0};
    action.sa_sigaction = pidns_handler;
    action.sa_flags = SA_SIGINFO | SA_RESTART;
    sigaction(SIGUSR1, &action, NULL);
    printf("init: pid=%d tid=%ld ppid=%d pgrp=%d sid=%d\n", getpid(), syscall(SYS_gettid), getppid(),
           getpgrp(), getsid(0));
    int own = ns_open("self", "pid");
    long outer_in = ns_setns(outer, CLONE_NEWPID), own_in = ns_setns(own, CLONE_NEWPID);
    printf("init: setns-outer=%ld setns-own=%ld\n", outer_in, own_in);
    /* From inside, SIGTERM and SIGKILL do not reach it; SIGUSR1, which it
       handles, does, from the sender's number. */
    fflush(stdout);
    pid_t sender = child();
    if (sender == 0) {
        errno = 0;
        long none = kill(99, 0);
        printf("sender: pid=%d ppid=%d none=%ld errno=%d\n", getpid(), getppid(), none, errno);
        kill(1, SIGTERM);
        kill(1, SIGKILL);
        kill(1, SIGUSR1);
        fflush(stdout);
        _exit(0);
    }
    int status = 0;
    pid_t waited = waitpid(sender, &status, 0);
    printf("init: sender=%d waited=%d status=%d usr1=%d from=%d\n", sender, waited, status, pidns_usr1,
           pidns_from);
    /* An orphan comes to the init. */
    fflush(stdout);
    pid_t parent = child();
    if (parent == 0) {
        pid_t orphan = child();
        if (orphan == 0) {
            for (int i = 0; i < 10000 && getppid() != 1; i++) usleep(1000);
            printf("orphan: pid=%d ppid=%d\n", getpid(), getppid());
            fflush(stdout);
            _exit(0);
        }
        printf("parent: pid=%d orphan=%d\n", getpid(), orphan);
        fflush(stdout);
        _exit(0);
    }
    pid_t first = waitpid(parent, &status, 0), second = waitpid(-1, &status, 0);
    printf("init: parent=%d reaped=%d,%d\n", parent, first, second);
    /* From outside, SIGTERM neither; SIGUSR1 from no number it has. */
    pidns_usr1 = 0;
    pidns_from = -1;
    fflush(stdout);
    char byte;
    if (write(done, "x", 1) != 1 || read(go, &byte, 1) != 1) return 80;
    printf("init: outside usr1=%d from=%d\n", pidns_usr1, pidns_from);
    /* Its exit takes the rest of the namespace with it. */
    fflush(stdout);
    pid_t stayer = child();
    if (stayer == 0) {
        for (;;) pause();
    }
    printf("init: stayer=%d\n", stayer);
    fflush(stdout);
    return 7;
}
/* execveat(dir, path, argv, envp, flags) through the raw call. */
static long execveat_call(int dir, const char *path, char *const *argv, int flags) {
    char *env[] = {NULL};
    return syscall(SYS_execveat, dir, path, argv, env, flags);
}
/* A copy of the file at `from` in descriptor `to`, from its start. */
static int copy_into(const char *from, int to) {
    char buffer[65536];
    long n;
    int in = open(from, O_RDONLY);
    if (in < 0) return -1;
    while ((n = read(in, buffer, sizeof buffer)) > 0)
        if (write(to, buffer, n) != n) return -1;
    close(in);
    return n < 0 ? -1 : 0;
}
/* Runs `label` in a child: execveat as given, which reports from the new
   program, or the error it gives. */
static void execveat_child(const char *label, int dir, const char *path, int flags) {
    fflush(stdout);
    pid_t pid = child();
    if (pid == 0) {
        char *args[] = {"x", "execveat-run", (char *)label, NULL};
        long r = execveat_call(dir, path, args, flags);
        printf("%s: failed=%ld errno=%d\n", label, r, errno);
        fflush(stdout);
        _exit(9);
    }
    printf("%s: status=%d\n", label, reaped(pid));
}
/* The pipe whose write end keeps an etxtbsy-run child running. */
static int etxtbsy_release[2];
/* Starts a child that runs `path` (execveat on `dir` with `flags`) in the
   etxtbsy-run mode, and returns once that program runs. */
static pid_t etxtbsy_start(int dir, const char *path, int flags) {
    int ready[2];
    if (pipe(etxtbsy_release) || pipe(ready)) return -1;
    fflush(stdout);
    pid_t pid = child();
    if (pid == 0) {
        dup2(etxtbsy_release[0], 10);
        dup2(ready[1], 11);
        close(etxtbsy_release[0]);
        close(etxtbsy_release[1]);
        close(ready[0]);
        close(ready[1]);
        char *args[] = {"x", "etxtbsy-run", "x", NULL};
        execveat_call(dir, path, args, flags);
        _exit(9);
    }
    close(etxtbsy_release[0]);
    close(ready[1]);
    char c;
    result("started", read(ready[0], &c, 1));
    close(ready[0]);
    return pid;
}
static void etxtbsy_stop(pid_t pid) {
    close(etxtbsy_release[1]);
    result("stopped", reaped(pid));
}
/* Opens `path` with `flags`, reporting the outcome, and closes it. */
static void etxtbsy_open(const char *name, const char *path, int flags) {
    errno = 0;
    int fd = open(path, flags | O_CLOEXEC);
    printf("%s=%d errno=%d\n", name, fd >= 0, fd < 0 ? errno : 0);
    if (fd >= 0) close(fd);
}
/* The value of `field` in /proc/self/status, read through a /proc/self
   descriptor as procfs readers do. */
static int status_field(const char *field, char *value, size_t size) {
    int dir = open("/proc/self", O_PATH | O_DIRECTORY | O_CLOEXEC);
    int fd = openat(dir, "status", O_RDONLY | O_CLOEXEC);
    close(dir);
    if (fd < 0) return -1;
    static char text[8192];
    ssize_t n = read(fd, text, sizeof text - 1);
    close(fd);
    if (n <= 0) return -1;
    text[n] = 0;
    size_t length = strlen(field);
    for (char *line = text; *line; line = strchr(line, '\n') + 1) {
        if (!strncmp(line, field, length) && line[length] == ':') {
            char *start = line + length + 1;
            while (*start == '\t') start++;
            size_t used = strcspn(start, "\n");
            if (used >= size) used = size - 1;
            memcpy(value, start, used);
            value[used] = 0;
            return 0;
        }
        if (!strchr(line, '\n')) break;
    }
    return -1;
}
static long raw_priority(int which, int who) { return syscall(SYS_getpriority, which, who); }
static int priority_ready[2], priority_go[2];
static volatile long priority_thread_start, priority_thread_after;
static volatile pid_t priority_tid;
static void *priority_thread(void *base) {
    long nice0 = 20 - (long)base;
    char byte;
    priority_tid = syscall(SYS_gettid);
    priority_thread_start = raw_priority(PRIO_PROCESS, 0);
    setpriority(PRIO_PROCESS, priority_tid, nice0 + 5);
    if (write(priority_ready[1], "x", 1) != 1 || read(priority_go[0], &byte, 1) != 1) return NULL;
    priority_thread_after = raw_priority(PRIO_PROCESS, 0);
    return NULL;
}
/* A core dump: the child sets RLIMIT_CORE to `limit` (at most its hard
   limit), may make itself undumpable or start a thread, and ends by a NULL
   write (SIGSEGV) or by `signal`; the parent reports how it ended and what
   the `core` file holds. */
static volatile uint64_t core_magic;
static void *core_parked(void *unused) { (void)unused; for (;;) pause(); }
static pid_t core_child(rlim_t limit, int dumpable, int thread, int signal) {
    pid_t pid = fork();
    if (pid != 0) return pid;
    struct rlimit r;
    getrlimit(RLIMIT_CORE, &r);
    r.rlim_cur = limit < r.rlim_max ? limit : r.rlim_max;
    setrlimit(RLIMIT_CORE, &r);
    if (!dumpable) prctl(PR_SET_DUMPABLE, 0);
    core_magic = 0x1122334455667788ULL;
    pthread_t t;
    if (thread && pthread_create(&t, NULL, core_parked, NULL)) _exit(71);
    if (signal) kill(getpid(), signal);
    else *(volatile int *)0 = 1;
    _exit(70);
}
/* A little-endian field of the core, or 0 past its end. */
static const unsigned char *core_bytes;
static uint64_t core_size;
static uint64_t le(uint64_t at, int size) {
    uint64_t v = 0;
    if (at > core_size || (uint64_t)size > core_size - at) return 0;
    for (int i = size - 1; i >= 0; i--) v = v << 8 | core_bytes[at + i];
    return v;
}
static void core_report(const char *name, pid_t pid) {
    siginfo_t info;
    int status = 0;
    waitid(P_PID, pid, &info, WEXITED | WNOWAIT);
    waitpid(pid, &status, 0);
    printf("%s: code=%d signal=%d core=%d", name, info.si_code,
           WIFSIGNALED(status) ? WTERMSIG(status) : -1, WCOREDUMP(status) ? 1 : 0);
    int fd = open("core", O_RDONLY);
    if (fd < 0) {
        printf(" file=0\n");
        fflush(stdout);
        return;
    }
    struct stat st;
    fstat(fd, &st);
    unsigned char *b = calloc(st.st_size + 1, 1);
    long size = 0, n;
    while (b && size < st.st_size && (n = read(fd, b + size, st.st_size - size)) > 0) size += n;
    close(fd);
    unlink("core");
    core_bytes = b;
    core_size = b ? (uint64_t)size : 0;
    printf(" file=1 mode=%o elf=%d", (unsigned)(st.st_mode & 0777), size >= 64 && !memcmp(b, "\177ELF", 4));
    if (!WCOREDUMP(status) || size < 64) {
        printf(" small=%d\n", st.st_size <= 4096);
        fflush(stdout);
        free(b);
        return;
    }
    printf(" type=%d machine=%d", (int)le(16, 2), (int)le(18, 2));
    int count = (int)le(56, 2), statuses = 0, magic = 0;
    for (int i = 0; i < count; i++) {
        uint64_t p = le(32, 8) + 56 * (uint64_t)i;
        uint64_t offset = le(p + 8, 8), address = le(p + 16, 8), filesz = le(p + 32, 8);
        uint64_t at = (uintptr_t)&core_magic;
        if (le(p, 4) == 1 && at >= address && at + 8 <= address + filesz)
            magic = le(offset + (at - address), 8) == 0x1122334455667788ULL;
        if (le(p, 4) != 4) continue;
        /* The first notes, their order, and the fatal signal. */
        for (uint64_t q = offset, k = 0; q + 12 <= offset + filesz && q + 12 <= core_size; k++) {
            uint64_t namesz = le(q, 4), descsz = le(q + 4, 4), type = le(q + 8, 4);
            uint64_t desc = q + 12 + ((namesz + 3) & ~3ULL);
            if (k < 4) printf(" note%d=%#llx", (int)k, (unsigned long long)type);
            if (type == 1 && statuses++ == 0)
                printf(" cursig=%d own=%d", (int)le(desc + 12, 2), (pid_t)le(desc + 32, 4) == pid);
            if (type == 3) {
                char fname[17] = {0};
                for (int c = 0; c < 16; c++) fname[c] = (char)le(desc + 40 + c, 1);
                printf(" fname=%s", fname);
            }
            /* A fault gives its address, a kill its sender, here the child. */
            if (type == 0x53494749 && le(desc, 4) == SIGSEGV)
                printf(" signo=11 sicode=%d addr=%#llx", (int)le(desc + 8, 4),
                       (unsigned long long)le(desc + 16, 8));
            else if (type == 0x53494749)
                printf(" signo=%d sicode=%d sender=%d", (int)le(desc, 4), (int)le(desc + 8, 4),
                       (pid_t)le(desc + 16, 4) == pid);
            if (type == 6)
                for (uint64_t a = 0; a + 16 <= descsz; a += 16)
                    if (le(desc + a, 8) == AT_PAGESZ) printf(" pagesz=%llu", (unsigned long long)le(desc + a + 8, 8));
            q = desc + ((descsz + 3) & ~3ULL);
        }
    }
    printf(" statuses=%d magic=%d\n", statuses, magic);
    fflush(stdout);
    free(b);
}
/* The entry of the NT_FILE note at `files` that maps `x`: its name, with
   its range and page offset, or NULL. */
static const char *file_entry(uint64_t files, uint64_t x, uint64_t *start, uint64_t *end,
                              uint64_t *pgoff) {
    if (!files) return NULL;
    uint64_t count = le(files, 8);
    const char *name = (const char *)core_bytes + files + 16 + 24 * count;
    for (uint64_t k = 0; k < count && (const unsigned char *)name < core_bytes + core_size; k++) {
        uint64_t e = files + 16 + 24 * k;
        if (x >= le(e, 8) && x < le(e + 8, 8)) {
            *start = le(e, 8), *end = le(e + 8, 8), *pgoff = le(e + 16, 8);
            return name;
        }
        name += strlen(name) + 1;
    }
    return NULL;
}
static int same_path(const char *a, const char *b) {
    struct stat x, y;
    return stat(a, &x) == 0 && stat(b, &y) == 0 && x.st_dev == y.st_dev && x.st_ino == y.st_ino;
}
/* Where the program's segment that holds its code starts, and its page in
   the program's file. */
static uint64_t text_start, text_pgoff;
static int text_segment(struct dl_phdr_info *info, size_t size, void *unused) {
    (void)size, (void)unused;
    uint64_t at = (uintptr_t)&text_segment;
    for (int i = 0; i < info->dlpi_phnum; i++) {
        const ElfW(Phdr) *h = &info->dlpi_phdr[i];
        uint64_t v = info->dlpi_addr + h->p_vaddr;
        if (h->p_type == PT_LOAD && at >= v && at < v + h->p_memsz)
            text_start = v & ~4095ULL, text_pgoff = h->p_offset / 4096;
    }
    return 1;
}
/* The calling thread's IDs and capabilities: getresuid and getresgid,
   the filesystem IDs (setfsuid(-1) changes nothing and returns them), the
   Uid, Gid and Groups lines of /proc/self/status, and the permitted and
   effective capabilities as all (the bounding set), none, or all but the
   filesystem ones. Dumpability is 1, or the fs.suid_dumpable setting
   (0 when it cannot be read). */
static const char *capabilities(const char *field) {
    char value[64], bounding[64];
    if (status_field(field, value, sizeof value) || status_field("CapBnd", bounding, sizeof bounding))
        return "missing";
    unsigned long long caps = strtoull(value, NULL, 16), all = strtoull(bounding, NULL, 16);
    unsigned long long fs = 0x1fULL | 1ULL << 9 | 1ULL << 27 | 1ULL << 32;
    return caps == all ? "all" : caps == 0 ? "none" : caps == (all & ~fs) ? "all-but-fs" : "other";
}
/* `fs.suid_dumpable`, which an undumpable process reads as its dumpable
   value: 0 (the emulator's, and the kernel's default) unless the system
   raised it. */
static int suid_dumpable(void) {
    int value = 0;
    FILE *f = fopen("/proc/sys/fs/suid_dumpable", "r");
    if (f) {
        if (fscanf(f, "%d", &value) != 1) value = 0;
        fclose(f);
    }
    return value;
}
static void credentials_line(const char *name) {
    unsigned r = 0, e = 0, sv = 0, gr = 0, ge = 0, gs = 0;
    syscall(SYS_getresuid, &r, &e, &sv);
    syscall(SYS_getresgid, &gr, &ge, &gs);
    long fsuid = syscall(SYS_setfsuid, -1), fsgid = syscall(SYS_setfsgid, -1);
    char uid[64], gid[64], groups[128];
    if (status_field("Uid", uid, sizeof uid)) strcpy(uid, "missing");
    if (status_field("Gid", gid, sizeof gid)) strcpy(gid, "missing");
    if (status_field("Groups", groups, sizeof groups)) strcpy(groups, "missing");
    for (char *t = uid; *t; t++) if (*t == '\t') *t = '/';
    for (char *t = gid; *t; t++) if (*t == '\t') *t = '/';
    int dumpable = prctl(PR_GET_DUMPABLE);
    printf("%s: uid=%u/%u/%u/%ld gid=%u/%u/%u/%ld status-uid=%s status-gid=%s groups=[%s] "
           "prm=%s eff=%s dumpable=%s\n",
           name, r, e, sv, fsuid, gr, ge, gs, fsgid, uid, gid, groups, capabilities("CapPrm"),
           capabilities("CapEff"), dumpable == 1 ? "1" : dumpable == suid_dumpable() ? "suid" : "other");
}
static unsigned thread_uid;
static void *credentials_thread(void *unused) {
    (void)unused;
    syscall(SYS_setresuid, 7, 7, 7);
    thread_uid = syscall(SYS_getuid);
    return NULL;
}
/* The permissions case: a tree under PERMISSIONS that root lays out and a
   thread of other IDs then works in. */
#define PERMISSIONS "/tmp/paludarium-permissions"
static void remove_tree(const char *path) {
    struct stat st;
    if (lstat(path, &st)) return;
    if (S_ISDIR(st.st_mode)) {
        DIR *dir = opendir(path);
        struct dirent *entry;
        while (dir && (entry = readdir(dir))) {
            if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
            char inner[512];
            snprintf(inner, sizeof inner, "%s/%s", path, entry->d_name);
            remove_tree(inner);
        }
        if (dir) closedir(dir);
        rmdir(path);
    } else {
        unlink(path);
    }
}
/* A file of `mode` belonging to `uid` and `gid`, holding `size` bytes of
   `content`. */
static int permissions_file(const char *name, mode_t mode, uid_t uid, gid_t gid,
                            const void *content, size_t size) {
    char path[256];
    snprintf(path, sizeof path, PERMISSIONS "/%s", name);
    int fd = open(path, O_CREAT|O_WRONLY|O_TRUNC, 0600);
    if (fd < 0 || write(fd, content, size) != (ssize_t)size || close(fd)) return -1;
    if (chown(path, uid, gid) || chmod(path, mode)) return -1;
    return 0;
}
static int permissions_directory(const char *name, mode_t mode, uid_t uid, gid_t gid) {
    char path[256];
    snprintf(path, sizeof path, PERMISSIONS "/%s", name);
    if (mkdir(path, 0700) || chown(path, uid, gid) || chmod(path, mode)) return -1;
    return 0;
}
/* A call's outcome: ok, or its error. */
static void permitted(const char *name, long value) {
    printf("%s: %s\n", name, value < 0 ? strerror(errno) : "ok");
}
static void permissions_owner(const char *name, const char *path) {
    struct stat st;
    if (lstat(path, &st)) {
        printf("%s: %s\n", name, strerror(errno));
        return;
    }
    printf("%s: uid=%u gid=%u mode=%o\n", name, st.st_uid, st.st_gid, st.st_mode & 07777);
}
/* The signal-permissions case: a process that waits with the given IDs. */
static pid_t signal_target(unsigned real, unsigned effective, unsigned saved, int own_group) {
    int ready[2];
    if (pipe(ready)) _exit(90);
    fflush(stdout);
    pid_t pid = child();
    if (pid == 0) {
        close(ready[0]);
        if (own_group) setpgid(0, 0);
        if (syscall(SYS_setresuid, real, effective, saved)) _exit(91);
        char byte = 1;
        if (write(ready[1], &byte, 1) != 1) _exit(92);
        for (;;) pause();
    }
    close(ready[1]);
    char byte;
    if (read(ready[0], &byte, 1) != 1) _exit(93);
    close(ready[0]);
    return pid;
}
static void signal_kill_reap(pid_t pid) {
    kill(pid, SIGKILL);
    int status = 0;
    waitpid(pid, &status, 0);
}
/* Sends with these IDs, in a child of their own. */
#define AS_SENDER(real, effective, saved, ...) do { \
        fflush(stdout); \
        pid_t sender_pid = child(); \
        if (sender_pid == 0) { \
            if (syscall(SYS_setresuid, real, effective, saved)) _exit(94); \
            __VA_ARGS__; \
            fflush(stdout); \
            _exit(0); \
        } \
        int sender_status = 0; \
        waitpid(sender_pid, &sender_status, 0); \
        printf("sender: status=%d\n", sender_status); \
    } while (0)
static void signal_queue_info(siginfo_t *info) {
    memset(info, 0, sizeof *info);
    info->si_code = SI_QUEUE;
}
/* What a signal waited for shows of its sender. */
static void signal_seen(const char *name, int number, pid_t sender) {
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, number);
    siginfo_t info;
    struct timespec patience = {5, 0};
    int got = sigtimedwait(&set, &info, &patience);
    if (got < 0) {
        printf("%s: %s\n", name, strerror(errno));
        return;
    }
    printf("%s: signal=%d code=%d uid=%u sender=%d\n", name, got, info.si_code, info.si_uid,
           info.si_pid == sender);
}
static int signal_thread_pipe[2];
static void *signal_thread_with_ids(void *unused) {
    (void)unused;
    pid_t tid = syscall(SYS_gettid);
    if (syscall(SYS_setresuid, 2000, 2000, 2000)) _exit(95);
    if (write(signal_thread_pipe[1], &tid, sizeof tid) != sizeof tid) _exit(96);
    for (;;) pause();
    return NULL;
}
static pid_t signal_main_thread;
static void *signal_thread_tkills(void *unused) {
    (void)unused;
    if (syscall(SYS_setresuid, 2000, 2000, 2000)) _exit(97);
    syscall(SYS_tgkill, getpid(), signal_main_thread, SIGUSR1);
    return NULL;
}
/* The peer-credentials and core-credentials cases: IDs that all differ. */
static void peer_ids_leave_root(void) {
    if (syscall(SYS_setresgid, 1100, 2100, 3100)) _exit(95);
    if (syscall(SYS_setresuid, 1000, 2000, 3000)) _exit(96);
}
static void peer_ids_peer(const char *name, int socket) {
    struct ucred peer;
    socklen_t len = sizeof peer;
    if (getsockopt(socket, SOL_SOCKET, SO_PEERCRED, &peer, &len)) {
        printf("%s: %s\n", name, strerror(errno));
        return;
    }
    printf("%s: own=%d uid=%d gid=%d\n", name, peer.pid == getpid(), (int)peer.uid, (int)peer.gid);
}
/* What the next message on `socket` carries: its bytes and credentials. */
static void peer_ids_received(const char *name, int socket) {
    char data[8] = {0};
    struct iovec iov = {data, sizeof data};
    union { char bytes[CMSG_SPACE(sizeof(struct ucred))]; struct cmsghdr align; } control;
    struct msghdr message = {.msg_iov = &iov, .msg_iovlen = 1, .msg_control = control.bytes,
                             .msg_controllen = sizeof control.bytes};
    long n = recvmsg(socket, &message, MSG_DONTWAIT);
    if (n < 0) {
        printf("%s: %s\n", name, strerror(errno));
        return;
    }
    struct cmsghdr *header = CMSG_FIRSTHDR(&message);
    struct ucred from = {0, 0, 0};
    if (header && header->cmsg_type == SCM_CREDENTIALS) memcpy(&from, CMSG_DATA(header), sizeof from);
    printf("%s: data=%.*s own=%d parent=%d uid=%d gid=%d\n", name, (int)n, data, from.pid == getpid(),
           from.pid == getppid(), (int)from.uid, (int)from.gid);
}
/* sendmsg with these credentials; what it did, and what arrived. */
static void peer_ids_send(const char *name, int from, int to, pid_t pid, uid_t uid, gid_t gid) {
    long sent = send_credentials(from, "m", pid, uid, gid, CMSG_LEN(sizeof(struct ucred)));
    permitted(name, sent);
    if (sent >= 0) peer_ids_received(name, to);
}
static volatile pid_t peer_ids_thread_id;
static void *peer_ids_thread(void *unused) {
    (void)unused;
    peer_ids_thread_id = syscall(SYS_gettid);
    for (;;) pause();
}
static pid_t peer_ids_thread_start(void) {
    pthread_t thread;
    if (pthread_create(&thread, NULL, peer_ids_thread, NULL)) _exit(97);
    while (!peer_ids_thread_id) sched_yield();
    return peer_ids_thread_id;
}
/* A child that faults with other IDs, in a thread of its own, with the
   filesystem IDs `fs` when it is not -1; the leader of `thread` stays root. */
static int core_credentials_fs = -1;
static void core_credentials_fault(void) {
    peer_ids_leave_root();
    if (core_credentials_fs >= 0) {
        syscall(SYS_setfsuid, core_credentials_fs);
        syscall(SYS_setfsgid, core_credentials_fs + 100);
    }
    if (prctl(PR_SET_DUMPABLE, 1)) _exit(98);
    *(volatile int *)0 = 1;
    _exit(70);
}
static void *core_credentials_thread(void *unused) {
    (void)unused;
    core_credentials_fault();
    return NULL;
}
/* No limit on a core: sudo runs its command with a hard limit of 0 (sudoers'
   `rlimit_core`), which root may raise. */
static void core_credentials_limit(void) {
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
    if (setrlimit(RLIMIT_CORE, &r)) _exit(93);
}
static pid_t core_credentials_child(int thread, int fs) {
    fflush(stdout);
    pid_t pid = fork();
    if (pid != 0) return pid;
    core_credentials_limit();
    core_credentials_fs = fs;
    if (thread) {
        pthread_t t;
        if (pthread_create(&t, NULL, core_credentials_thread, NULL)) _exit(99);
        for (;;) pause();
    }
    core_credentials_fault();
    return 0;
}
/* How `pid` ended, the owner and mode of `core`, and the IDs it names. */
static void core_credentials_report(const char *name, pid_t pid) {
    int status = 0;
    waitpid(pid, &status, 0);
    printf("%s: signal=%d core=%d", name, WIFSIGNALED(status) ? WTERMSIG(status) : -1,
           WCOREDUMP(status) ? 1 : 0);
    int fd = open("core", O_RDONLY);
    if (fd < 0) {
        printf(" file=0\n");
        fflush(stdout);
        return;
    }
    struct stat st;
    fstat(fd, &st);
    printf(" file=1 uid=%u gid=%u mode=%o", (unsigned)st.st_uid, (unsigned)st.st_gid,
           (unsigned)(st.st_mode & 0777));
    unsigned char *b = calloc(st.st_size + 1, 1);
    long size = 0, n;
    while (b && size < st.st_size && (n = read(fd, b + size, st.st_size - size)) > 0) size += n;
    close(fd);
    unlink("core");
    core_bytes = b;
    core_size = b ? (uint64_t)size : 0;
    int count = WCOREDUMP(status) ? (int)le(56, 2) : 0;
    for (int i = 0; i < count; i++) {
        uint64_t p = le(32, 8) + 56 * (uint64_t)i;
        uint64_t offset = le(p + 8, 8), filesz = le(p + 32, 8);
        if (le(p, 4) != 4) continue;
        for (uint64_t q = offset; q + 12 <= offset + filesz && q + 12 <= core_size;) {
            uint64_t namesz = le(q, 4), descsz = le(q + 4, 4), type = le(q + 8, 4);
            uint64_t desc = q + 12 + ((namesz + 3) & ~3ULL);
            if (type == 3)
                printf(" pr_uid=%u pr_gid=%u", (unsigned)le(desc + 16, 4), (unsigned)le(desc + 20, 4));
            q = desc + ((descsz + 3) & ~3ULL);
        }
    }
    printf("\n");
    fflush(stdout);
    free(b);
}
/* The set-id-writes case: what `change` does to a file of user 2000, whose
   group is `gid` and whose mode is `mode`, done with the IDs of user 2000 and
   group 2100 in a child; and the file's mode then, read as root. */
static long set_id_change(const char *way, int fd) {
    char buffer[1] = {'x'};
    struct iovec iov = {buffer, 1};
    if (!strcmp(way, "write")) return write(fd, buffer, 1);
    if (!strcmp(way, "write-empty")) return write(fd, buffer, 0);
    if (!strcmp(way, "pwrite")) return pwrite(fd, buffer, 1, 0);
    if (!strcmp(way, "pwrite-empty")) return pwrite(fd, buffer, 0, 0);
    if (!strcmp(way, "writev")) return writev(fd, &iov, 1);
    if (!strcmp(way, "pwritev")) return pwritev(fd, &iov, 1, 0);
    if (!strcmp(way, "ftruncate")) return ftruncate(fd, 0);
    if (!strcmp(way, "ftruncate-same")) return ftruncate(fd, 4);
    if (!strcmp(way, "truncate")) return truncate("f", 0);
    if (!strcmp(way, "open-trunc")) return open("f", O_WRONLY | O_TRUNC);
    if (!strcmp(way, "open-read")) return open("f", O_RDONLY);
    if (!strcmp(way, "fallocate")) return fallocate(fd, 0, 0, 16);
    if (!strcmp(way, "sendfile") || !strcmp(way, "copy_file_range")) {
        int from = open("from", O_RDONLY);
        if (from < 0) return -1;
        return !strcmp(way, "sendfile") ? sendfile(fd, from, NULL, 1)
                                        : copy_file_range(from, NULL, fd, NULL, 1, 0);
    }
    if (!strcmp(way, "chown-self")) return fchown(fd, -1, -1);
    if (!strcmp(way, "mmap")) {
        char *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        if (p == MAP_FAILED) return -1;
        *p = 'y';
        return msync(p, 4096, MS_SYNC);
    }
    return -2;
}
static void set_id_case(const char *way, unsigned mode, unsigned gid, unsigned uid) {
    unlink("f");
    int made = open("f", O_CREAT | O_WRONLY, 0666);
    if (made < 0 || write(made, "data", 4) != 4 || fchown(made, 2000, gid) || fchmod(made, mode)) _exit(80);
    close(made);
    fflush(stdout);
    pid_t pid = child();
    if (pid == 0) {
        int fd = open("f", O_RDWR);
        if (fd < 0) _exit(81);
        if (uid != 0) {
            if (syscall(SYS_setresgid, 2100, 2100, 2100)) _exit(82);
            if (syscall(SYS_setresuid, uid, uid, uid)) _exit(83);
        }
        long result = set_id_change(way, fd);
        _exit(result < 0 ? 1 : 0);
    }
    int status = 0;
    waitpid(pid, &status, 0);
    struct stat st;
    if (stat("f", &st)) _exit(84);
    printf("%s %o gid=%u uid=%u: exit=%d mode=%o\n", way, mode, gid, uid, WEXITSTATUS(status),
           (unsigned)(st.st_mode & 07777));
}
/* The socket-owners case: the owner and mode of what `fd` is. */
static void owner_show(const char *name, int fd) {
    struct stat st;
    if (fd < 0) {
        printf("%s: %s\n", name, strerror(errno));
        return;
    }
    if (fstat(fd, &st)) {
        printf("%s: stat %s\n", name, strerror(errno));
        return;
    }
    printf("%s: uid=%u gid=%u mode=%o\n", name, (unsigned)st.st_uid, (unsigned)st.st_gid, (unsigned)st.st_mode);
}
static void path_show(const char *name, const char *path) {
    struct stat st;
    if (lstat(path, &st)) {
        printf("%s: %s\n", name, strerror(errno));
        return;
    }
    printf("%s: uid=%u gid=%u mode=%o\n", name, (unsigned)st.st_uid, (unsigned)st.st_gid, (unsigned)st.st_mode);
}
static socklen_t socket_path(struct sockaddr_un *a, const char *path) {
    memset(a, 0, sizeof *a);
    a->sun_family = AF_UNIX;
    strcpy(a->sun_path, path);
    return offsetof(struct sockaddr_un, sun_path) + strlen(path) + 1;
}
static long socket_bind(int type, const char *path) {
    struct sockaddr_un a;
    socklen_t len = socket_path(&a, path);
    int s = socket(AF_UNIX, type, 0);
    if (s < 0) return -1;
    if (bind(s, (void *)&a, len)) return -1;
    return s;
}
static long socket_connect(const char *path) {
    struct sockaddr_un a;
    socklen_t len = socket_path(&a, path);
    int s = socket(AF_UNIX, SOCK_STREAM, 0);
    if (s < 0) return -1;
    long result = connect(s, (void *)&a, len);
    int saved = errno;
    close(s);
    errno = saved;
    return result;
}
static long socket_sendto(const char *path) {
    struct sockaddr_un a;
    socklen_t len = socket_path(&a, path);
    int s = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (s < 0) return -1;
    long result = sendto(s, "x", 1, MSG_DONTWAIT, (void *)&a, len);
    int saved = errno;
    close(s);
    errno = saved;
    return result;
}
/* The capabilities case: raw capget and capset, with no library's help. */
#define CAPS_V1 0x19980330u
#define CAPS_V2 0x20071026u
#define CAPS_V3 0x20080522u
#define CAPS_ALL ((1ULL << 41) - 1)
#define CAP_BIT(n) (1ULL << (n))
struct caps_header {
    uint32_t version;
    int pid;
};
struct caps_word {
    uint32_t effective, permitted, inheritable;
};
static long caps_get(uint32_t version, int pid, struct caps_word *data) {
    struct caps_header header = {version, pid};
    return syscall(SYS_capget, &header, data);
}
static long caps_set(uint64_t effective, uint64_t permitted, uint64_t inheritable) {
    struct caps_header header = {CAPS_V3, 0};
    struct caps_word data[2] = {
        {(uint32_t)effective, (uint32_t)permitted, (uint32_t)inheritable},
        {(uint32_t)(effective >> 32), (uint32_t)(permitted >> 32), (uint32_t)(inheritable >> 32)},
    };
    return syscall(SYS_capset, &header, data);
}
/* Only these effective capabilities, keeping every permitted one. */
static void caps_only(uint64_t effective) {
    if (caps_set(effective, CAPS_ALL, 0)) _exit(95);
}
static void caps_show(const char *name, int pid) {
    struct caps_word data[2];
    if (caps_get(CAPS_V3, pid, data)) {
        printf("%s: %s\n", name, strerror(errno));
        return;
    }
    printf("%s: e=%llx p=%llx i=%llx\n", name,
           (unsigned long long)data[0].effective | (unsigned long long)data[1].effective << 32,
           (unsigned long long)data[0].permitted | (unsigned long long)data[1].permitted << 32,
           (unsigned long long)data[0].inheritable | (unsigned long long)data[1].inheritable << 32);
}
/* What `/proc/self/status` says of the sets. */
static void caps_status(void) {
    FILE *f = fopen("/proc/self/status", "r");
    char line[256];
    while (f && fgets(line, sizeof line, f))
        if (!strncmp(line, "CapInh", 6) || !strncmp(line, "CapPrm", 6) || !strncmp(line, "CapEff", 6))
            printf("  %s", line);
    if (f) fclose(f);
}
static void caps_exec(void) {
    char *args[] = {"./prog", "capabilities-show", "./prog", NULL};
    char *env[] = {NULL};
    fflush(stdout);
    execve("./prog", args, env);
    _exit(96);
}
/* A copy of this program where any thread may reach it, whatever it holds: the
   tests' own program may be in a directory only its user may search. */
static int caps_copy(const char *self) {
    char buffer[65536];
    long n;
    int from = open(self, O_RDONLY), to = open("prog", O_CREAT | O_WRONLY, 0755);
    if (from < 0 || to < 0 || fchmod(to, 0755)) return -1;
    while ((n = read(from, buffer, sizeof buffer)) > 0)
        if (write(to, buffer, n) != n) return -1;
    close(from);
    close(to);
    return n;
}
static volatile int caps_thread_id;
static volatile int caps_thread_done;
static void *caps_thread(void *unused) {
    (void)unused;
    if (caps_set(CAP_BIT(0), CAP_BIT(0) | CAP_BIT(1), 0)) _exit(97);
    caps_thread_id = syscall(SYS_gettid);
    while (!caps_thread_done) sched_yield();
    return NULL;
}
/* The limit-permissions case: a process that waits with the given IDs. */
static pid_t limit_target(unsigned real, unsigned effective, unsigned saved, unsigned gid,
                          unsigned egid, unsigned sgid) {
    int ready[2];
    if (pipe(ready)) _exit(100);
    fflush(stdout);
    pid_t pid = child();
    if (pid == 0) {
        close(ready[0]);
        if (syscall(SYS_setresgid, gid, egid, sgid)) _exit(101);
        if (syscall(SYS_setresuid, real, effective, saved)) _exit(102);
        char byte = 1;
        if (write(ready[1], &byte, 1) != 1) _exit(103);
        for (;;) pause();
    }
    close(ready[1]);
    char byte;
    if (read(ready[0], &byte, 1) != 1) _exit(104);
    close(ready[0]);
    return pid;
}
static long limit_set(pid_t pid, int resource, unsigned long soft, unsigned long hard) {
    struct rlimit limit = {soft, hard};
    return syscall(SYS_prlimit64, pid, resource, &limit, NULL);
}
static long limit_read(pid_t pid, int resource) {
    struct rlimit limit;
    return syscall(SYS_prlimit64, pid, resource, NULL, &limit);
}
static void limit_show(const char *name, pid_t pid) {
    struct rlimit limit;
    if (syscall(SYS_prlimit64, pid, RLIMIT_NOFILE, NULL, &limit)) {
        printf("%s: %s\n", name, strerror(errno));
        return;
    }
    printf("%s: soft=%lu hard=%lu\n", name, (unsigned long)limit.rlim_cur,
           (unsigned long)limit.rlim_max);
}
static void nice_show(const char *name, int which, int who) {
    long priority = raw_priority(which, who);
    if (priority < 0) printf("%s: %s\n", name, strerror(errno));
    else printf("%s: nice=%ld\n", name, 20 - priority);
}
/* A thread of a process led by root takes other IDs and acts by the leader's ID. */
static void *limit_thread(void *unused) {
    (void)unused;
    if (syscall(SYS_setresuid, 2000, 2000, 2000)) _exit(105);
    permitted("thread-limit-own", limit_read(syscall(SYS_gettid), RLIMIT_NOFILE));
    permitted("thread-limit-leader", limit_read(getpid(), RLIMIT_NOFILE));
    permitted("thread-nice-own", setpriority(PRIO_PROCESS, 0, 15));
    permitted("thread-nice-leader", setpriority(PRIO_PROCESS, getpid(), 15));
    return NULL;
}
static void finish(pid_t pid) {
    int status = 0;
    result("wait", waitpid(pid, &status, 0) == pid);
    result("status", status);
}
/* The cpu-state case: the 16 XMM registers from `in`, `fxsave` into `area`. */
static void fx_save_from(const unsigned char *in, unsigned char *area, int wide) {
    __asm__ volatile(
        "movdqu 0(%0),%%xmm0\n movdqu 16(%0),%%xmm1\n movdqu 32(%0),%%xmm2\n movdqu 48(%0),%%xmm3\n"
        "movdqu 64(%0),%%xmm4\n movdqu 80(%0),%%xmm5\n movdqu 96(%0),%%xmm6\n movdqu 112(%0),%%xmm7\n"
        "movdqu 128(%0),%%xmm8\n movdqu 144(%0),%%xmm9\n movdqu 160(%0),%%xmm10\n movdqu 176(%0),%%xmm11\n"
        "movdqu 192(%0),%%xmm12\n movdqu 208(%0),%%xmm13\n movdqu 224(%0),%%xmm14\n movdqu 240(%0),%%xmm15\n"
        "test %2,%2\n jnz 1f\n fxsave (%1)\n jmp 2f\n 1: fxsave64 (%1)\n 2:\n"
        : : "r"(in), "r"(area), "r"(wide)
        : "memory", "cc", "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7", "xmm8", "xmm9",
          "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15");
}
/* `fxrstor` from `area`, and the 16 XMM registers into `out`. */
static void fx_restore_to(const unsigned char *area, unsigned char *out, int wide) {
    __asm__ volatile(
        "test %2,%2\n jnz 1f\n fxrstor (%0)\n jmp 2f\n 1: fxrstor64 (%0)\n 2:\n"
        "movdqu %%xmm0,0(%1)\n movdqu %%xmm1,16(%1)\n movdqu %%xmm2,32(%1)\n movdqu %%xmm3,48(%1)\n"
        "movdqu %%xmm4,64(%1)\n movdqu %%xmm5,80(%1)\n movdqu %%xmm6,96(%1)\n movdqu %%xmm7,112(%1)\n"
        "movdqu %%xmm8,128(%1)\n movdqu %%xmm9,144(%1)\n movdqu %%xmm10,160(%1)\n movdqu %%xmm11,176(%1)\n"
        "movdqu %%xmm12,192(%1)\n movdqu %%xmm13,208(%1)\n movdqu %%xmm14,224(%1)\n movdqu %%xmm15,240(%1)\n"
        : : "r"(area), "r"(out), "r"(wide)
        : "memory", "cc", "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7", "xmm8", "xmm9",
          "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15");
}
/* The x87 case. Each value goes in as its 80-bit image. The status word leaves
   out what the manuals leave undefined after these instructions: C0, C2, C3. */
struct x87_value {
    uint64_t mantissa;
    uint16_t high;
};
static const struct x87_value x87_values[] = {
    {0, 0},                                  /* +0 */
    {0, 0x8000},                             /* -0 */
    {1ULL << 63, 0x3fff},                    /* 1 */
    {3ULL << 62, 0xbfff},                    /* -1.5 */
    {(1ULL << 63) | 1, 0x3fff},              /* just above 1 */
    {(1ULL << 63) | 1, 0xbfff},              /* just below -1 */
    {5ULL << 61, 0x4000},                    /* 2.5 */
    {7ULL << 61, 0x4000},                    /* 3.5 */
    {5ULL << 61, 0xc000},                    /* -2.5 */
    {1ULL << 63, 0x4000 + 14},               /* 32768 */
    {1ULL << 63, 0xc000 + 14},               /* -32768 */
    {0xc000000000000000ULL, 0xc000 + 14},    /* -49152 */
    {1ULL << 63, 0x4000 + 30},               /* 2^31 */
    {1ULL << 63, 0xc000 + 30},               /* -2^31 */
    {1ULL << 63, 0x4000 + 62},               /* 2^63 */
    {1ULL << 63, 0xc000 + 62},               /* -2^63 */
    {~0ULL, 0x4000 + 61},                    /* just under 2^63 */
    {1ULL << 63, 0x7000},                    /* too large for a double */
    {1ULL << 63, 0xf000},
    {~0ULL, 0x47fe},                         /* rounds up to a double's overflow */
    {1ULL << 63, 0x0100},                    /* too small for a double */
    {1ULL << 63, 0x8100},
    {1ULL << 63, 0x3c01},                    /* a double's smallest normal */
    {1ULL << 63, 0x3bcd},                    /* a double's smallest denormal */
    {3ULL << 62, 0x3bcc},                    /* rounds to it */
    {~0ULL, 0x3c00},                         /* rounds up to the smallest normal */
    {1ULL << 63, 0x3f81},                    /* a float's smallest normal */
    {1ULL << 63, 0x3f6a},                    /* a float's smallest denormal */
    {1, 0},                                  /* a denormal */
    {1ULL << 63, 0},                         /* a pseudo-denormal */
    {1ULL << 63, 0x7fff},                    /* infinity */
    {1ULL << 63, 0xffff},
    {3ULL << 62, 0x7fff},                    /* a quiet NaN */
    {0xc000000000000123ULL, 0xffff},
    {0x8000000000000800ULL, 0x7fff},         /* a signaling NaN */
    {1, 0x3fff},                             /* no integer bit: not supported */
    {0, 0x7fff},
    {1, 0x7fff},
};
static uint16_t x87_status(void) {
    uint16_t status;
    __asm__ volatile("fnstsw %0" : "=m"(status));
    return status & 0xbaff;
}
static void x87_control(uint16_t control) {
    __asm__ volatile("fldcw %0" : : "m"(control));
}
static void x87_load(const struct x87_value *v) {
    __asm__ volatile("fldt %0" : : "m"(*v));
}
static void x87_show(const char *name, const void *bytes, int size, int shown) {
    const unsigned char *p = bytes;
    printf("%s ", name);
    for (int i = size; i-- > 0;) printf("%02x", p[i]);
    printf(" sw=%04x\n", shown);
}
/* The FP state a signal frame has: its words, tags, MXCSR and the top. */
static void x87_frame(const char *name, void *context) {
    const unsigned char *f = (const unsigned char *)((ucontext_t *)context)->uc_mcontext.fpregs;
    uint16_t control, status;
    uint32_t mxcsr;
    memcpy(&control, f, 2);
    memcpy(&status, f + 2, 2);
    memcpy(&mxcsr, f + 24, 4);
    printf("%s: frame cw=%04x sw=%04x tags=%02x mxcsr=%x st0=", name, control, status & 0xbaff, f[4], mxcsr);
    for (int i = 9; i >= 0; i--) printf("%02x", f[32 + i]);
    printf("\n");
}
static void x87_signal(int number, siginfo_t *info, void *context) {
    (void)number;
    (void)info;
    uint16_t control, status;
    uint32_t mxcsr;
    __asm__ volatile("fnstcw %0\n fnstsw %1\n stmxcsr %2" : "=m"(control), "=m"(status), "=m"(mxcsr));
    printf("handler: cw=%04x sw=%04x mxcsr=%x\n", control, status, mxcsr);
    x87_frame("handler", context);
    /* What it does here is gone when it returns. */
    __asm__ volatile("fldz\n fldz");
    x87_control(0xc7f);
}
static void x87_fault(int number, siginfo_t *info, void *context) {
    (void)number;
    printf("fault: code=%d\n", info->si_code);
    x87_frame("fault", context);
    fflush(stdout);
    _exit(0);
}
static void x87_cases(void) {
    uint16_t control, status;
    __asm__ volatile("fnstcw %0\n fnstsw %1" : "=m"(control), "=m"(status));
    printf("start: cw=%04x sw=%04x\n", control, status);
    static const uint16_t controls[] = {0xffff, 0, 0x1000, 0x37f};
    for (int i = 0; i < 4; i++) {
        uint16_t written = controls[i], read;
        __asm__ volatile("fldcw %1\n fnstcw %0\n fninit" : "=m"(read) : "m"(written));
        printf("control %04x: %04x\n", written, read);
    }
    int count = (int)(sizeof x87_values / sizeof x87_values[0]);
    /* Into each smaller format and integer, in each rounding mode. */
    for (int mode = 0; mode < 4; mode++) {
        x87_control((uint16_t)(0x37f | mode << 10));
        for (int i = 0; i < count; i++) {
            uint64_t d = 0x5555555555555555ULL, q = d;
            uint32_t s = 0x55555555, l = s;
            uint16_t w = 0x5555;
            char name[32];
            int shown;
            __asm__ volatile("fnclex");
            x87_load(&x87_values[i]);
            __asm__ volatile("fstl %0" : "=m"(d));
            shown = x87_status();
            sprintf(name, "%d %d double", mode, i);
            x87_show(name, &d, 8, shown);
            __asm__ volatile("fnclex\n fsts %0" : "=m"(s));
            shown = x87_status();
            sprintf(name, "%d %d float", mode, i);
            x87_show(name, &s, 4, shown);
            __asm__ volatile("fnclex\n fists %0" : "=m"(w));
            shown = x87_status();
            sprintf(name, "%d %d int16", mode, i);
            x87_show(name, &w, 2, shown);
            __asm__ volatile("fnclex\n fistl %0" : "=m"(l));
            shown = x87_status();
            sprintf(name, "%d %d int32", mode, i);
            x87_show(name, &l, 4, shown);
            __asm__ volatile("fnclex\n fistpll %0" : "=m"(q));
            shown = x87_status();
            sprintf(name, "%d %d int64", mode, i);
            x87_show(name, &q, 8, shown);
        }
    }
    __asm__ volatile("fninit");
    /* Each kind of value, by fxam, which is defined on C0, C1, C2 and C3. */
    for (int i = 0; i < count; i++) {
        uint16_t kind;
        x87_load(&x87_values[i]);
        __asm__ volatile("fxam\n fnstsw %0\n fstp %%st(0)" : "=m"(kind));
        printf("kind %d: %04x\n", i, kind);
    }
    /* Each kind of value compared with some, both ways: the flags, and only
       the invalid and denormal exceptions and the stack move as they should. */
    for (int i = 0; i < count; i++) {
        static const int partners[] = {0, 2, 3, 6, 28, 30, 31, 32, 34, 35};
        for (int k = 0; k < 10; k++) {
            uint64_t flags[4];
            uint16_t status[4];
            x87_load(&x87_values[partners[k]]);
            x87_load(&x87_values[i]);
            __asm__ volatile("fnclex\n fcomi %%st(1), %%st\n pushfq\n popq %0\n fnstsw %1" : "=r"(flags[0]), "=m"(status[0]) : : "cc");
            __asm__ volatile("fnclex\n fucomi %%st(1), %%st\n pushfq\n popq %0\n fnstsw %1" : "=r"(flags[1]), "=m"(status[1]) : : "cc");
            __asm__ volatile("fnclex\n fcomip %%st(1), %%st\n pushfq\n popq %0\n fnstsw %1" : "=r"(flags[2]), "=m"(status[2]) : : "cc");
            x87_load(&x87_values[i]);
            __asm__ volatile("fnclex\n fucomip %%st(1), %%st\n pushfq\n popq %0\n fnstsw %1" : "=r"(flags[3]), "=m"(status[3]) : : "cc");
            __asm__ volatile("fstp %st(0)");
            printf("compare %d %d:", i, partners[k]);
            for (int m = 0; m < 4; m++) printf(" %03llx/%04x", (unsigned long long)flags[m] & 0x8d5, status[m] & 0xbaff);
            printf("\n");
        }
    }
    __asm__ volatile("fnclex\n fninit");
    /* Back and forth through the 80-bit format, and with the sign changed. */
    for (int i = 0; i < count; i++) {
        unsigned char out[10], negated[10], absolute[10];
        x87_load(&x87_values[i]);
        __asm__ volatile("fstpt %0" : "=m"(out));
        x87_load(&x87_values[i]);
        __asm__ volatile("fchs\n fstpt %0" : "=m"(negated));
        x87_load(&x87_values[i]);
        __asm__ volatile("fabs\n fstpt %0" : "=m"(absolute));
        printf("extended %d: ", i);
        for (int k = 9; k >= 0; k--) printf("%02x", out[k]);
        printf(" ");
        for (int k = 9; k >= 0; k--) printf("%02x", negated[k]);
        printf(" ");
        for (int k = 9; k >= 0; k--) printf("%02x", absolute[k]);
        printf(" sw=%04x\n", x87_status());
    }
    /* From the smaller formats and integers. */
    static const uint64_t doubles[] = {0, 1ULL << 63, 0x3ff8000000000000ULL, 0xc008000000000000ULL, 1, 0x800fffffffffffffULL,
                                       0x7ff0000000000000ULL, 0xfff0000000000000ULL, 0x7ff8000000000123ULL,
                                       0x7ff0000000000123ULL, 0xfff0000000000001ULL};
    for (int i = 0; i < 11; i++) {
        unsigned char out[10];
        __asm__ volatile("fnclex\n fldl %1\n fnstsw %%ax\n fstpt %0" : "=m"(out) : "m"(doubles[i]) : "ax");
        int shown = x87_status();
        x87_show("from double", out, 10, shown);
    }
    static const uint32_t floats[] = {0, 1u << 31, 0x3fc00000, 1, 0x807fffff, 0x7f800000, 0xff800000, 0x7fc00123, 0x7f800123};
    for (int i = 0; i < 9; i++) {
        unsigned char out[10];
        __asm__ volatile("fnclex\n flds %1\n fstpt %0" : "=m"(out) : "m"(floats[i]));
        int shown = x87_status();
        x87_show("from float", out, 10, shown);
    }
    static const int64_t integers[] = {0, 1, -1, 32767, -32768, 2147483647, -2147483647 - 1, INT64_MAX, INT64_MIN};
    for (int i = 0; i < 9; i++) {
        unsigned char q[10], l[10], w[10];
        int32_t l_in = (int32_t)integers[i];
        int16_t w_in = (int16_t)integers[i];
        __asm__ volatile("fildll %3\n fstpt %0\n fildl %4\n fstpt %1\n filds %5\n fstpt %2"
                         : "=m"(q), "=m"(l), "=m"(w) : "m"(integers[i]), "m"(l_in), "m"(w_in));
        x87_show("from int64", q, 10, x87_status());
        x87_show("from int32", l, 10, x87_status());
        x87_show("from int16", w, 10, x87_status());
    }
    /* The stack: a ninth value overflows, and C1 says so. */
    __asm__ volatile("fninit");
    for (int i = 0; i < 9; i++) {
        __asm__ volatile("fld1");
        printf("push %d: sw=%04x\n", i, x87_status());
    }
    __asm__ volatile("fnclex\n fninit");
    /* Reading what is empty: C1 clear, and the invalid result. */
    {
        uint64_t d = 0;
        uint32_t s = 0;
        uint16_t w = 0;
        unsigned char e[10];
        __asm__ volatile("fld1\n fstp %%st(0)\n fstl %0" : "=m"(d));
        x87_show("empty double", &d, 8, x87_status());
        __asm__ volatile("fnclex\n fsts %0" : "=m"(s));
        x87_show("empty float", &s, 4, x87_status());
        __asm__ volatile("fnclex\n fists %0" : "=m"(w));
        x87_show("empty int16", &w, 2, x87_status());
        __asm__ volatile("fnclex\n fstpt %0" : "=m"(e));
        x87_show("empty extended", e, 10, x87_status());
        __asm__ volatile("fninit\n fld %%st(2)\n fstpt %0" : "=m"(e));
        x87_show("empty register", e, 10, x87_status());
        __asm__ volatile("fninit\n fchs\n fstpt %0" : "=m"(e));
        x87_show("empty fchs", e, 10, x87_status());
        __asm__ volatile("fninit\n fabs\n fstpt %0" : "=m"(e));
        x87_show("empty fabs", e, 10, x87_status());
        __asm__ volatile("fninit\n fld1\n fxch %%st(2)\n fstpt %0" : "=m"(e));
        x87_show("empty fxch", e, 10, x87_status());
        __asm__ volatile("fstpt %0" : "=m"(e));
        x87_show("empty fxch st1", e, 10, x87_status());
        __asm__ volatile("fstpt %0" : "=m"(e));
        x87_show("empty fxch st2", e, 10, x87_status());
        __asm__ volatile("fninit\n fstp %st(1)");
        printf("empty fstp: sw=%04x\n", x87_status());
    }
    /* Moving between registers, and freeing. */
    {
        unsigned char a[10], b[10], c[10];
        __asm__ volatile("fninit\n fld1\n fldz\n fxch\n fstpt %0\n fstpt %1" : "=m"(a), "=m"(b));
        x87_show("fxch st0", a, 10, x87_status());
        x87_show("fxch st1", b, 10, x87_status());
        __asm__ volatile("fninit\n fld1\n fldz\n fst %%st(1)\n fstpt %0\n fstpt %1" : "=m"(a), "=m"(b));
        x87_show("fst st0", a, 10, x87_status());
        x87_show("fst st1", b, 10, x87_status());
        __asm__ volatile("fninit\n fld1\n fld %%st(0)\n fstp %%st(1)\n fstpt %0" : "=m"(c));
        x87_show("fstp st1", c, 10, x87_status());
        uint16_t kind;
        __asm__ volatile("fninit\n fld1\n ffree %%st(0)\n fxam\n fnstsw %0" : "=m"(kind));
        printf("freed: %04x\n", kind);
        __asm__ volatile("fninit\n fincstp");
        printf("fincstp: sw=%04x\n", x87_status());
        __asm__ volatile("fdecstp\n fdecstp");
        printf("fdecstp: sw=%04x\n", x87_status());
        __asm__ volatile("fninit\n fnop\n wait");
        printf("fnop: sw=%04x\n", x87_status());
    }
    /* fstcw, fstsw, finit and fclex have a wait in front. */
    {
        uint16_t c, s;
        short ax;
        __asm__ volatile("finit\n fldz\n fstcw %0\n fstsw %1\n fstsw %%ax\n mov %%ax, %2\n fclex"
                         : "=m"(c), "=m"(s), "=m"(ax) : : "ax");
        printf("waiting: cw=%04x sw=%04x ax=%04x\n", c, s, (unsigned short)ax);
    }
    /* The environment: its words, and every exception masked after it. */
    {
        uint16_t env[14];
        uint16_t after;
        memset(env, 0x55, sizeof env);
        /* With exceptions unmasked, none being pending, to see them masked after. */
        __asm__ volatile("fninit\n fld1\n fldz\n flds %2\n fldcw %3\n fnstenv %0\n fnstcw %1"
                         : "+m"(env), "=m"(after)
                         : "m"(floats[5]), "m"(*(const uint16_t[]){0x260}));
        printf("environment: cw=%04x sw=%04x tags=%04x then cw=%04x reserved=%04x %04x %04x %04x\n", env[0],
               env[2] & 0xbaff, env[4], after, env[1], env[3], env[5], env[13]);
        __asm__ volatile("fninit\n fldenv %1\n fnstcw %0" : "=m"(after) : "m"(env));
        printf("loaded: cw=%04x sw=%04x\n", after, x87_status());
        unsigned char e[10];
        __asm__ volatile("fstpt %0" : "=m"(e));
        x87_show("loaded st0", e, 10, x87_status());
        __asm__ volatile("fstpt %0" : "=m"(e));
        x87_show("loaded st1", e, 10, x87_status());
    }
    /* fxsave and fxrstor keep it all. Where the last instruction was is left
       out: CPUs differ. */
    {
        static _Alignas(16) unsigned char area[512];
        __asm__ volatile("fninit\n fld1\n fldz\n fxsave %0" : "=m"(area));
        printf("fxsave: cw=%02x%02x sw=%04x tags=%02x\n", area[1], area[0], (area[2] | area[3] << 8) & 0xbaff, area[4]);
        for (int r = 0; r < 8; r++) {
            printf("  st%d ", r);
            for (int k = 9; k >= 0; k--) printf("%02x", r < 2 ? area[32 + r * 16 + k] : 0);
            printf("\n");
        }
        __asm__ volatile("fninit\n fxrstor %0" : : "m"(area));
        unsigned char a[10], b[10];
        x87_show("fxrstor status", area, 0, x87_status());
        __asm__ volatile("fstpt %0\n fstpt %1" : "=m"(a), "=m"(b));
        x87_show("fxrstor st0", a, 10, x87_status());
        x87_show("fxrstor st1", b, 10, x87_status());
    }
}
/* The x87 arithmetic case. C0, C2 and C3 are left out where the manuals leave
   them undefined. x87_clear keeps the control word. */
static void x87_clear(void) {
    uint16_t control;
    __asm__ volatile("fnstcw %0\n fninit\n fldcw %0" : "+m"(control));
}
static uint64_t x87_random_state = 0x123456789abcdefULL;
static uint64_t x87_random(void) {
    x87_random_state ^= x87_random_state << 13;
    x87_random_state ^= x87_random_state >> 7;
    x87_random_state ^= x87_random_state << 17;
    return x87_random_state;
}
/* Near each other often, so that subtracting cancels; and near the ends of the
   range, so that results overflow and go denormal. */
static struct x87_value x87_random_value(uint16_t near) {
    static const uint16_t exponents[] = {0x3fff, 0x4000, 0x3fff + 20, 0x3fff - 20, 0x3fff + 63, 0x3fff - 70,
                                         0x7ffe, 0x7f00, 0x0001, 0x0040, 0x2000, 0};
    uint64_t pick = x87_random();
    uint16_t exponent = exponents[pick % 12];
    if (near != 0xffff && pick >> 8 & 1) {
        exponent = (uint16_t)((near & 0x7fff) + (pick >> 16 & 3) - 1);
        if (exponent > 0x7ffe) exponent = 0x7ffe;
    }
    uint64_t mantissa = x87_random();
    /* Long runs of bits, which carry. */
    if (pick >> 24 & 1) mantissa = pick >> 25 & 1 ? mantissa | ~0ULL << (pick >> 32 & 63) : mantissa & ~0ULL << (pick >> 32 & 63);
    mantissa = exponent ? mantissa | 1ULL << 63 : mantissa & ~(1ULL << 63);
    struct x87_value v = {mantissa, (uint16_t)(exponent | (pick >> 40 & 1) << 15)};
    return v;
}
/* These lines are many: written by hand, the case takes far less time than
   through printf, most of all under the coverage build's watchdog. */
static int x87_mode_shown = -1, x87_precision_shown = -1;
static char *x87_put_number(char *p, int n) {
    char digits[12];
    int count = 0;
    if (n < 0) return p;
    *p++ = ' ';
    do digits[count++] = (char)('0' + n % 10); while (n /= 10);
    while (count) *p++ = digits[--count];
    return p;
}
static char *x87_put_hex(char *p, const unsigned char *bytes, int size) {
    static const char hex[] = "0123456789abcdef";
    for (int i = size; i-- > 0;) {
        *p++ = hex[bytes[i] >> 4];
        *p++ = hex[bytes[i] & 15];
    }
    return p;
}
static void x87_line(const char *label, int first, int second, int third, const void *bytes, int size, int shown) {
    char line[128], *p = line;
    while (*label) *p++ = *label++;
    p = x87_put_number(p, x87_mode_shown);
    p = x87_put_number(p, x87_precision_shown);
    p = x87_put_number(p, first);
    p = x87_put_number(p, second);
    p = x87_put_number(p, third);
    *p++ = ' ';
    p = x87_put_hex(p, bytes, size);
    *p++ = ' ';
    unsigned char word[2] = {(unsigned char)shown, (unsigned char)(shown >> 8)};
    p = x87_put_hex(p, word, 2);
    *p++ = '\n';
    fwrite(line, 1, (size_t)(p - line), stdout);
}
#define X87_PAIR(label, form, a, b, i, j) do { \
        unsigned char out_[10]; \
        uint16_t sw_; \
        x87_load(b); \
        x87_load(a); \
        __asm__ volatile("fnclex\n " form "\n fnstsw %1\n fstpt %0" : "=m"(out_), "=m"(sw_)); \
        x87_clear(); \
        x87_line(label, i, j, -1, out_, 10, sw_ & 0xbaff); \
    } while (0)
#define X87_SINGLE(label, form, a, i) do { \
        unsigned char out_[10]; \
        uint16_t sw_; \
        x87_load(a); \
        __asm__ volatile("fnclex\n " form "\n fnstsw %1\n fstpt %0" : "=m"(out_), "=m"(sw_)); \
        x87_clear(); \
        x87_line(label, i, -1, -1, out_, 10, sw_ & 0xbaff); \
    } while (0)
/* What is left and how it is said, once it is done. Going part of the way, how
   far it goes and so the quotient's bits are the CPU's choice. */
static void x87_remainder(const char *label, int nearest, const struct x87_value *a, const struct x87_value *b, int i, int j) {
    unsigned char out[10];
    uint16_t sw;
    int rounds = 0;
    x87_load(b);
    x87_load(a);
    __asm__ volatile("fnclex");
    do {
        if (nearest) __asm__ volatile("fprem1\n fnstsw %0" : "=m"(sw));
        else __asm__ volatile("fprem\n fnstsw %0" : "=m"(sw));
        rounds++;
    } while (sw & 0x400 && rounds < 100000);
    __asm__ volatile("fstpt %0" : "=m"(out));
    x87_clear();
    x87_line(label, rounds > 1, i, j, out, 10, rounds > 1 ? sw & 0xbaff & ~0x200 : sw);
}
static void x87_arithmetic_cases(void) {
    static const unsigned char out_none[1] = {0};
    __asm__ volatile("fninit");
    int count = (int)(sizeof x87_values / sizeof x87_values[0]);
    /* Each kind of value with each, in each of the operations. */
    for (int i = 0; i < count; i++) {
        for (int j = 0; j < count; j++) {
            const struct x87_value *a = &x87_values[i], *b = &x87_values[j];
            X87_PAIR("add", "fadd %%st(1), %%st", a, b, i, j);
            X87_PAIR("sub", "fsub %%st(1), %%st", a, b, i, j);
            X87_PAIR("mul", "fmul %%st(1), %%st", a, b, i, j);
            X87_PAIR("div", "fdiv %%st(1), %%st", a, b, i, j);
            X87_PAIR("scale", "fscale", a, b, i, j);
            x87_remainder("prem", 0, a, b, i, j);
            x87_remainder("prem1", 1, a, b, i, j);
        }
    }
    /* Each rounding and precision, on the values that show them. */
    static const int some[] = {0, 2, 3, 4, 5, 6, 16, 17, 19, 20, 22, 25, 28, 29};
    int several = (int)(sizeof some / sizeof some[0]);
    static const uint16_t precisions[] = {0, 2 << 8, 3 << 8};
    for (int mode = 0; mode < 4; mode++) {
        for (int p = 0; p < 3; p++) {
            x87_control((uint16_t)(0x7f | mode << 10 | precisions[p]));
            x87_mode_shown = mode;
            x87_precision_shown = p;
            for (int i = 0; i < several; i++) {
                const struct x87_value *a = &x87_values[some[i]];
                X87_SINGLE("sqrt", "fsqrt", a, i);
                X87_SINGLE("rndint", "frndint", a, i);
                for (int j = 0; j < several; j++) {
                    const struct x87_value *b = &x87_values[some[j]];
                    X87_PAIR("add", "fadd %%st(1), %%st", a, b, i, j);
                    X87_PAIR("sub", "fsub %%st(1), %%st", a, b, i, j);
                    X87_PAIR("mul", "fmul %%st(1), %%st", a, b, i, j);
                    X87_PAIR("div", "fdiv %%st(1), %%st", a, b, i, j);
                    X87_PAIR("scale", "fscale", a, b, i, j);
                }
            }
            /* Long values, in the same way. */
            for (int n = 0; n < 60; n++) {
                struct x87_value a = x87_random_value(0xffff), b = x87_random_value(a.high);
                X87_PAIR("long add", "fadd %%st(1), %%st", &a, &b, n, 0);
                X87_PAIR("long sub", "fsub %%st(1), %%st", &a, &b, n, 0);
                X87_PAIR("long mul", "fmul %%st(1), %%st", &a, &b, n, 0);
                X87_PAIR("long div", "fdiv %%st(1), %%st", &a, &b, n, 0);
                X87_SINGLE("long sqrt", "fsqrt", &a, n);
                X87_SINGLE("long rndint", "frndint", &a, n);
            }
        }
    }
    x87_mode_shown = x87_precision_shown = -1;
    x87_control(0x37f);
    /* Long remainders. */
    for (int n = 0; n < 150; n++) {
        struct x87_value a = x87_random_value(0xffff), b = x87_random_value(a.high);
        if (n & 1) b = x87_random_value(0xffff);
        x87_remainder("long prem", 0, &a, &b, n, 0);
        x87_remainder("long prem1", 1, &a, &b, n, 0);
    }
    /* The other operand forms: the reversed ones, into st(1), and popping. */
    {
        const struct x87_value *a = &x87_values[6], *b = &x87_values[3];
        X87_PAIR("form", "fsubr %%st(1), %%st", a, b, 0, 0);
        X87_PAIR("form", "fdivr %%st(1), %%st", a, b, 0, 1);
        X87_PAIR("form", "fadd %%st, %%st(1)\n fxch", a, b, 0, 2);
        X87_PAIR("form", "fsub %%st, %%st(1)\n fxch", a, b, 0, 3);
        X87_PAIR("form", "fsubr %%st, %%st(1)\n fxch", a, b, 0, 4);
        X87_PAIR("form", "fmul %%st, %%st(1)\n fxch", a, b, 0, 5);
        X87_PAIR("form", "fdiv %%st, %%st(1)\n fxch", a, b, 0, 6);
        X87_PAIR("form", "fdivr %%st, %%st(1)\n fxch", a, b, 0, 7);
        X87_PAIR("form", "faddp", a, b, 0, 8);
        X87_PAIR("form", "fsubp", a, b, 0, 9);
        X87_PAIR("form", "fsubrp", a, b, 0, 10);
        X87_PAIR("form", "fmulp", a, b, 0, 11);
        X87_PAIR("form", "fdivp", a, b, 0, 12);
        X87_PAIR("form", "fdivrp", a, b, 0, 13);
    }
    /* From memory: each value of the smaller formats, into each of some. */
    static const uint64_t doubles[] = {0, 1ULL << 63, 0x3ff8000000000000ULL, 0xc008000000000000ULL, 1, 0x800fffffffffffffULL,
                                       0x7ff0000000000000ULL, 0xfff0000000000000ULL, 0x7ff8000000000123ULL,
                                       0x7ff0000000000123ULL, 0xfff0000000000001ULL};
    static const uint32_t floats[] = {0, 1u << 31, 0x3fc00000, 1, 0x807fffff, 0x7f800000, 0xff800000, 0x7fc00123, 0x7f800123};
    static const int16_t shorts[] = {0, 1, -1, 3, 32767, -32768};
    static const int32_t longs[] = {0, 1, -1, 3, 2147483647, -2147483647 - 1};
    static const int partners[] = {0, 1, 2, 3, 6, 28, 30, 31, 32, 34, 35};
    for (int k = 0; k < 11; k++) {
        const struct x87_value *a = &x87_values[partners[k]];
        for (int i = 0; i < 11; i++) {
            const uint64_t *m = &doubles[i];
#define X87_MEMORY(label, form) do { \
                unsigned char out_[10]; \
                uint16_t sw_; \
                x87_load(a); \
                __asm__ volatile("fnclex\n " form " %2\n fnstsw %1\n fstpt %0" : "=m"(out_), "=m"(sw_) : "m"(*m)); \
                x87_clear(); \
                x87_line(label, k, i, -1, out_, 10, sw_ & 0xbaff); \
            } while (0)
#define X87_ORDER(label, form) do { \
                uint16_t sw_; \
                x87_load(a); \
                __asm__ volatile("fnclex\n " form " %1\n fnstsw %0" : "=m"(sw_) : "m"(*m)); \
                x87_clear(); \
                x87_line(label, k, i, -1, out_none, 0, sw_); \
            } while (0)
            X87_MEMORY("faddl", "faddl");
            X87_MEMORY("fsubl", "fsubl");
            X87_MEMORY("fsubrl", "fsubrl");
            X87_MEMORY("fmull", "fmull");
            X87_MEMORY("fdivl", "fdivl");
            X87_MEMORY("fdivrl", "fdivrl");
            X87_ORDER("fcoml", "fcoml");
            X87_ORDER("fcompl", "fcompl");
        }
        for (int i = 0; i < 9; i++) {
            const uint32_t *m = &floats[i];
            X87_MEMORY("fadds", "fadds");
            X87_MEMORY("fsubs", "fsubs");
            X87_MEMORY("fsubrs", "fsubrs");
            X87_MEMORY("fmuls", "fmuls");
            X87_MEMORY("fdivs", "fdivs");
            X87_MEMORY("fdivrs", "fdivrs");
            X87_ORDER("fcoms", "fcoms");
            X87_ORDER("fcomps", "fcomps");
        }
        for (int i = 0; i < 6; i++) {
            {
                const int16_t *m = &shorts[i];
                X87_MEMORY("fiadds", "fiadds");
                X87_MEMORY("fisubs", "fisubs");
                X87_MEMORY("fisubrs", "fisubrs");
                X87_MEMORY("fimuls", "fimuls");
                X87_MEMORY("fidivs", "fidivs");
                X87_MEMORY("fidivrs", "fidivrs");
                X87_ORDER("ficoms", "ficoms");
                X87_ORDER("ficomps", "ficomps");
            }
            {
                const int32_t *m = &longs[i];
                X87_MEMORY("fiaddl", "fiaddl");
                X87_MEMORY("fisubl", "fisubl");
                X87_MEMORY("fisubrl", "fisubrl");
                X87_MEMORY("fimull", "fimull");
                X87_MEMORY("fidivl", "fidivl");
                X87_MEMORY("fidivrl", "fidivrl");
                X87_ORDER("ficoml", "ficoml");
                X87_ORDER("ficompl", "ficompl");
            }
        }
    }
    /* One operand, of each kind of value. */
    for (int i = 0; i < count; i++) {
        const struct x87_value *a = &x87_values[i];
        unsigned char m[10], e[10];
        uint16_t sw;
        X87_SINGLE("sqrt", "fsqrt", a, i);
        X87_SINGLE("rndint", "frndint", a, i);
        x87_load(a);
        __asm__ volatile("fnclex\n fxtract\n fnstsw %2\n fstpt %0\n fstpt %1" : "=m"(m), "=m"(e), "=m"(sw));
        x87_clear();
        printf("extract %d ", i);
        x87_show("mantissa", m, 10, sw & 0xbaff);
        x87_show("exponent", e, 10, 0);
        x87_load(a);
        __asm__ volatile("fnclex\n ftst\n fnstsw %0" : "=m"(sw));
        x87_clear();
        printf("ftst %d %04x\n", i, sw);
    }
    /* Each kind of value compared with each, in the condition bits. */
    for (int i = 0; i < count; i++) {
        for (int j = 0; j < count; j++) {
            uint16_t sw[6];
            x87_load(&x87_values[j]);
            x87_load(&x87_values[i]);
            __asm__ volatile("fnclex\n fcom %%st(1)\n fnstsw %0\n fnclex\n fucom %%st(1)\n fnstsw %1" : "=m"(sw[0]), "=m"(sw[1]));
            __asm__ volatile("fnclex\n fcomp %%st(1)\n fnstsw %0" : "=m"(sw[2]));
            x87_load(&x87_values[i]);
            __asm__ volatile("fnclex\n fucomp %%st(1)\n fnstsw %0" : "=m"(sw[3]));
            x87_load(&x87_values[i]);
            __asm__ volatile("fnclex\n fcompp\n fnstsw %0" : "=m"(sw[4]));
            x87_load(&x87_values[j]);
            x87_load(&x87_values[i]);
            __asm__ volatile("fnclex\n fucompp\n fnstsw %0" : "=m"(sw[5]));
            x87_clear();
            x87_line("order", i, j, -1, sw, 12, 0);
        }
    }
    /* The constants, in each rounding. */
    for (int mode = 0; mode < 4; mode++) {
        unsigned char out[10];
        char name[32];
        x87_control((uint16_t)(0x37f | mode << 10));
#define X87_CONSTANT(form) do { \
            __asm__ volatile("fnclex\n " form "\n fstpt %0" : "=m"(out)); \
            sprintf(name, "%s %d", form, mode); \
            x87_show(name, out, 10, x87_status()); \
        } while (0)
        X87_CONSTANT("fldpi");
        X87_CONSTANT("fldln2");
        X87_CONSTANT("fldlg2");
        X87_CONSTANT("fldl2e");
        X87_CONSTANT("fldl2t");
    }
    x87_control(0x37f);
    /* Conditional moves, on each of the flags they read: 0, CF, ZF, PF, and CF
       with ZF. */
    {
        static const uint64_t flags[] = {0x202, 0x203, 0x242, 0x206, 0x243};
        for (int k = 0; k < 5; k++) {
            unsigned char out[8][10];
#define X87_MOVE(n, form) do { \
                __asm__ volatile("fnclex\n fld1\n fldz\n pushq %1\n popfq\n " form " %%st(1), %%st\n fstpt %0\n fstp %%st(0)" \
                                 : "=m"(out[n]) : "m"(flags[k]) : "cc"); \
            } while (0)
            X87_MOVE(0, "fcmovb");
            X87_MOVE(1, "fcmove");
            X87_MOVE(2, "fcmovbe");
            X87_MOVE(3, "fcmovu");
            X87_MOVE(4, "fcmovnb");
            X87_MOVE(5, "fcmovne");
            X87_MOVE(6, "fcmovnbe");
            X87_MOVE(7, "fcmovnu");
            printf("fcmov %d:", k);
            for (int n = 0; n < 8; n++) printf(" %d", out[n][9]);
            printf(" sw=%04x\n", x87_status());
        }
    }
    /* What is empty: the invalid result, and C1 clear. */
    {
        unsigned char out[10];
        uint16_t sw;
        char name[32];
#define X87_EMPTY(form) do { \
            __asm__ volatile("fninit\n " form "\n fnstsw %0" : "=m"(sw)); \
            __asm__ volatile("fstpt %0" : "=m"(out)); \
            sprintf(name, "empty %s", form); \
            x87_show(name, out, 10, sw & 0xbaff); \
        } while (0)
        X87_EMPTY("fsqrt");
        X87_EMPTY("frndint");
        X87_EMPTY("fscale");
        X87_EMPTY("fxtract");
        X87_EMPTY("fprem");
        X87_EMPTY("fprem1");
        X87_EMPTY("fadd %%st(1), %%st");
        X87_EMPTY("fld1\n fadd %%st(1), %%st");
        X87_EMPTY("fld1\n fadd %%st, %%st(1)\n fxch");
        X87_EMPTY("fld1\n faddp\n fldz");
        X87_EMPTY("fld1\n fscale");
        X87_EMPTY("fld1\n fprem");
        X87_EMPTY("fcmovb %%st(1), %%st");
        X87_EMPTY("fld1\n fcmovb %%st(1), %%st");
        X87_EMPTY("fld1\n fcmovnb %%st(1), %%st");
#define X87_EMPTY_ORDER(form) do { \
            __asm__ volatile("fninit\n " form "\n fnstsw %0" : "=m"(sw)); \
            sprintf(name, "empty %s", form); \
            printf("%s %04x\n", name, sw); \
        } while (0)
        X87_EMPTY_ORDER("fcom %%st(1)");
        X87_EMPTY_ORDER("fcomp %%st(1)");
        X87_EMPTY_ORDER("fcompp");
        X87_EMPTY_ORDER("fucom %%st(1)");
        X87_EMPTY_ORDER("fucomp %%st(1)");
        X87_EMPTY_ORDER("fucompp");
        X87_EMPTY_ORDER("ftst");
        X87_EMPTY_ORDER("fld1\n fcom %%st(1)");
        __asm__ volatile("fninit\n fcoml %1\n fnstsw %0" : "=m"(sw) : "m"(doubles[2]));
        printf("empty fcoml %04x\n", sw);
        __asm__ volatile("fninit\n faddl %1\n fnstsw %0\n fstpt %2" : "=m"(sw) : "m"(doubles[2]), "m"(out));
        x87_show("empty faddl", out, 10, sw & 0xbaff);
        /* A full stack, which only fxtract could push onto. */
        __asm__ volatile("fninit\n fld1\n fld1\n fld1\n fld1\n fld1\n fld1\n fld1\n fldz\n fxtract\n fnstsw %0" : "=m"(sw));
        printf("full fxtract: %04x", sw & 0xbaff);
        for (int r = 0; r < 8; r++) {
            __asm__ volatile("fstpt %0" : "=m"(out));
            printf(" ");
            for (int k = 9; k >= 0; k--) printf("%02x", out[k]);
        }
        printf("\n");
        __asm__ volatile("fnclex\n fninit");
    }
}
/* The interpreter of the script-exec case: what exec gave it. */
static int script_show(int argc, char **argv) {
    char name[17] = {0};
    prctl(PR_GET_NAME, name);
    printf("  ran: argc=%d", argc);
    for (int i = 0; i < argc; i++) printf(" [%s]", argv[i]);
    /* Dumpable or not: how it is not depends on fs.suid_dumpable. */
    printf(" execfn=%s name=%s uid=%d euid=%d secure=%lu dumpable=%d\n", (const char *)getauxval(AT_EXECFN),
           name, (int)getuid(), (int)geteuid(), getauxval(AT_SECURE), prctl(PR_GET_DUMPABLE) == 1);
    return 0;
}
/* A file `path` of `length` bytes with the mode `mode`. */
static void script_file(const char *path, const char *bytes, size_t length, unsigned mode) {
    unlink(path);
    int fd = open(path, O_CREAT | O_WRONLY, 0600);
    if (fd < 0 || write(fd, bytes, length) != (long)length || fchmod(fd, mode)) _exit(70);
    close(fd);
}
/* Exec `path` in a child with `args`, as user `uid` if not 0, and how it ended. */
static void script_run(const char *name, const char *path, char *const *args, unsigned uid) {
    char *env[] = {NULL};
    printf("%s:\n", name);
    fflush(stdout);
    pid_t pid = syscall(SYS_fork);
    if (pid == 0) {
        if (uid && (syscall(SYS_setresgid, uid, uid, uid) || syscall(SYS_setresuid, uid, uid, uid))) _exit(71);
        execve(path, args, env);
        printf("  exec: %s\n", strerror(errno));
        fflush(stdout);
        _exit(72);
    }
    int status = 0;
    waitpid(pid, &status, 0);
    printf("  status=%d\n", status);
}
static void script_line(const char *name, const char *line, size_t length) {
    char *args[] = {"./s", "a", "b", NULL};
    script_file("s", line, length, 0755);
    script_run(name, "./s", args, 0);
}
#define SCRIPT_LINE(name, literal) script_line(name, literal, sizeof literal - 1)
/* The lines of /proc/self/maps as they are now, one read at a time. */
static char *maps_text(int fd) {
    static char text[1 << 20];
    size_t length = 0;
    for (;;) {
        ssize_t got = read(fd, text + length, sizeof text - 1 - length);
        if (got <= 0) break;
        length += (size_t)got;
    }
    text[length] = 0;
    return text;
}

struct maps_line {
    unsigned long start, end, offset, inode;
    unsigned major, minor;
    char perms[5];
    int column;
    const char *name;
    int name_length;
    int trailing_space;
};

/* The line of `text` at `line`, whose end it gives back. */
static const char *maps_parse(const char *line, struct maps_line *out) {
    const char *end = strchr(line, '\n');
    if (!end) return NULL;
    int column = 0;
    if (sscanf(line, "%lx-%lx %4s %lx %x:%x %lu%n", &out->start, &out->end, out->perms, &out->offset,
               &out->major, &out->minor, &out->inode, &column) != 7)
        return NULL;
    out->trailing_space = line[column] == ' ';
    while (line[column] == ' ') column++;
    out->column = column;
    out->name = line + column;
    out->name_length = (int)(end - out->name);
    return end + 1;
}

/* The line holding `address`, if a VMA does. */
static int maps_find(const char *text, unsigned long address, struct maps_line *out) {
    while ((text = maps_parse(text, out))) {
        if (out->start <= address && address < out->end) return 1;
    }
    return 0;
}

/* The line holding `at`, without its addresses or inode, its name after
   `prefix` when it starts so. */
static void maps_show(const char *label, const void *at, const char *prefix) {
    struct maps_line line;
    int fd = open("/proc/self/maps", O_RDONLY);
    if (fd < 0 || !maps_find(maps_text(fd), (unsigned long)at, &line)) {
        printf("%s: none\n", label);
    } else {
        const char *name = line.name;
        int length = line.name_length;
        size_t skip = prefix ? strlen(prefix) : 0;
        if (skip && (size_t)length >= skip && !strncmp(name, prefix, skip)) {
            name += skip;
            length -= (int)skip;
        }
        printf("%s: from-here=%d pages=%lu %s offset=%lx space=%d column=%d name=[%.*s]\n", label,
               line.start == (unsigned long)at, (line.end - line.start) / 4096, line.perms,
               line.offset, line.trailing_space, length ? line.column : 0, length, name);
    }
    if (fd >= 0) close(fd);
}

/* Native Linux's gate and vDSO lines are left out, and so are the addresses;
   the stack's size is Linux's to grow. */
static void maps_listing(void) {
    int fd = open("/proc/self/maps", O_RDONLY);
    const char *text = maps_text(fd);
    struct maps_line line;
    unsigned long previous = 0;
    int ordered = 1, aligned = 1;
    while ((text = maps_parse(text, &line))) {
        ordered &= line.start >= previous && line.start < line.end;
        aligned &= !(line.start & 4095) && !(line.end & 4095);
        previous = line.end;
        if (line.name_length > 0 && line.name[0] == '[' && line.name[1] == 'v') continue;
        const char *base = memrchr(line.name, '/', (size_t)line.name_length);
        base = base ? base + 1 : line.name;
        int length = line.name_length - (int)(base - line.name);
        if (length == 7 && !strncmp(base, "[stack]", 7)) {
            printf("  %s stack\n", line.perms);
        } else {
            printf("  %s pages=%lu offset=%lx name=[%.*s]\n", line.perms,
                   (line.end - line.start) / 4096, line.offset, length, base);
        }
    }
    printf("ordered=%d aligned=%d\n", ordered, aligned);
    close(fd);
}

/* After an exec, a descriptor still open reads the old image's lines, of
   which nothing is left once no thread uses it. */
static int maps_after_exec(const char *number) {
    int fd = atoi(number);
    char byte;
    long got = read(fd, &byte, 1);
    printf("after-exec read=%ld\n", got);
    printf("after-exec rewound=%ld\n", (long)lseek(fd, 0, SEEK_SET));
    printf("after-exec read=%ld\n", (long)read(fd, &byte, 1));
    return 0;
}

static int maps_cases(const char *self) {
    long page = 4096;
    maps_listing();

    /* What it is: a regular file of size 0, 0444. */
    struct stat st;
    if (stat("/proc/self/maps", &st)) return 90;
    printf("stat mode=%o size=%ld\n", (unsigned)st.st_mode, (long)st.st_size);
    char pid_path[64];
    snprintf(pid_path, sizeof pid_path, "/proc/%d/maps", (int)getpid());
    int by_pid = open(pid_path, O_RDONLY);
    printf("by-pid=%d\n", by_pid >= 0);
    if (by_pid >= 0) close(by_pid);

    /* Each mapping lies between PROT_NONE pages, so that nothing merges but
       what is placed to. */
    char *base = mmap(NULL, 128 * page, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (base == MAP_FAILED) return 91;
    int flags = MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS;
    char *a = mmap(base + 2 * page, 3 * page, PROT_READ | PROT_WRITE, flags, -1, 0);
    if (a == MAP_FAILED) return 92;
    maps_show("anonymous", a, NULL);
    maps_show("no-access", base, NULL);
    mprotect(a + page, page, PROT_READ);
    maps_show("split-low", a, NULL);
    maps_show("split-middle", a + page, NULL);
    maps_show("split-high", a + 2 * page, NULL);
    mprotect(a + page, page, PROT_READ | PROT_WRITE);
    maps_show("split-rejoined", a, NULL);
    mmap(a + 3 * page, page, PROT_READ | PROT_WRITE, flags, -1, 0);
    maps_show("merged", a, NULL);
    munmap(a + page, page);
    maps_show("hole-low", a, NULL);
    maps_show("hole", a + page, NULL);
    maps_show("hole-high", a + 2 * page, NULL);
    mprotect(base + 12 * page, page, PROT_READ | PROT_EXEC);
    maps_show("execute", base + 12 * page, NULL);

    /* Files, named by their paths. */
    char dir[] = "/tmp/maps-XXXXXX";
    if (!mkdtemp(dir)) return 93;
    char prefix[64];
    snprintf(prefix, sizeof prefix, "%s/", dir);
    if (chdir(dir)) return 94;
    char fill[4 * 4096];
    memset(fill, 'x', sizeof fill);
    int fd = open("data", O_CREAT | O_RDWR, 0644);
    if (fd < 0 || write(fd, fill, sizeof fill) != (long)sizeof fill) return 95;
    char *f = base + 20 * page;
    if (mmap(f, 2 * page, PROT_READ, MAP_FIXED | MAP_PRIVATE, fd, page) == MAP_FAILED) return 96;
    maps_show("file-private", f, prefix);
    {
        struct maps_line line;
        int maps = open("/proc/self/maps", O_RDONLY);
        struct stat file;
        if (maps < 0 || fstat(fd, &file) || !maps_find(maps_text(maps), (unsigned long)f, &line))
            return 97;
        printf("file-inode-matches=%d\n", line.inode == (unsigned long)file.st_ino);
        close(maps);
    }
    if (mmap(f + 4 * page, page, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_SHARED, fd, 2 * page) == MAP_FAILED)
        return 98;
    maps_show("file-shared", f + 4 * page, prefix);
    if (mmap(f + 8 * page, page, PROT_READ, MAP_FIXED | MAP_SHARED, fd, 0) == MAP_FAILED) return 99;
    maps_show("file-shared-read-only", f + 8 * page, prefix);
    /* The same file at the next page merges; a written private page stays. */
    if (mmap(f + 12 * page, page, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_PRIVATE, fd, 0) == MAP_FAILED ||
        mmap(f + 13 * page, page, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_PRIVATE, fd, page) == MAP_FAILED)
        return 100;
    f[12 * page] = 1;
    maps_show("file-merged", f + 12 * page, prefix);
    mprotect(f + 13 * page, page, PROT_READ);
    maps_show("file-split", f + 13 * page, prefix);

    /* A space and a backslash stay; a newline is octal. */
    int odd = open("a b\\c\nd", O_CREAT | O_RDWR, 0644);
    if (odd < 0 || write(odd, fill, (size_t)page) != page) return 101;
    if (mmap(f + 16 * page, page, PROT_READ, MAP_FIXED | MAP_PRIVATE, odd, 0) == MAP_FAILED) return 102;
    maps_show("file-odd-name", f + 16 * page, prefix);

    int gone = open("gone", O_CREAT | O_RDWR, 0644);
    if (gone < 0 || write(gone, fill, (size_t)page) != page) return 103;
    if (mmap(f + 18 * page, page, PROT_READ, MAP_FIXED | MAP_PRIVATE, gone, 0) == MAP_FAILED) return 104;
    maps_show("file-before-unlink", f + 18 * page, prefix);
    unlink("gone");
    maps_show("file-unlinked", f + 18 * page, prefix);

    int memfd = memfd_create("maps", 0);
    if (memfd < 0 || ftruncate(memfd, 2 * page)) return 105;
    if (mmap(f + 20 * page, page, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_SHARED, memfd, page) == MAP_FAILED)
        return 106;
    maps_show("memfd", f + 20 * page, NULL);

    char *s = mmap(f + 24 * page, 2 * page, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (s == MAP_FAILED) return 107;
    maps_show("shared-anonymous", s, NULL);
    char *t = mmap(f + 28 * page, page, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (t == MAP_FAILED) return 108;
    {
        struct maps_line one, other;
        int maps = open("/proc/self/maps", O_RDONLY);
        const char *text = maps_text(maps);
        if (!maps_find(text, (unsigned long)s, &one) || !maps_find(text, (unsigned long)t, &other)) return 109;
        printf("shared-anonymous inodes differ=%d nonzero=%d\n", one.inode != other.inode, one.inode != 0);
        close(maps);
    }

    /* The stack and the break. */
    char local;
    {
        struct maps_line line;
        int maps = open("/proc/self/maps", O_RDONLY);
        if (!maps_find(maps_text(maps), (unsigned long)&local, &line)) return 110;
        printf("stack %s %.*s offset=%lx inode=%lu\n", line.perms, line.name_length, line.name,
               line.offset, line.inode);
        close(maps);
    }
    unsigned long top = (unsigned long)syscall(SYS_brk, 0);
    unsigned long grown = (unsigned long)syscall(SYS_brk, top + 3 * (unsigned long)page);
    {
        struct maps_line line;
        int maps = open("/proc/self/maps", O_RDONLY);
        if (!maps_find(maps_text(maps), grown - 1, &line)) return 111;
        printf("break %s %.*s offset=%lx inode=%lu\n", line.perms, line.name_length, line.name,
               line.offset, line.inode);
        close(maps);
    }
    syscall(SYS_brk, top);

    /* How it reads: at most about a page of whole lines at once, however much
       is asked for, and a piece of a line when little is. */
    int reader = open("/proc/self/maps", O_RDONLY);
    if (reader < 0) return 112;
    static char big[1 << 18], again[1 << 18];
    long first = read(reader, big, sizeof big);
    printf("read-first within-page=%d whole-lines=%d\n", first > 0 && first <= 4096, first > 0 && big[first - 1] == '\n');
    errno = 0;
    long sought = lseek(reader, 0, SEEK_END);
    printf("seek-end=%ld errno=%d\n", sought, errno);
    errno = 0;
    sought = lseek(reader, -1, SEEK_SET);
    printf("seek-negative=%ld errno=%d\n", sought, errno);
    long position = lseek(reader, 0, SEEK_CUR);
    printf("seek-current-is-read=%d\n", position == first);
    printf("seek-start=%ld\n", (long)lseek(reader, 0, SEEK_SET));
    char small[10];
    printf("read-small=%ld\n", (long)read(reader, small, sizeof small));
    printf("read-small-is-start=%d\n", !memcmp(small, big, sizeof small));
    /* A position within a line reads the rest of it; pread keeps the place. */
    printf("seek-within=%ld\n", (long)lseek(reader, 45, SEEK_SET));
    long within = read(reader, again, 20);
    printf("read-within=%ld same=%d\n", within, !memcmp(again, big + 45, 20));
    long positioned = pread(reader, again, 20, 3);
    printf("pread=%ld same=%d\n", positioned, !memcmp(again, big + 3, 20));
    printf("after-pread=%ld\n", (long)lseek(reader, 0, SEEK_CUR));
    printf("seek-far=%ld\n", (long)lseek(reader, 1 << 28, SEEK_SET));
    printf("read-far=%ld\n", (long)read(reader, again, 20));
    /* It is made as it is read: what changed since it was opened shows. */
    lseek(reader, 0, SEEK_SET);
    char *later = f + 40 * page;
    if (mmap(later, page, PROT_READ | PROT_WRITE, flags, -1, 0) == MAP_FAILED) return 113;
    struct maps_line seen;
    printf("sees-a-later-mapping=%d\n", maps_find(maps_text(reader), (unsigned long)later, &seen) &&
                                              !strcmp(seen.perms, "rw-p"));
    munmap(later, page);
    lseek(reader, 0, SEEK_SET);
    printf("sees-it-gone=%d\n", !maps_find(maps_text(reader), (unsigned long)later, &seen));
    /* /proc's generated files have no mapping operation. */
    int status_file = open("/proc/self/status", O_RDONLY);
    errno = 0;
    int status_unmapped = mmap(NULL, page, PROT_READ, MAP_PRIVATE, status_file, 0) == MAP_FAILED;
    printf("mmap-status-failed=%d errno=%d\n", status_unmapped, errno);
    close(status_file);
    /* Neither written nor mapped, nor truncated. */
    errno = 0;
    long written = write(reader, "x", 1);
    printf("write=%ld errno=%d\n", written, errno);
    errno = 0;
    int unmapped = mmap(NULL, page, PROT_READ, MAP_PRIVATE, reader, 0) == MAP_FAILED;
    printf("mmap-failed=%d errno=%d\n", unmapped, errno);
    errno = 0;
    int writer = open("/proc/self/maps", O_RDWR);
    if (writer >= 0) {
        written = write(writer, "x", 1);
        printf("write-opened=%ld errno=%d\n", written, errno);
        close(writer);
    } else {
        printf("write-open errno=%d\n", errno);
    }

    /* A descriptor keeps the address space it was opened on: a child reading
       an inherited one sees its parent's mappings, not its own. */
    int ready[2], go[2];
    if (pipe(ready) || pipe(go)) return 114;
    lseek(reader, 0, SEEK_SET);
    fflush(stdout);
    pid_t child = fork();
    if (child < 0) return 115;
    if (!child) {
        char *mine = f + 44 * page;
        char byte = 0;
        mmap(mine, page, PROT_READ | PROT_WRITE, flags, -1, 0);
        if (write(ready[1], &byte, 1) != 1 || read(go[0], &byte, 1) != 1) _exit(1);
        const char *text = maps_text(reader);
        struct maps_line line;
        int own = maps_find(text, (unsigned long)mine, &line) && !strcmp(line.perms, "rw-p");
        printf("child-sees-its-own=%d\n", own);
        int parents = maps_find(text, (unsigned long)(f + 46 * page), &line) && !strcmp(line.perms, "rw-p");
        printf("child-sees-the-parents=%d\n", parents);
        fflush(stdout);
        _exit(0);
    }
    char byte = 0;
    if (read(ready[0], &byte, 1) != 1) return 116;
    if (mmap(f + 46 * page, page, PROT_READ | PROT_WRITE, flags, -1, 0) == MAP_FAILED) return 117;
    if (write(go[1], &byte, 1) != 1) return 118;
    int status;
    waitpid(child, &status, 0);
    printf("child status=%d\n", status);

    unlink("data");
    unlink("a b\\c\nd");
    if (chdir("/") || rmdir(dir)) return 119;

    /* Through an exec, a descriptor stays open and shows no more. */
    lseek(reader, 0, SEEK_SET);
    fflush(stdout);
    char number[16];
    snprintf(number, sizeof number, "%d", reader);
    char *arguments[] = {(char *)self, "proc-maps-after-exec", number, NULL};
    execv(self, arguments);
    return 120;
}

/* Robust futexes (kernel/futex/core.c): a list in guest memory, which Linux
   walks when its thread ends or calls execve. */
struct robust_list_for_test {
    void *next;
    long futex_offset;
    void *pending;
};
#define ROBUST_DIED 0x40000000u
#define ROBUST_WAITERS 0x80000000u
#define ROBUST_TID 0x3fffffffu

/* The list of `count` entries from `base`, each 16 bytes with its word at 8. */
static struct robust_list_for_test *robust_build(char *base, int count, void *pending) {
    struct robust_list_for_test *head = (void *)base;
    head->futex_offset = 8;
    head->pending = pending;
    void **link = &head->next;
    for (int i = 0; i < count; i++) {
        char *entry = base + 64 + 16 * i;
        *link = entry;
        link = (void **)entry;
    }
    *link = head;
    return head;
}
static unsigned *robust_word(char *base, int i) { return (unsigned *)(base + 64 + 16 * i + 8); }
static void robust_show(const char *label, unsigned word, unsigned tid) {
    printf("%s: died=%d waiters=%d tid-kept=%d low-zero=%d\n", label, !!(word & ROBUST_DIED),
           !!(word & ROBUST_WAITERS), (word & ROBUST_TID) == tid, (word & ROBUST_TID) == 0);
}

struct robust_thread {
    char *base;
    int ready, go;
    unsigned tid;
};
static void *robust_thread(void *argument) {
    struct robust_thread *t = argument;
    t->tid = (unsigned)syscall(SYS_gettid);
    char *base = t->base;
    *robust_word(base, 0) = t->tid;
    *robust_word(base, 1) = t->tid | ROBUST_WAITERS;
    *robust_word(base, 2) = t->tid + 1;
    *robust_word(base, 3) = t->tid;
    *robust_word(base, 4) = 0;
    void *head = robust_build(base, 3, base + 64 + 16 * 3);
    syscall(SYS_set_robust_list, head, sizeof(struct robust_list_for_test));
    char byte = 0;
    if (write(t->ready, &byte, 1) != 1 || read(t->go, &byte, 1) != 1) return NULL;
    return NULL;
}

static int robust_list_cases(const char *self) {
    long page = 4096;
    char *base = mmap(NULL, page, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (base == MAP_FAILED) return 80;

    /* The calls. */
    errno = 0;
    long r = syscall(SYS_set_robust_list, base, 23L);
    printf("set-short=%ld errno=%d\n", r, errno);
    void *got = base;
    size_t length = 0;
    r = syscall(SYS_get_robust_list, 0, &got, &length);
    printf("get-first=%ld head-is-null-or-libcs=%d length=%zu\n", r, got != base, length);
    void *saved = got;
    r = syscall(SYS_set_robust_list, base + 64, 24L);
    printf("set=%ld\n", r);
    r = syscall(SYS_get_robust_list, 0, &got, &length);
    printf("get=%ld same=%d length=%zu\n", r, got == base + 64, length);
    r = syscall(SYS_get_robust_list, (long)getpid(), &got, &length);
    printf("get-by-tid=%ld same=%d\n", r, got == base + 64);
    errno = 0;
    r = syscall(SYS_get_robust_list, 0x3ffffff0L, &got, &length);
    printf("get-missing=%ld errno=%d\n", r, errno);
    errno = 0;
    r = syscall(SYS_get_robust_list, -1L, &got, &length);
    printf("get-negative=%ld errno=%d\n", r, errno);
    errno = 0;
    r = syscall(SYS_get_robust_list, 0, NULL, &length);
    printf("get-bad-head=%ld errno=%d\n", r, errno);
    errno = 0;
    r = syscall(SYS_get_robust_list, 0, &got, NULL);
    printf("get-bad-length=%ld errno=%d\n", r, errno);

    /* A thread starts with none, whatever its creator has. */
    fflush(stdout);
    pid_t child = fork();
    if (child < 0) return 81;
    if (!child) {
        r = syscall(SYS_get_robust_list, 0, &got, &length);
        printf("forked=%ld none=%d\n", r, got == NULL);
        fflush(stdout);
        _exit(0);
    }
    int status;
    waitpid(child, &status, 0);
    syscall(SYS_set_robust_list, saved, 24L);

    /* A thread that ends: its own words are marked, also with waiters and the
       pending one, and not another's or one at zero. */
    int ready[2], go[2];
    if (pipe(ready) || pipe(go)) return 82;
    struct robust_thread t = {base, ready[1], go[0], 0};
    pthread_t thread;
    if (pthread_create(&thread, NULL, robust_thread, &t)) return 83;
    char byte;
    if (read(ready[0], &byte, 1) != 1) return 84;
    r = syscall(SYS_get_robust_list, (long)t.tid, &got, &length);
    printf("get-of-sibling=%ld same=%d\n", r, got == base);
    /* It wakes a shared waiter on a word with FUTEX_WAITERS. */
    if (write(go[1], &byte, 1) != 1) return 85;
    struct timespec limit = {10, 0};
    unsigned expected = t.tid | ROBUST_WAITERS;
    errno = 0;
    r = syscall(SYS_futex, robust_word(base, 1), 0 /* FUTEX_WAIT */, expected, &limit);
    printf("woken=%d\n", r == 0 || errno == EAGAIN);
    if (pthread_join(thread, NULL)) return 86;
    robust_show("owned", *robust_word(base, 0), t.tid);
    robust_show("waiters", *robust_word(base, 1), t.tid);
    printf("other-untouched=%d\n", *robust_word(base, 2) == t.tid + 1);
    robust_show("pending", *robust_word(base, 3), t.tid);
    printf("zero-untouched=%d\n", *robust_word(base, 4) == 0);

    /* A process: its list goes when it ends, by exit or by a signal. */
    for (int how = 0; how < 2; how++) {
        memset(base, 0, (size_t)page);
        fflush(stdout);
        child = fork();
        if (child < 0) return 87;
        if (!child) {
            unsigned tid = (unsigned)getpid();
            *robust_word(base, 0) = tid;
            syscall(SYS_set_robust_list, robust_build(base, 1, NULL), 24L);
            if (how) raise(SIGKILL);
            _exit(0);
        }
        waitpid(child, &status, 0);
        robust_show(how ? "killed" : "exited", *robust_word(base, 0), (unsigned)child);
    }

    /* A misaligned word ends the walk, and so does an entry not mapped. */
    memset(base, 0, (size_t)page);
    fflush(stdout);
    child = fork();
    if (child < 0) return 88;
    if (!child) {
        unsigned tid = (unsigned)getpid();
        *robust_word(base, 1) = tid;
        struct robust_list_for_test *head = robust_build(base, 2, NULL);
        head->futex_offset = 9;
        syscall(SYS_set_robust_list, head, 24L);
        _exit(0);
    }
    waitpid(child, &status, 0);
    robust_show("after-misaligned", *robust_word(base, 1), (unsigned)child);
    memset(base, 0, (size_t)page);
    fflush(stdout);
    child = fork();
    if (child < 0) return 89;
    if (!child) {
        unsigned tid = (unsigned)getpid();
        *robust_word(base, 0) = tid;
        *(void **)(base + 64) = (void *)16;
        struct robust_list_for_test *head = (void *)base;
        head->next = base + 64;
        head->futex_offset = 8;
        syscall(SYS_set_robust_list, head, 24L);
        _exit(0);
    }
    waitpid(child, &status, 0);
    robust_show("before-unmapped", *robust_word(base, 0), (unsigned)child);

    /* execve walks it on the old image, and the new program has none. */
    memset(base, 0, (size_t)page);
    fflush(stdout);
    child = fork();
    if (child < 0) return 90;
    if (!child) {
        unsigned tid = (unsigned)getpid();
        *robust_word(base, 0) = tid;
        syscall(SYS_set_robust_list, robust_build(base, 1, NULL), 24L);
        char *arguments[] = {(char *)self, "robust-list-after-exec", (char *)self, NULL};
        execv(self, arguments);
        _exit(91);
    }
    waitpid(child, &status, 0);
    printf("exec status=%d\n", status);
    robust_show("exec", *robust_word(base, 0), (unsigned)child);
    munmap(base, (size_t)page);
    return 0;
}

/* A futex word in shared memory is the same word in every process that maps
   it (kernel/futex/core.c's get_futex_key), however each maps it. The parent
   wakes until a wake reaches the waiting child, so no sleep sets the order. */
static long futex_call(volatile unsigned *word, long op, unsigned value) {
    return syscall(SYS_futex, word, op, value, NULL, NULL, 0);
}

/* The child waits on `wait_at` until woken; the parent wakes at `wake_at`.
   A private wake names the parent's own memory, so it never reaches it. */
static void futex_shared_show(const char *label, volatile unsigned *wait_at,
                              volatile unsigned *wake_at, int remap_fd) {
    fflush(stdout);
    pid_t child = fork();
    if (child < 0) {
        printf("%s: fork failed\n", label);
        return;
    }
    if (!child) {
        volatile unsigned *at = wait_at;
        if (remap_fd >= 0) {
            /* The second page of the file, wherever this mapping lands. */
            char *page = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, remap_fd, 4096);
            if (page == MAP_FAILED) _exit(2);
            at = (volatile unsigned *)(page + 8);
        }
        long r = futex_call(at, 0 /* FUTEX_WAIT */, 0);
        _exit(r == 0 ? 0 : 1);
    }
    long private = futex_call(wake_at, 1 | 128 /* FUTEX_WAKE_PRIVATE */, 1);
    long woke;
    while ((woke = futex_call(wake_at, 1 /* FUTEX_WAKE */, 1)) == 0) sched_yield();
    int status;
    waitpid(child, &status, 0);
    printf("%s: private wake=%ld shared wake=%ld child status=%d\n", label, private, woke, status);
}

static int futex_shared_cases(void) {
    char *anonymous = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (anonymous == MAP_FAILED) return 80;
    volatile unsigned *word = (volatile unsigned *)(anonymous + 8);
    futex_shared_show("anonymous", word, word, -1);

    int fd = (int)syscall(SYS_memfd_create, "futex", 0);
    if (fd < 0 || ftruncate(fd, 2 * 4096)) return 81;
    char *file = mmap(NULL, 2 * 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (file == MAP_FAILED) return 82;
    volatile unsigned *second = (volatile unsigned *)(file + 4096 + 8);
    futex_shared_show("file-other-mapping", second, second, fd);

    /* A process-shared robust mutex whose owner ends while the parent waits:
       the end's wake reaches the parent, which gets EOWNERDEAD. */
    pthread_mutex_t *mutex = (pthread_mutex_t *)(anonymous + 64);
    pthread_mutexattr_t attributes;
    pthread_mutexattr_init(&attributes);
    pthread_mutexattr_setpshared(&attributes, PTHREAD_PROCESS_SHARED);
    pthread_mutexattr_setrobust(&attributes, PTHREAD_MUTEX_ROBUST);
    pthread_mutex_init(mutex, &attributes);
    volatile int *held = (volatile int *)(anonymous + 32);
    *held = 0;
    fflush(stdout);
    pid_t child = fork();
    if (child < 0) return 83;
    if (!child) {
        if (pthread_mutex_lock(mutex)) _exit(2);
        *held = 1;
        /* Ends once the parent waits: musl marks the lock word (the
           mutex's second int) waited on, its top bit, before its futex wait. */
        while (!(((volatile unsigned *)mutex)[1] & 0x80000000u)) sched_yield();
        _exit(0);
    }
    while (!*held) sched_yield();
    int r = pthread_mutex_lock(mutex);
    printf("robust-owner-ended: lock=%s\n", r == EOWNERDEAD ? "EOWNERDEAD" : r == 0 ? "0" : "other");
    if (r == EOWNERDEAD) pthread_mutex_consistent(mutex);
    pthread_mutex_unlock(mutex);
    int status;
    waitpid(child, &status, 0);
    printf("robust-owner-ended: child status=%d\n", status);
    return 0;
}

/* A handler set while another thread already waits is that thread's too:
   the actions are the process's (Linux's sighand_struct). Both threads block
   SIGCHLD but for the waiter's epoll_pwait mask, so the signal can only
   arrive in that wait, which it ends with EINTR after the handler ran. */
static volatile int late_ready, late_handled;
static void late_handler(int number) {
    (void)number;
    late_handled++;
}
static void *late_waiter(void *unused) {
    (void)unused;
    int ep = epoll_create1(EPOLL_CLOEXEC);
    sigset_t open;
    pthread_sigmask(SIG_SETMASK, NULL, &open);
    sigdelset(&open, SIGCHLD);
    struct epoll_event event;
    late_ready = 1;
    int r = epoll_pwait(ep, &event, 1, -1, &open);
    int error = errno;
    printf("epoll_pwait=%d errno=%s handled=%d\n", r, error == EINTR ? "EINTR" : "other", late_handled);
    close(ep);
    return NULL;
}
static int late_handler_cases(void) {
    sigset_t blocked;
    sigemptyset(&blocked);
    sigaddset(&blocked, SIGCHLD);
    pthread_sigmask(SIG_BLOCK, &blocked, NULL);
    signal(SIGCHLD, SIG_DFL);
    pthread_t waiter;
    if (pthread_create(&waiter, NULL, late_waiter, NULL)) return 80;
    while (!late_ready) sched_yield();
    /* Most likely the waiter is in its wait by now; the output is the same
       either way. */
    for (int i = 0; i < 1000; i++) sched_yield();
    struct sigaction action = {.sa_handler = late_handler};
    sigaction(SIGCHLD, &action, NULL);
    fflush(stdout);
    pid_t child = fork();
    if (child < 0) return 81;
    if (!child) _exit(0);
    pthread_join(waiter, NULL);
    int status;
    printf("waitpid=%d status=%d\n", waitpid(child, &status, 0) == child, status);
    return 0;
}

/* The whole of a small /proc file, NUL-terminated; its length or -1. */
static long proc_read(const char *path, char *buffer, size_t size) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    long total = 0, n;
    while (total < (long)size - 1 && (n = read(fd, buffer + total, size - 1 - (size_t)total)) > 0) total += n;
    close(fd);
    buffer[total] = 0;
    return total;
}

/* This process's stat, cmdline, comm, exe and cwd, and the system's loadavg,
   meminfo, uptime and stat: their format, and what the system calls say too. */
static int proc_own_files_cases(int argc, char **argv) {
    static char buffer[65536];
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGUSR1);
    sigprocmask(SIG_BLOCK, &set, NULL);
    signal(SIGUSR2, SIG_IGN);
    signal(SIGHUP, interrupted);

    long n = proc_read("/proc/self/stat", buffer, sizeof buffer);
    char *close_paren = n > 0 ? strrchr(buffer, ')') : NULL;
    char *open_paren = n > 0 ? strchr(buffer, '(') : NULL;
    if (!close_paren || !open_paren) return 80;
    *close_paren = 0;
    printf("stat comm=%s pid=%d newline=%d\n", open_paren + 1, atol(buffer) == getpid(), buffer[n - 1] == '\n');
    char *fields[64];
    int count = 0;
    for (char *field = strtok(close_paren + 2, " \n"); field && count < 64; field = strtok(NULL, " \n")) fields[count++] = field;
    /* fields[0] is the state, the third field of the line. */
    printf("stat fields=%d state=%s\n", count + 2, count ? fields[0] : "-");
    if (count >= 50) {
        printf("stat ppid=%d pgrp=%d session=%d\n", atol(fields[1]) == getppid(), atol(fields[2]) == getpgrp(),
               atol(fields[3]) == getsid(0));
        printf("stat priority=%s nice=%s threads=%s itrealvalue=%s\n", fields[15], fields[16], fields[17], fields[18]);
        printf("stat signal=%s blocked=%s ignored=%s caught=%s exit_signal=%s\n", fields[28], fields[29], fields[30],
               fields[31], fields[35]);
        unsigned long arg_start = strtoul(fields[45], NULL, 10), arg_end = strtoul(fields[46], NULL, 10);
        unsigned long env_start = strtoul(fields[47], NULL, 10), env_end = strtoul(fields[48], NULL, 10);
        printf("stat arguments-at-argv=%d environment-after-arguments=%d\n", arg_start == (unsigned long)argv[0],
               env_start >= arg_end && env_end >= env_start);
    }

    n = proc_read("/proc/self/cmdline", buffer, sizeof buffer);
    long expected = 0;
    int same = 1;
    for (int i = 0; i < argc; i++) {
        size_t length = strlen(argv[i]) + 1;
        same &= expected + (long)length <= n && !memcmp(buffer + expected, argv[i], length);
        expected += (long)length;
    }
    printf("cmdline is-argv=%d\n", same && n == expected);
    n = proc_read("/proc/self/comm", buffer, sizeof buffer);
    printf("comm=%s", buffer);

    struct stat link, through, target;
    char path[4096];
    ssize_t length = readlink("/proc/self/exe", path, sizeof path - 1);
    path[length > 0 ? length : 0] = 0;
    int is_link = lstat("/proc/self/exe", &link) == 0 && S_ISLNK(link.st_mode);
    int same_file = stat("/proc/self/exe", &through) == 0 && stat(path, &target) == 0 &&
                    through.st_ino == target.st_ino && through.st_dev == target.st_dev;
    printf("exe link=%d mode=%o absolute=%d same-file=%d\n", is_link, (unsigned)(link.st_mode & 07777), path[0] == '/',
           same_file);
    /* A forked child runs the same program, so its link names the same path. */
    fflush(stdout);
    int link_pipe[2];
    if (pipe(link_pipe)) return 82;
    pid_t child = fork();
    if (child < 0) return 83;
    if (!child) {
        char child_path[4096];
        ssize_t got = readlink("/proc/self/exe", child_path, sizeof child_path);
        if (got > 0 && write(link_pipe[1], child_path, (size_t)got) != got) _exit(2);
        _exit(got > 0 ? 0 : 1);
    }
    close(link_pipe[1]);
    char child_path[4096];
    ssize_t got = read(link_pipe[0], child_path, sizeof child_path - 1);
    child_path[got > 0 ? got : 0] = 0;
    close(link_pipe[0]);
    int child_status;
    waitpid(child, &child_status, 0);
    printf("exe forked-child-same=%d status=%d\n", !strcmp(child_path, path), child_status);
    int exe = open("/proc/self/exe", O_RDONLY);
    char magic[4] = {0};
    printf("exe opens=%d elf=%d\n", exe >= 0, exe >= 0 && read(exe, magic, 4) == 4 && !memcmp(magic, "\177ELF", 4));
    if (exe >= 0) close(exe);
    errno = 0;
    int nofollow = open("/proc/self/exe", O_RDONLY | O_NOFOLLOW);
    printf("exe nofollow=%d errno=%d\n", nofollow, errno);
    if (chdir("/tmp")) return 81;
    char cwd[4096];
    length = readlink("/proc/self/cwd", path, sizeof path - 1);
    path[length > 0 ? length : 0] = 0;
    printf("cwd is-getcwd=%d\n", getcwd(cwd, sizeof cwd) && !strcmp(cwd, path));

    struct sysinfo info;
    sysinfo(&info);
    n = proc_read("/proc/loadavg", buffer, sizeof buffer);
    double one, five, fifteen;
    int running, tasks, last;
    int matched = sscanf(buffer, "%lf %lf %lf %d/%d %d", &one, &five, &fifteen, &running, &tasks, &last);
    printf("loadavg fields=%d running-of-tasks=%d newline=%d\n", matched, running >= 1 && running <= tasks,
           n > 0 && buffer[n - 1] == '\n');
    n = proc_read("/proc/meminfo", buffer, sizeof buffer);
    unsigned long total = 0, free = 0, available = 0;
    char *line = strstr(buffer, "MemTotal:");
    if (line) sscanf(line, "MemTotal: %lu kB", &total);
    if ((line = strstr(buffer, "MemFree:"))) sscanf(line, "MemFree: %lu kB", &free);
    if ((line = strstr(buffer, "MemAvailable:"))) sscanf(line, "MemAvailable: %lu kB", &available);
    printf("meminfo first=%d total-is-sysinfo=%d free-within-total=%d\n", !strncmp(buffer, "MemTotal:", 9),
           total == info.totalram * info.mem_unit / 1024, free <= total && available <= total);
    n = proc_read("/proc/uptime", buffer, sizeof buffer);
    double up = -1, idle = -1;
    int uptime_fields = sscanf(buffer, "%lf %lf", &up, &idle);
    printf("uptime fields=%d near-sysinfo=%d\n", uptime_fields,
           up >= (double)info.uptime - 1 && up <= (double)info.uptime + 2);
    /* /proc/stat: the all-CPU line, one per online CPU, then the counters
       in show_stat's order; the boot time is now less the uptime. */
    n = proc_read("/proc/stat", buffer, sizeof buffer);
    cpu_set_t online;
    int cpus = sched_getaffinity(0, sizeof online, &online) ? -1 : CPU_COUNT(&online);
    int cpu_lines = 0, times = 0, order = 0, softirqs = 0;
    long long btime = -1, processes = -1, procs_running = -1;
    const char *keys[] = {"intr ", "ctxt ", "btime ", "processes ", "procs_running ", "procs_blocked ", "softirq "};
    for (char *line = n > 0 ? buffer : NULL, *end; line && *line; line = end + 1) {
        if (!(end = strchr(line, '\n'))) break;
        *end = 0;
        if (!strncmp(line, "cpu  ", 5)) {
            for (char *t = strtok(line + 5, " "); t; t = strtok(NULL, " ")) times++;
        } else if (!strncmp(line, "cpu", 3)) {
            cpu_lines += atoi(line + 3) == cpu_lines;
        } else if (order < 7 && !strncmp(line, keys[order], strlen(keys[order]))) {
            if (order == 2) btime = atoll(line + 6);
            if (order == 3) processes = atoll(line + 10);
            if (order == 4) procs_running = atoll(line + 14);
            if (order == 6)
                for (char *t = strtok(line + 8, " "); t; t = strtok(NULL, " ")) softirqs++;
            order++;
        }
    }
    long long booted = (long long)time(NULL) - info.uptime;
    printf("proc-stat first-cpu=%d times=%d per-cpu=%d counters-in-order=%d softirq-values=%d\n",
           !strncmp(buffer, "cpu  ", 5), times, cpu_lines == cpus, order, softirqs);
    printf("proc-stat btime-near-boot=%d processes=%d running=%d\n", btime >= booted - 2 && btime <= booted + 2,
           processes >= 1, procs_running >= 1);

    DIR *own = opendir("/proc/self");
    int seen = 0;
    const char *names[] = {"cmdline", "comm", "cwd", "exe", "fd", "maps", "stat", "status"};
    for (struct dirent *entry; own && (entry = readdir(own));)
        for (int i = 0; i < 8; i++)
            if (!strcmp(entry->d_name, names[i])) seen |= 1 << i;
    if (own) closedir(own);
    printf("listed=%x\n", seen);
    return 0;
}

/* FIFOs: mkfifo and mknod make the node, and every open of it joins one pipe
   (fs/pipe.c's fifo_open). A blocking reader waits for a writer and a
   blocking writer for a reader, so the parent and a forked child meet. */
static void fifo_show(const char *label, long r) {
    printf("%s: r=%ld errno=%d\n", label, r < 0 ? -1L : r, r < 0 ? errno : 0);
}
static int fifo_cases(void) {
    const char *path = "/tmp/paludarium-fifo";
    unlink(path);
    umask(022);
    errno = 0;
    fifo_show("mkfifo", mkfifo(path, 0666));
    struct stat st;
    stat(path, &st);
    printf("node: fifo=%d mode=%o size=%ld\n", S_ISFIFO(st.st_mode), (unsigned)(st.st_mode & 07777), (long)st.st_size);
    errno = 0;
    fifo_show("mkfifo-again", mkfifo(path, 0666));

    /* Nonblocking: a writer without a reader is ENXIO; a reader opens, and
       reads the end of the file while no writer is there. */
    errno = 0;
    fifo_show("write-alone", open(path, O_WRONLY | O_NONBLOCK));
    int reader = open(path, O_RDONLY | O_NONBLOCK);
    char buffer[64];
    errno = 0;
    fifo_show("read-no-writer", read(reader, buffer, sizeof buffer));
    int writer = open(path, O_WRONLY | O_NONBLOCK);
    printf("both-open: reader=%d writer=%d\n", reader >= 0, writer >= 0);
    fifo_show("write", write(writer, "abc", 3));
    long got = read(reader, buffer, sizeof buffer);
    printf("read: %ld %.*s\n", got, (int)(got > 0 ? got : 0), buffer);
    struct stat opened;
    fstat(reader, &opened);
    printf("fstat: fifo=%d same-inode=%d mode=%o\n", S_ISFIFO(opened.st_mode), opened.st_ino == st.st_ino,
           (unsigned)(opened.st_mode & 07777));
    close(writer);
    errno = 0;
    fifo_show("read-after-writer", read(reader, buffer, sizeof buffer));
    close(reader);

    /* Blocking: the child's writer and the parent's reader wait for each
       other, whichever comes first. */
    fflush(stdout);
    pid_t child = fork();
    if (child < 0) return 80;
    if (!child) {
        int w = open(path, O_WRONLY);
        if (w < 0 || write(w, "from child\n", 11) != 11) _exit(1);
        close(w);
        _exit(0);
    }
    reader = open(path, O_RDONLY);
    long total = 0;
    while ((got = read(reader, buffer + total, sizeof buffer - (size_t)total)) > 0) total += got;
    int status;
    waitpid(child, &status, 0);
    printf("blocking: %.*s", (int)total, buffer);
    printf("blocking: end=%ld status=%d\n", got, status);
    close(reader);

    /* O_RDWR is both ends and waits for neither. */
    int both = open(path, O_RDWR);
    fifo_show("rdwr-write", write(both, "xy", 2));
    got = read(both, buffer, sizeof buffer);
    printf("rdwr-read: %ld %.*s\n", got, (int)(got > 0 ? got : 0), buffer);
    close(both);
    errno = 0;
    fifo_show("excl", open(path, O_RDWR | O_CREAT | O_EXCL, 0600));
    errno = 0;
    fifo_show("directory", open(path, O_RDONLY | O_DIRECTORY | O_NONBLOCK));
    fifo_show("unlink", unlink(path));

    /* mknod's other types. */
    const char *other = "/tmp/paludarium-mknod";
    unlink(other);
    errno = 0;
    fifo_show("mknod-fifo", mknod(other, S_IFIFO | 0600, 0));
    stat(other, &st);
    printf("mknod-fifo: fifo=%d mode=%o\n", S_ISFIFO(st.st_mode), (unsigned)(st.st_mode & 07777));
    unlink(other);
    errno = 0;
    fifo_show("mknod-regular", mknod(other, S_IFREG | 0640, 0));
    stat(other, &st);
    printf("mknod-regular: regular=%d mode=%o size=%ld\n", S_ISREG(st.st_mode), (unsigned)(st.st_mode & 07777),
           (long)st.st_size);
    unlink(other);
    errno = 0;
    fifo_show("mknod-no-type", mknod(other, 0600, 0));
    stat(other, &st);
    printf("mknod-no-type: regular=%d\n", S_ISREG(st.st_mode));
    unlink(other);
    errno = 0;
    fifo_show("mknod-directory", mknod(other, S_IFDIR | 0700, 0));
    errno = 0;
    fifo_show("mknod-bad-type", mknod(other, 0170000 | 0600, 0));
    errno = 0;
    fifo_show("mknodat-exists", mknodat(AT_FDCWD, "/tmp", S_IFIFO | 0600, 0));
    errno = 0;
    fifo_show("mknod-missing-parent", mknod("/tmp/no-such-dir/f", S_IFIFO | 0600, 0));

    /* fchmodat2 (452, Linux 6.6), which glibc's lchmod calls first. */
    const char *link = "/tmp/paludarium-mknod-link";
    unlink(link);
    mkfifo(other, 0600);
    symlink(other, link);
    errno = 0;
    fifo_show("fchmodat2", syscall(452, AT_FDCWD, other, 0640, AT_SYMLINK_NOFOLLOW));
    stat(other, &st);
    printf("fchmodat2: mode=%o\n", (unsigned)(st.st_mode & 07777));
    errno = 0;
    fifo_show("fchmodat2-link", syscall(452, AT_FDCWD, link, 0600, AT_SYMLINK_NOFOLLOW));
    errno = 0;
    fifo_show("fchmodat2-follows", syscall(452, AT_FDCWD, link, 0604, 0));
    stat(other, &st);
    printf("fchmodat2-follows: mode=%o\n", (unsigned)(st.st_mode & 07777));
    errno = 0;
    fifo_show("fchmodat2-flags", syscall(452, AT_FDCWD, other, 0600, 1));
    int node = open(other, O_PATH);
    errno = 0;
    fifo_show("fchmodat2-empty-path", syscall(452, node, "", 0600, AT_EMPTY_PATH));
    stat(other, &st);
    printf("fchmodat2-empty-path: mode=%o\n", (unsigned)(st.st_mode & 07777));
    close(node);
    unlink(link);
    unlink(other);
    return 0;
}

/* The fields of a /proc stat line after the name, which ends at the last
   ')': fields[0] is the state, the line's third field. Their count, or -1. */
static int proc_fields(const char *path, char *buffer, size_t size, char **fields, int most) {
    if (proc_read(path, buffer, size) <= 0) return -1;
    char *close_paren = strrchr(buffer, ')');
    if (!close_paren) return -1;
    int count = 0;
    for (char *field = strtok(close_paren + 2, " \n"); field && count < most; field = strtok(NULL, " \n"))
        fields[count++] = field;
    return count;
}

/* The value of a status line, such as "State", or "" when it has none; the
   last eight values stay, for one printf. */
static const char *proc_status_field(char *status, const char *name) {
    static char values[8][256];
    static int next;
    char *value = values[next++ % 8];
    size_t length = strlen(name);
    value[0] = 0;
    for (char *line = status; line && *line; line = strchr(line, '\n') ? strchr(line, '\n') + 1 : NULL)
        if (!strncmp(line, name, length) && line[length] == ':') {
            char *start = line + length + 1;
            while (*start == '\t' || *start == ' ') start++;
            size_t n = strcspn(start, "\n");
            if (n >= sizeof values[0]) n = sizeof values[0] - 1;
            memcpy(value, start, n);
            value[n] = 0;
            break;
        }
    return value;
}

/* Whether directory `path` lists `name`, or -1 when it does not open. */
static int proc_lists(const char *path, const char *name) {
    DIR *dir = opendir(path);
    if (!dir) return -1;
    int found = 0;
    for (struct dirent *entry; (entry = readdir(dir));) found |= !strcmp(entry->d_name, name);
    closedir(dir);
    return found;
}

/* The child the case reads: named, with signals blocked, ignored and caught,
   in /tmp with umask 027, its environment its own, waiting in a read. */
static int proc_other_child(char **argv) {
    int ready = atoi(argv[3]), hold = atoi(argv[4]);
    prctl(PR_SET_NAME, "kid name");
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGUSR1);
    sigaddset(&set, SIGTERM);
    sigprocmask(SIG_BLOCK, &set, NULL);
    signal(SIGUSR2, SIG_IGN);
    signal(SIGHUP, interrupted);
    umask(027);
    if (chdir("/tmp")) return 2;
    if (write(ready, "x", 1) != 1) return 3;
    char byte;
    while (read(hold, &byte, 1) < 0 && errno == EINTR) {}
    return 0;
}

static volatile int proc_worker_ready;
static int proc_worker_hold[2];
static void *proc_worker(void *unused) {
    (void)unused;
    prctl(PR_SET_NAME, "worker");
    proc_worker_ready = (int)syscall(SYS_gettid);
    char byte;
    while (read(proc_worker_hold[0], &byte, 1) < 0 && errno == EINTR) {}
    return NULL;
}

/* Another process's stat, status, cmdline, environ, comm, exe and cwd, its
   directory and /proc's listing, a zombie's, a stopped one's and a reaped
   one's, and the task directories of this process's threads. */
static int proc_other_files_cases(const char *self) {
    static char buffer[65536];
    char path[256], *fields[64];
    int ready[2], hold[2];
    if (pipe(ready) || pipe(hold)) return 80;
    fflush(stdout);
    pid_t kid = fork();
    if (kid < 0) return 81;
    if (!kid) {
        close(ready[0]);
        close(hold[1]);
        char ready_fd[16], hold_fd[16];
        snprintf(ready_fd, sizeof ready_fd, "%d", ready[1]);
        snprintf(hold_fd, sizeof hold_fd, "%d", hold[0]);
        char *arguments[] = {(char *)self, "proc-other-child", (char *)self, ready_fd, hold_fd, "an arg", NULL};
        char *environment[] = {"A=1", "B=two words", NULL};
        execve(self, arguments, environment);
        _exit(90);
    }
    close(ready[1]);
    close(hold[0]);
    char byte;
    if (read(ready[0], &byte, 1) != 1) return 82;
    /* What its cmdline holds: its arguments, each ending in a NUL. */
    char expected[8192];
    int expected_length = snprintf(expected, sizeof expected, "%s|proc-other-child|%s|%d|%d|an arg|", self, self,
                                   ready[1], hold[0]);
    /* It reads its pipe now, or is about to: wait until it sleeps there. */
    snprintf(path, sizeof path, "/proc/%d/stat", (int)kid);
    int count = -1;
    for (int i = 0; i < 100000; i++) {
        count = proc_fields(path, buffer, sizeof buffer, fields, 64);
        if (count > 0 && !strcmp(fields[0], "S")) break;
        sched_yield();
    }
    long n = proc_read(path, buffer, sizeof buffer);
    char *open_paren = strchr(buffer, '(');
    char *close_paren = strrchr(buffer, ')');
    if (n <= 0 || !open_paren || !close_paren) return 83;
    *close_paren = 0;
    printf("stat pid=%d comm=%s\n", atol(buffer) == kid, open_paren + 1);
    count = proc_fields(path, buffer, sizeof buffer, fields, 64);
    printf("stat fields=%d state=%s\n", count + 2, count > 0 ? fields[0] : "-");
    if (count >= 50) {
        printf("stat ppid=%d pgrp=%d session=%d tty=%s tpgid=%s\n", atol(fields[1]) == getpid(),
               atol(fields[2]) == getpgid(kid), atol(fields[3]) == getsid(kid), fields[4], fields[5]);
        printf("stat priority=%s nice=%s threads=%s itrealvalue=%s\n", fields[15], fields[16], fields[17], fields[18]);
        printf("stat signal=%s blocked=%s ignored=%s caught=%s wchan=%s exit_signal=%s\n", fields[28], fields[29],
               fields[30], fields[31], fields[32], fields[35]);
        unsigned long arg_start = strtoul(fields[45], NULL, 10), arg_end = strtoul(fields[46], NULL, 10);
        unsigned long env_start = strtoul(fields[47], NULL, 10), env_end = strtoul(fields[48], NULL, 10);
        printf("stat arguments-are-cmdline=%d environment=%lu after=%d\n",
               arg_end - arg_start == (unsigned long)expected_length, env_end - env_start, env_start >= arg_end);
    }
    snprintf(path, sizeof path, "/proc/%d/status", (int)kid);
    proc_read(path, buffer, sizeof buffer);
    char pid_text[16], own_text[16];
    snprintf(pid_text, sizeof pid_text, "%d", (int)kid);
    snprintf(own_text, sizeof own_text, "%d", (int)getpid());
    printf("status first=%d name=%s umask=%s state=%s\n", !strncmp(buffer, "Name:", 5),
           proc_status_field(buffer, "Name"), proc_status_field(buffer, "Umask"),
           proc_status_field(buffer, "State"));
    /* FDSize is left out: a table the native run inherits may have grown. */
    printf("status tgid=%d pid=%d ppid=%d threads=%s\n", !strcmp(proc_status_field(buffer, "Tgid"), pid_text),
           !strcmp(proc_status_field(buffer, "Pid"), pid_text), !strcmp(proc_status_field(buffer, "PPid"), own_text),
           proc_status_field(buffer, "Threads"));
    char ids[64];
    snprintf(ids, sizeof ids, "%u\t%u\t%u\t%u", getuid(), getuid(), getuid(), getuid());
    printf("status uid=%d sigpnd=%s shdpnd=%s\n", !strcmp(proc_status_field(buffer, "Uid"), ids),
           proc_status_field(buffer, "SigPnd"), proc_status_field(buffer, "ShdPnd"));
    printf("status sigblk=%s sigign=%s sigcgt=%s\n", proc_status_field(buffer, "SigBlk"),
           proc_status_field(buffer, "SigIgn"), proc_status_field(buffer, "SigCgt"));

    snprintf(path, sizeof path, "/proc/%d/cmdline", (int)kid);
    n = proc_read(path, buffer, sizeof buffer);
    for (long i = 0; i < n; i++)
        if (!buffer[i]) buffer[i] = '|';
    printf("cmdline is-arguments=%d\n", n == expected_length && !memcmp(buffer, expected, (size_t)n));
    snprintf(path, sizeof path, "/proc/%d/environ", (int)kid);
    n = proc_read(path, buffer, sizeof buffer);
    for (long i = 0; i < n; i++)
        if (!buffer[i]) buffer[i] = '|';
    printf("environ=%s length=%ld\n", buffer, n);
    snprintf(path, sizeof path, "/proc/%d/comm", (int)kid);
    proc_read(path, buffer, sizeof buffer);
    printf("comm=%s", buffer);

    /* The kid runs `self`, which the emulated run's own program is only a
       copy of, so its link names `self` with its links resolved. */
    char target[4096], own_exe[4096];
    ssize_t length;
    if (!realpath(self, own_exe)) own_exe[0] = 0;
    snprintf(path, sizeof path, "/proc/%d/exe", (int)kid);
    length = readlink(path, target, sizeof target - 1);
    target[length > 0 ? length : 0] = 0;
    struct stat link, through, program;
    printf("exe same=%d link=%d same-file=%d\n", !strcmp(target, own_exe),
           lstat(path, &link) == 0 && S_ISLNK(link.st_mode),
           stat(path, &through) == 0 && stat(own_exe, &program) == 0 && through.st_ino == program.st_ino);
    errno = 0;
    int nofollow = open(path, O_RDONLY | O_NOFOLLOW);
    printf("exe nofollow=%d errno=%d\n", nofollow, errno);
    snprintf(path, sizeof path, "/proc/%d/cwd", (int)kid);
    length = readlink(path, target, sizeof target - 1);
    target[length > 0 ? length : 0] = 0;
    printf("cwd=%s\n", target);
    errno = 0;
    snprintf(path, sizeof path, "/proc/%d/stat", (int)kid);
    length = readlink(path, target, sizeof target - 1);
    printf("readlink-of-stat=%ld errno=%d\n", (long)length, errno);

    struct stat directory;
    snprintf(path, sizeof path, "/proc/%d", (int)kid);
    int found = stat(path, &directory) == 0;
    printf("directory stat=%d mode=%o owner=%d\n", found, (unsigned)directory.st_mode & 0177777,
           directory.st_uid == geteuid());
    printf("proc lists kid=%d self=%d self-link=%d\n", proc_lists("/proc", pid_text), proc_lists("/proc", own_text),
           proc_lists("/proc", "self"));
    const char *names[] = {"cmdline", "comm", "cwd", "environ", "exe", "stat", "status", "task"};
    int seen = 0;
    for (int i = 0; i < 8; i++) seen |= (proc_lists(path, names[i]) == 1) << i;
    printf("kid lists=%x\n", seen);
    snprintf(path, sizeof path, "/proc/%d/task", (int)kid);
    printf("kid task lists-kid=%d\n", proc_lists(path, pid_text));
    snprintf(path, sizeof path, "/proc/%d/task/%d/comm", (int)kid, (int)kid);
    proc_read(path, buffer, sizeof buffer);
    printf("kid task comm=%s", buffer);
    snprintf(path, sizeof path, "/proc/%d/task/%d", (int)kid, (int)getpid());
    errno = 0;
    found = stat(path, &directory);
    printf("kid task of another=%d errno=%d\n", found, errno);

    /* Stopped, then going on. */
    kill(kid, SIGSTOP);
    int status;
    waitpid(kid, &status, WUNTRACED);
    snprintf(path, sizeof path, "/proc/%d/stat", (int)kid);
    count = proc_fields(path, buffer, sizeof buffer, fields, 64);
    printf("stopped state=%s\n", count > 0 ? fields[0] : "-");
    snprintf(path, sizeof path, "/proc/%d/status", (int)kid);
    proc_read(path, buffer, sizeof buffer);
    printf("stopped status=%s\n", proc_status_field(buffer, "State"));
    kill(kid, SIGCONT);
    waitpid(kid, &status, WCONTINUED);

    /* Ended and not yet reaped, then reaped. */
    close(hold[1]);
    siginfo_t info;
    waitid(P_PID, (id_t)kid, &info, WEXITED | WNOWAIT);
    snprintf(path, sizeof path, "/proc/%d/stat", (int)kid);
    count = proc_fields(path, buffer, sizeof buffer, fields, 64);
    printf("zombie state=%s threads=%s vsize=%s\n", count > 0 ? fields[0] : "-", count > 17 ? fields[17] : "-",
           count > 20 ? fields[20] : "-");
    snprintf(path, sizeof path, "/proc/%d/status", (int)kid);
    proc_read(path, buffer, sizeof buffer);
    printf("zombie status=%s name=%s umask=[%s]\n", proc_status_field(buffer, "State"),
           proc_status_field(buffer, "Name"), proc_status_field(buffer, "Umask"));
    snprintf(path, sizeof path, "/proc/%d/cmdline", (int)kid);
    printf("zombie cmdline=%ld\n", proc_read(path, buffer, sizeof buffer));
    snprintf(path, sizeof path, "/proc/%d/exe", (int)kid);
    errno = 0;
    length = readlink(path, target, sizeof target);
    printf("zombie exe=%ld errno=%d\n", (long)length, errno);
    printf("zombie listed=%d\n", proc_lists("/proc", pid_text));
    waitpid(kid, &status, 0);
    printf("reaped status=%d\n", status);
    snprintf(path, sizeof path, "/proc/%d/stat", (int)kid);
    errno = 0;
    found = open(path, O_RDONLY);
    int error = errno;
    printf("reaped open=%d errno=%d listed=%d\n", found, error, proc_lists("/proc", pid_text));
    snprintf(path, sizeof path, "/proc/%d", (int)kid);
    errno = 0;
    found = stat(path, &directory);
    printf("reaped stat=%d errno=%d\n", found, errno);

    /* This process's threads under task. */
    if (pipe(proc_worker_hold)) return 84;
    pthread_t worker;
    if (pthread_create(&worker, NULL, proc_worker, NULL)) return 85;
    while (!proc_worker_ready) sched_yield();
    int tid = proc_worker_ready;
    snprintf(path, sizeof path, "/proc/self/task/%d/stat", tid);
    for (int i = 0; i < 100000; i++) {
        count = proc_fields(path, buffer, sizeof buffer, fields, 64);
        if (count > 0 && !strcmp(fields[0], "S")) break;
        sched_yield();
    }
    char tid_text[16];
    snprintf(tid_text, sizeof tid_text, "%d", tid);
    printf("task lists self=%d worker=%d\n", proc_lists("/proc/self/task", own_text),
           proc_lists("/proc/self/task", tid_text));
    printf("task worker state=%s threads=%s wchan=%s\n", count > 0 ? fields[0] : "-", count > 17 ? fields[17] : "-",
           count > 32 ? fields[32] : "-");
    snprintf(path, sizeof path, "/proc/self/task/%d/stat", (int)getpid());
    count = proc_fields(path, buffer, sizeof buffer, fields, 64);
    printf("task self state=%s\n", count > 0 ? fields[0] : "-");
    snprintf(path, sizeof path, "/proc/%d/task/%d/comm", (int)getpid(), tid);
    proc_read(path, buffer, sizeof buffer);
    printf("task worker comm=%s", buffer);
    snprintf(path, sizeof path, "/proc/self/task/%d/status", tid);
    proc_read(path, buffer, sizeof buffer);
    printf("task worker status name=%s tgid=%d pid=%d threads=%s\n", proc_status_field(buffer, "Name"),
           !strcmp(proc_status_field(buffer, "Tgid"), own_text), !strcmp(proc_status_field(buffer, "Pid"), tid_text),
           proc_status_field(buffer, "Threads"));
    snprintf(path, sizeof path, "/proc/self/task/%d", tid);
    seen = 0;
    for (int i = 0; i < 8; i++) seen |= (proc_lists(path, names[i]) == 1) << i;
    printf("task worker lists=%x\n", seen);
    /* A thread's own ID names a directory too, which /proc does not list. */
    snprintf(path, sizeof path, "/proc/%d/status", tid);
    proc_read(path, buffer, sizeof buffer);
    printf("thread directory name=%s tgid=%d pid=%d listed=%d\n", proc_status_field(buffer, "Name"),
           !strcmp(proc_status_field(buffer, "Tgid"), own_text), !strcmp(proc_status_field(buffer, "Pid"), tid_text),
           proc_lists("/proc", tid_text));
    /* thread-self is a link to the reading thread's directory under task. */
    char expected_link[64];
    snprintf(expected_link, sizeof expected_link, "%d/task/%d", (int)getpid(), (int)getpid());
    length = readlink("/proc/thread-self", target, sizeof target - 1);
    target[length > 0 ? length : 0] = 0;
    struct stat self_link;
    found = lstat("/proc/thread-self", &self_link) == 0 && S_ISLNK(self_link.st_mode);
    proc_read("/proc/thread-self/comm", buffer, sizeof buffer);
    printf("thread-self link=%d is-link=%d listed=%d comm=%s", !strcmp(target, expected_link), found,
           proc_lists("/proc", "thread-self"), buffer);
    /* A trailing slash or dot follows the link to the directory. */
    int slash = lstat("/proc/thread-self/", &self_link) == 0 && S_ISDIR(self_link.st_mode);
    printf("thread-self slash-is-directory=%d dot-lists-comm=%d\n", slash, proc_lists("/proc/thread-self/.", "comm"));
    close(proc_worker_hold[1]);
    pthread_join(worker, NULL);
    /* Linux wakes the join before the thread is quite gone. */
    snprintf(path, sizeof path, "/proc/self/task/%d/stat", tid);
    int ended = 0;
    for (int i = 0; i < 100000 && (ended = open(path, O_RDONLY)) >= 0; i++) {
        close(ended);
        sched_yield();
    }
    printf("task ended open=%d errno=%d\n", ended, errno);
    return 0;
}

static void lock_show(const char *label, long number, void *at, size_t length, long flags) {
    errno = 0;
    long r = syscall(number, at, length, flags);
    printf("%s: r=%ld errno=%d\n", label, r, errno);
}

static void lock_all_show(long flags) {
    errno = 0;
    long r = syscall(SYS_mlockall, flags);
    /* Whether the flags are valid: MCL_CURRENT then asks RLIMIT_MEMLOCK for all
       that is mapped, which is ENOMEM for a user without CAP_IPC_LOCK and not
       for root, as the guest. A unit test holds the result for root. */
    int invalid = r == -1 && errno == EINVAL;
    errno = 0;
    long undone = syscall(SYS_munlockall);
    printf("mlockall %ld: invalid=%d, munlockall r=%ld errno=%d\n", flags, invalid, undone, errno);
}

static int lock_cases(void) {
    long page = 4096;
    char *base = mmap(NULL, 16 * page, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (base == MAP_FAILED) return 80;
    int flags = MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS;
    char *a = mmap(base + 2 * page, 4 * page, PROT_READ | PROT_WRITE, flags, -1, 0);
    if (a == MAP_FAILED) return 81;
    a[page] = 42;
    /* A hole of our own, not to depend on what mmap put after the mapping. */
    char *before_hole = mmap(base + 11 * page, (size_t)page, PROT_READ | PROT_WRITE, flags, -1, 0);
    if (before_hole == MAP_FAILED || munmap(base + 12 * page, (size_t)page)) return 84;
    long numbers[] = {SYS_mlock, SYS_munlock, SYS_mlock2};
    const char *names[] = {"mlock", "munlock", "mlock2"};
    for (int i = 0; i < 3; i++) {
        long n = numbers[i];
        printf("--- %s\n", names[i]);
        lock_show("whole", n, a, (size_t)(4 * page), 0);
        lock_show("past-page-start", n, a + 1, (size_t)(4 * page - 1), 0);
        lock_show("one-byte", n, a + page + 7, 1, 0);
        lock_show("no-length", n, a, 0, 0);
        lock_show("no-length-unmapped", n, (void *)(uintptr_t)page, 0, 0);
        lock_show("no-length-past-page-start", n, (char *)(uintptr_t)page + 1, 0, 0);
        lock_show("no-access", n, base, (size_t)page, 0);
        lock_show("across-protections", n, base, (size_t)(4 * page), 0);
        lock_show("unmapped", n, (void *)(uintptr_t)page, (size_t)page, 0);
        lock_show("runs-past-mapping", n, before_hole, (size_t)(2 * page), 0);
        /* A lock looks at RLIMIT_MEMLOCK first, which only a user without
           CAP_IPC_LOCK meets: ENOMEM there and EINVAL for root, as the guest. */
        if (n == SYS_munlock) lock_show("huge", n, a, (size_t)-4096, 0);
        lock_show("wraps-to-nothing", n, a + 1, (size_t)-1, 0);
        if (n == SYS_munlock) lock_show("wraps", n, a, (size_t)-1 - 8191, 0);
        lock_show("past-user-space", n, (void *)(uintptr_t)0x800000000000, (size_t)page, 0);
        lock_show("kernel", n, (void *)(uintptr_t)-4096, (size_t)page, 0);
    }
    printf("--- flags\n");
    lock_show("onfault", SYS_mlock2, a, (size_t)page, 1);
    lock_show("unknown", SYS_mlock2, a, (size_t)page, 2);
    lock_show("onfault-and-unknown", SYS_mlock2, a, (size_t)page, 3);
    lock_show("unknown-unmapped", SYS_mlock2, (void *)(uintptr_t)page, (size_t)page, 2);
    lock_show("unknown-no-length", SYS_mlock2, a, 0, 2);
    lock_show("onfault-no-access", SYS_mlock2, base, (size_t)page, 1);
    lock_show("onfault-high-bits", SYS_mlock2, a, (size_t)page, (1L << 32) | 1);
    lock_show("no-flags-high-bits", SYS_mlock2, a, (size_t)page, 1L << 32);
    lock_show("onfault-across-protections", SYS_mlock2, base, (size_t)(4 * page), 1);
    syscall(SYS_munlock, base, (size_t)(4 * page));
    char *shared = mmap(NULL, (size_t)page, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (shared == MAP_FAILED) return 83;
    lock_show("shared", SYS_mlock, shared, (size_t)page, 0);
    lock_show("shared", SYS_munlock, shared, (size_t)page, 0);
    munmap(shared, (size_t)page);
    syscall(SYS_munlock, a, (size_t)page);
    /* A gap in the range: what is before it does not change the result. */
    munmap(a + 2 * page, (size_t)page);
    lock_show("gap", SYS_mlock, a, (size_t)(4 * page), 0);
    lock_show("gap", SYS_munlock, a, (size_t)(4 * page), 0);
    lock_show("after-gap", SYS_mlock, a + 3 * page, (size_t)page, 0);
    lock_show("after-gap", SYS_munlock, a + 3 * page, (size_t)page, 0);
    printf("contents %d\n", a[page]);
    for (long f = 0; f <= 8; f++) lock_all_show(f);
    lock_all_show(1L << 32);
    lock_all_show((1L << 32) | 1);
    /* With memory no access reaches: it is left out, and is not an error. */
    lock_all_show(1);
    return 0;
}

static int mincore_show(const char *label, void *at, size_t length, size_t pages) {
    unsigned char vec[16];
    memset(vec, 7, sizeof vec);
    errno = 0;
    int r = mincore(at, length, vec);
    printf("%s: r=%d errno=%d", label, r, errno);
    for (size_t i = 0; i < pages; i++) printf(" %d", vec[i]);
    printf("\n");
    return r;
}

static int mincore_cases(void) {
    long page = 4096;
    /* Each mapping lies between PROT_NONE pages, not to merge or grow into a
       huge page. */
    char *base = mmap(NULL, 64 * page, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (base == MAP_FAILED) return 80;
    int flags = MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS;
    char *a = mmap(base + 2 * page, 4 * page, PROT_READ | PROT_WRITE, flags, -1, 0);
    if (a == MAP_FAILED) return 81;
    mincore_show("untouched", a, (size_t)(4 * page), 5);
    a[page] = 1;
    mincore_show("written", a, (size_t)(4 * page), 5);
    volatile char seen = a[2 * page];
    (void)seen;
    mincore_show("read", a, (size_t)(4 * page), 5);
    mincore_show("short-length", a + page, 1, 2);
    mincore_show("no-length", a, 0, 1);
    mincore_show("no-access", base, (size_t)page, 1);
    madvise(a + page, (size_t)page, MADV_DONTNEED);
    mincore_show("dontneed", a, (size_t)(4 * page), 5);
    mprotect(a + 2 * page, (size_t)page, PROT_READ);
    mincore_show("protected", a, (size_t)(4 * page), 5);

    /* Errors. */
    mincore_show("misaligned", a + 1, (size_t)page, 1);
    errno = 0;
    int bad = mincore(a, (size_t)page, (unsigned char *)16);
    printf("bad-vec=%d errno=%d\n", bad, errno);
    errno = 0;
    bad = mincore(a, 0, (unsigned char *)16);
    printf("no-length-bad-vec=%d errno=%d\n", bad, errno);
    mincore_show("huge", a, (size_t)-4096, 1);
    /* A gap: what is before it is written. */
    a[0] = 1;
    munmap(a + 2 * page, (size_t)page);
    mincore_show("gap", a, (size_t)(4 * page), 5);
    mincore_show("unmapped", a + 2 * page, (size_t)page, 1);

    /* A fork keeps what is in memory. */
    fflush(stdout);
    pid_t child = fork();
    if (child < 0) return 82;
    if (!child) {
        mincore_show("forked", a, (size_t)(2 * page), 3);
        fflush(stdout);
        _exit(0);
    }
    int status;
    waitpid(child, &status, 0);

    /* Shared anonymous memory. */
    char *s = mmap(base + 10 * page, 3 * page, PROT_READ | PROT_WRITE,
                   MAP_FIXED | MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (s == MAP_FAILED) return 83;
    mincore_show("shared-untouched", s, (size_t)(3 * page), 4);
    s[page] = 1;
    mincore_show("shared-written", s, (size_t)(3 * page), 4);

    /* A file that was written, whose pages are in the page cache, and past its
       end, where there are none. */
    char dir[] = "/tmp/mincore-XXXXXX";
    if (!mkdtemp(dir) || chdir(dir)) return 84;
    int fd = open("data", O_CREAT | O_RDWR, 0644);
    char fill[2 * 4096];
    memset(fill, 'x', sizeof fill);
    if (fd < 0 || write(fd, fill, sizeof fill) != (long)sizeof fill) return 85;
    char *f = mmap(base + 20 * page, 3 * page, PROT_READ, MAP_FIXED | MAP_PRIVATE, fd, 0);
    if (f == MAP_FAILED) return 86;
    mincore_show("file", f, (size_t)(3 * page), 4);
    close(fd);
    unlink("data");
    if (chdir("/") || rmdir(dir)) return 87;
    return 0;
}

/* The CPU mask a new thread starts with, for the affinity case. */
/* struct sched_attr. */
struct attr {
    uint32_t size, policy;
    uint64_t flags;
    int32_t nice;
    uint32_t priority;
    uint64_t runtime, deadline, period;
    uint32_t util_min, util_max;
};
/* What the sched_get* calls report for the calling thread. */
static void sched_show(const char *label) {
    int param = -1;
    struct attr a;
    memset(&a, 0xee, sizeof a);
    long scheduler = syscall(SYS_sched_getscheduler, 0);
    syscall(SYS_sched_getparam, 0, &param);
    struct timespec slice = {-1, -1};
    syscall(SYS_sched_rr_get_interval, 0, &slice);
    long r = syscall(SYS_sched_getattr, 0, &a, sizeof a, 0);
    printf("%s: scheduler=%#lx param=%d interval=%ld.%09ld nice=%d getattr=%ld size=%u policy=%u flags=%#lx "
           "nice=%d priority=%u runtime=%lu deadline=%lu period=%lu clamps=%u,%u\n",
           label, scheduler, param, (long)slice.tv_sec, slice.tv_nsec, getpriority(PRIO_PROCESS, 0), r, a.size,
           a.policy, (unsigned long)a.flags, a.nice, a.priority, (unsigned long)a.runtime,
           (unsigned long)a.deadline, (unsigned long)a.period, a.util_min, a.util_max);
}
static void *membarrier_thread(void *unused) {
    (void)unused;
    printf("thread: registrations=%ld private=%ld\n", syscall(SYS_membarrier, 512, 0, 0),
           syscall(SYS_membarrier, 8, 0, 0));
    return NULL;
}
static volatile int unshare_release, unshare_child_done;
static volatile int unshare_waiter_tid;
static void *unshare_waiter(void *unused) {
    (void)unused;
    unshare_waiter_tid = syscall(SYS_gettid);
    while (!unshare_release) sched_yield();
    return NULL;
}
/* Waits until /proc/self/task no longer lists a joined thread. pthread_join
   returns when the thread clears its TID, before Linux's release_task takes
   it out of the thread group and drops its share of the signal handlers,
   which unshare checks; paludarium likewise wakes the joiner before the
   thread leaves its group. */
static void unshare_wait_gone(int tid) {
    char path[64];
    snprintf(path, sizeof path, "/proc/self/task/%d", tid);
    struct stat st;
    while (stat(path, &st) == 0) sched_yield();
}
/* A thread that unshares its descriptor table and its directory, then
   closes, moves and changes them, which the process does not see. */
static void *unshare_thread(void *unused) {
    (void)unused;
    long r = syscall(SYS_unshare, CLONE_FILES|CLONE_FS);
    int fd = open("/", O_RDONLY);
    printf("thread: unshare=%ld\n", r);
    close(fd);
    for (int i = 3; i < 64; i++) close(i);
    chdir("/proc");
    umask(077);
    return NULL;
}
static int unshare_vm_child(void *unused) {
    (void)unused;
    long results[2];
    int errors[2];
    long tries[] = {CLONE_SIGHAND, CLONE_VM};
    for (int i = 0; i < 2; i++) {
        errno = 0;
        results[i] = syscall(SYS_unshare, tries[i]);
        errors[i] = errno;
    }
    char line[96];
    int n = snprintf(line, sizeof line, "child 0x800: %ld errno=%d\nchild 0x100: %ld errno=%d\n",
                     results[0], errors[0], results[1], errors[1]);
    write(1, line, n);
    unshare_child_done = 1;
    while (!unshare_release) sched_yield();
    return 0;
}
static void *affinity_of_thread(void *mask) {
    syscall(SYS_sched_getaffinity, 0, 16 * sizeof(unsigned long), mask);
    return NULL;
}

/* System V shared memory, compared without the IDs, keys and addresses the
   machine chooses: the IDs and keys of other programs on a native machine
   share its one IPC namespace. */
enum {
    SHMX_CREAT = 01000, SHMX_EXCL = 02000, SHMX_RDONLY = 010000, SHMX_RND = 020000,
    SHMX_REMAP = 040000, SHMX_RMID = 0, SHMX_SET = 1, SHMX_STAT = 2, SHMX_INFO = 3,
    SHMX_LOCK = 11, SHMX_UNLOCK = 12, SHMX_STAT_INDEX = 13, SHMX_INFO_ALL = 14,
};
struct shm_status {
    int key, cpid, lpid;
    unsigned uid, gid, cuid, cgid, mode, seq;
    unsigned long segsz, nattch;
    long atime, dtime, ctime;
};
/* shmctl's `struct shmid64_ds`, read by its x86-64 offsets; the result, or
   -errno. */
static long shm_status_of(int id, int cmd, struct shm_status *s) {
    unsigned char ds[112];
    unsigned short seq = 0;
    memset(ds, 0, sizeof ds);
    memset(s, 0, sizeof *s);
    long r = syscall(SYS_shmctl, id, cmd, ds);
    if (r < 0) return -errno;
    memcpy(&s->key, ds, 4);
    memcpy(&s->uid, ds + 4, 4);
    memcpy(&s->gid, ds + 8, 4);
    memcpy(&s->cuid, ds + 12, 4);
    memcpy(&s->cgid, ds + 16, 4);
    memcpy(&s->mode, ds + 20, 4);
    memcpy(&seq, ds + 24, 2);
    s->seq = seq;
    memcpy(&s->segsz, ds + 48, 8);
    memcpy(&s->atime, ds + 56, 8);
    memcpy(&s->dtime, ds + 64, 8);
    memcpy(&s->ctime, ds + 72, 8);
    memcpy(&s->cpid, ds + 80, 4);
    memcpy(&s->lpid, ds + 84, 4);
    memcpy(&s->nattch, ds + 88, 8);
    return r;
}
static long shm_nattch(int id) {
    struct shm_status s;
    long r = shm_status_of(id, SHMX_STAT, &s);
    return r < 0 ? r : (long)s.nattch;
}
/* 0 for a call that worked, else its errno. */
static int shm_errno(long r) { return r == -1 ? errno : 0; }
static long shm_call(long number, long a, long b, long c) {
    errno = 0;
    return syscall(number, a, b, c);
}

/* rseq: registration, the abort of a critical section that a signal or
 * membarrier interrupts, and the descriptors Linux does not accept.
 * Each section spins until SIGUSR1 sets the flag: rseq_spin returns 1 when
 * the kernel sent it to the abort handler, 0 when it committed. Another
 * thread sends the signal once the spinning one is ready, with no timer,
 * so that no clock has to move. */
__asm__(".text\n"
        ".globl rseq_spin\n"
        "rseq_spin:\n"
        "    movq %rcx, (%rdi)\n"
        ".globl rseq_spin_start\n"
        "rseq_spin_start:\n"
        "    movl $1, (%rsi)\n"
        "1:  cmpl $0, (%rdx)\n"
        "    je 1b\n"
        ".globl rseq_spin_end\n"
        "rseq_spin_end:\n"
        "    xorl %eax, %eax\n"
        "    ret\n"
        "    .long 0x53053053\n"
        ".globl rseq_spin_abort\n"
        "rseq_spin_abort:\n"
        "    movl $1, %eax\n"
        "    ret\n"
        ".globl rseq_unsigned\n"
        "rseq_unsigned:\n"
        "    leaq rseq_unsigned_cs(%rip), %rax\n"
        "    movq %rax, (%rdi)\n"
        "rseq_unsigned_start:\n"
        "    movl $1, (%rsi)\n"
        "1:  cmpl $0, (%rdx)\n"
        "    je 1b\n"
        "rseq_unsigned_end:\n"
        "    xorl %eax, %eax\n"
        "    ret\n"
        "    .long 0x12345678\n"
        "rseq_unsigned_abort:\n"
        "    movl $1, %eax\n"
        "    ret\n"
        ".data\n"
        ".balign 32\n"
        ".globl rseq_spin_cs\n"
        "rseq_spin_cs:\n"
        "    .long 0, 0\n"
        "    .quad rseq_spin_start, rseq_spin_end - rseq_spin_start, rseq_spin_abort\n"
        ".balign 32\n"
        "rseq_unsigned_cs:\n"
        "    .long 0, 0\n"
        "    .quad rseq_unsigned_start, rseq_unsigned_end - rseq_unsigned_start, rseq_unsigned_abort\n"
        ".text\n");
int rseq_spin(volatile uint64_t *cs, volatile int *ready, volatile int *flag, const void *descriptor);
int rseq_unsigned(volatile uint64_t *cs, volatile int *ready, volatile int *flag);
extern char rseq_spin_start[], rseq_spin_end[], rseq_spin_abort[], rseq_spin_cs[];

struct rseq_area {
    uint32_t cpu_id_start, cpu_id;
    uint64_t rseq_cs;
    uint32_t flags, node_id, mm_cid, pad;
} __attribute__((aligned(32)));
struct rseq_desc {
    uint32_t version, flags;
    uint64_t start, length, abort;
} __attribute__((aligned(32)));

#define RSEQ_SIGNATURE 0x53053053
static volatile int rseq_flag, rseq_ready;
/* Volatile: the kernel reads and writes them behind the compiler's back. */
static volatile struct rseq_area rseq_main, rseq_other;
static _Alignas(32) char rseq_space[128];

static void rseq_alarm(int sig) {
    (void)sig;
    rseq_flag = 1;
}

static long rseq_call(volatile void *area, unsigned length, int flags, unsigned signature) {
    errno = 0;
    long r = syscall(334, (void *)area, length, flags, signature);
    return r < 0 ? -errno : r;
}

/* Sends the calling thread SIGUSR1, which sets the flag, from another
 * thread once `ready` is set. */
struct rseq_sender {
    volatile int *ready;
    pid_t pid, tid;
    pthread_t thread;
};

static void *rseq_send(void *argument) {
    struct rseq_sender *sender = argument;
    while (!*sender->ready) {}
    syscall(SYS_tgkill, sender->pid, sender->tid, SIGUSR1);
    return 0;
}

static void rseq_arm(struct rseq_sender *sender) {
    rseq_flag = 0;
    rseq_ready = 0;
    sender->ready = &rseq_ready;
    sender->pid = getpid();
    sender->tid = (pid_t)syscall(SYS_gettid);
    if (pthread_create(&sender->thread, 0, rseq_send, sender)) _exit(60);
}

/* The signal a child ends by when it spins while its area's rseq_cs is
 * `desc` and a signal comes: in the unsigned section when `desc` is 0, in
 * the section `desc` describes when `inside`, else outside it. */
static int rseq_child_dies(struct rseq_desc *desc, int inside) {
    fflush(stdout);
    pid_t child = fork();
    if (child == 0) {
        struct rlimit none = {0, 0};
        setrlimit(RLIMIT_CORE, &none);
        struct rseq_sender sender;
        rseq_arm(&sender);
        if (!desc) _exit(rseq_unsigned(&rseq_main.rseq_cs, &rseq_ready, &rseq_flag) + 50);
        if (inside) _exit(rseq_spin(&rseq_main.rseq_cs, &rseq_ready, &rseq_flag, desc) + 50);
        rseq_main.rseq_cs = (uint64_t)desc;
        rseq_ready = 1;
        while (!rseq_flag) {}
        _exit(40);
    }
    int status;
    if (waitpid(child, &status, 0) != child) return -1;
    return WIFSIGNALED(status) ? WTERMSIG(status) : 100 + WEXITSTATUS(status);
}

static volatile int rseq_other_flag, rseq_other_ready, rseq_other_result;

static void *rseq_other_thread(void *unused) {
    (void)unused;
    if (rseq_call(&rseq_other, 32, 0, RSEQ_SIGNATURE)) {
        rseq_other_result = -1;
        rseq_other_ready = 1;
        return 0;
    }
    rseq_other_result = rseq_spin(&rseq_other.rseq_cs, &rseq_other_ready, &rseq_other_flag, rseq_spin_cs);
    return 0;
}

/* Protection keys, only where a CPU with them and one without agree: the
   virtual CPU has none, so the key pkey_alloc gives (or the default key 0)
   would differ from a host with PKU. Key -1 is mprotect. */
static void pkey_show(const char *label, long r) {
    printf("%s: r=%ld errno=%d\n", label, r, r < 0 ? errno : 0);
    errno = 0;
}

static int pkey_case(void) {
    long page = 4096;
    char *base = mmap(NULL, 4 * page, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (base == MAP_FAILED) return 80;
    char *a = mmap(base + page, (size_t)page, PROT_READ | PROT_WRITE,
                   MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (a == MAP_FAILED) return 81;
    errno = 0;
    pkey_show("alloc-flags", syscall(SYS_pkey_alloc, 1L, 0L));
    pkey_show("alloc-rights", syscall(SYS_pkey_alloc, 0L, 4L));
    pkey_show("alloc-high-rights", syscall(SYS_pkey_alloc, 0L, 1L << 32));
    pkey_show("free-none", syscall(SYS_pkey_free, -1L));
    pkey_show("free-past", syscall(SYS_pkey_free, 16L));
    pkey_show("free-unallocated", syscall(SYS_pkey_free, 1L));
    /* -1 is mprotect, and only the low 32 bits are the key. */
    pkey_show("no-key", syscall(SYS_pkey_mprotect, a, page, PROT_READ, -1L));
    fflush(stdout);
    pid_t child = fork();
    if (child < 0) return 82;
    if (!child) {
        a[0] = 1;
        _exit(0);
    }
    int status = 0;
    waitpid(child, &status, 0);
    printf("write after no-key: signaled=%d sig=%d\n", WIFSIGNALED(status),
           WIFSIGNALED(status) ? WTERMSIG(status) : 0);
    pkey_show("no-key-high-bits",
              syscall(SYS_pkey_mprotect, a, page, PROT_READ | PROT_WRITE, 0xffffffffL));
    a[0] = 1;
    pkey_show("no-key-bad-prot", syscall(SYS_pkey_mprotect, a, page, 0x10L, -1L));
    /* Keys not allocated, after what Linux checks first. */
    pkey_show("unallocated", syscall(SYS_pkey_mprotect, a, page, PROT_READ, 1L));
    pkey_show("past", syscall(SYS_pkey_mprotect, a, page, PROT_READ, 16L));
    pkey_show("negative", syscall(SYS_pkey_mprotect, a, page, PROT_READ, -2L));
    a[0] = 2;
    pkey_show("misaligned", syscall(SYS_pkey_mprotect, a + 1, page, PROT_READ, 16L));
    pkey_show("empty", syscall(SYS_pkey_mprotect, a, 0L, PROT_READ, 16L));
    pkey_show("empty-bad-prot", syscall(SYS_pkey_mprotect, a, 0L, 0xffL, 16L));
    pkey_show("both-grows", syscall(SYS_pkey_mprotect, a, 0L, 0x3000000L, 16L));
    pkey_show("overflow", syscall(SYS_pkey_mprotect, a, -1L, PROT_READ, 16L));
    pkey_show("bad-prot", syscall(SYS_pkey_mprotect, a, page, 0xffL, 16L));
    printf("still writable: %d\n", a[0]);
    return 0;
}

static int rseq_case(void) {
    long cpus = sysconf(_SC_NPROCESSORS_CONF);
    printf("auxv feature-size>=28=%d align=%lu\n", getauxval(27) >= 28, getauxval(28));
    /* Each call a statement of its own: the order a call's arguments are
     * evaluated in is not C's to say. An unknown flag, not one a newer
     * Linux may have (2 is RSEQ_FLAG_SLICE_EXT_DEFAULT_ON there). */
    long unregister = rseq_call(&rseq_main, 32, 1, RSEQ_SIGNATURE);
    long unknown = rseq_call(&rseq_main, 32, 1 << 30, RSEQ_SIGNATURE);
    long short_area = rseq_call(&rseq_main, 31, 0, RSEQ_SIGNATURE);
    long misaligned = rseq_call(rseq_space + 16, 32, 0, RSEQ_SIGNATURE);
    long past_user = rseq_call((void *)0x7fffffffffe0, 32, 0, RSEQ_SIGNATURE);
    printf("before unregister=%ld unknown-flag=%ld short=%ld misaligned=%ld past-user=%ld\n", unregister,
           unknown, short_area, misaligned, past_user);
    void *gone = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (gone == MAP_FAILED || munmap(gone, 4096)) return 10;
    printf("unmapped=%ld\n", rseq_call(gone, 32, 0, RSEQ_SIGNATURE));

    /* A registration clears rseq_cs, and the area shows where it runs. */
    rseq_main.rseq_cs = 0x1234;
    rseq_main.cpu_id = 0xfffffffe;
    long r = rseq_call(&rseq_main, 32, 0, RSEQ_SIGNATURE);
    int matches = 0;
    for (int i = 0; i < 1000 && !matches; i++) {
        unsigned before, after;
        syscall(SYS_getcpu, &before, 0, 0);
        unsigned seen = rseq_main.cpu_id;
        syscall(SYS_getcpu, &after, 0, 0);
        matches = before == after && seen == before;
    }
    printf("register=%ld cs-cleared=%d cpu-valid=%d start-same=%d node=%u cid-valid=%d getcpu-same=%d\n", r,
           rseq_main.rseq_cs == 0, rseq_main.cpu_id < (unsigned long)cpus,
           rseq_main.cpu_id_start < (unsigned long)cpus, rseq_main.node_id,
           rseq_main.mm_cid < (unsigned long)cpus, matches);
    long same = rseq_call(&rseq_main, 32, 0, RSEQ_SIGNATURE);
    long other_area = rseq_call(&rseq_other, 32, 0, RSEQ_SIGNATURE);
    long other_length = rseq_call(&rseq_main, 64, 0, RSEQ_SIGNATURE);
    long other_signature = rseq_call(&rseq_main, 32, 0, RSEQ_SIGNATURE + 1);
    printf("again same=%ld other-area=%ld other-length=%ld other-signature=%ld\n", same, other_area,
           other_length, other_signature);

    /* A signal in the critical section sends it to its abort handler, and
     * the kernel clears rseq_cs; outside it, the kernel only clears it. */
    struct sigaction sa = {0};
    sa.sa_handler = rseq_alarm;
    sigaction(SIGUSR1, &sa, 0);
    struct rseq_sender sender;
    rseq_arm(&sender);
    int aborted = rseq_spin(&rseq_main.rseq_cs, &rseq_ready, &rseq_flag, rseq_spin_cs);
    pthread_join(sender.thread, 0);
    printf("signal aborted=%d handled=%d cs-cleared=%d\n", aborted, rseq_flag, rseq_main.rseq_cs == 0);
    rseq_arm(&sender);
    rseq_main.rseq_cs = (uint64_t)rseq_spin_cs;
    rseq_ready = 1;
    while (!rseq_flag) {}
    pthread_join(sender.thread, 0);
    printf("outside cs-cleared=%d\n", rseq_main.rseq_cs == 0);

    /* A descriptor the kernel does not accept ends a thread inside its
     * section by SIGSEGV when it next looks at it: here, for a signal.
     * Current Linux reads neither the version nor the flags, so a section
     * with them is aborted (the child exits 51). */
    static struct rseq_desc version = {1, 0, 0, 0, 0}, flagged = {0, 1, 0, 0, 0};
    static struct rseq_desc inside = {0, 0, 0, 0, 0};
    version.start = flagged.start = inside.start = (uint64_t)rseq_spin_start;
    version.length = flagged.length = inside.length = (uint64_t)(rseq_spin_end - rseq_spin_start);
    version.abort = flagged.abort = (uint64_t)rseq_spin_abort;
    inside.abort = (uint64_t)rseq_spin_start + 2;
    /* Current Linux refuses a descriptor only for a thread inside its
     * section, so outside it these are only cleared (the child exits 40). */
    int unsigned_abort = rseq_child_dies(0, 1);
    int in_version = rseq_child_dies(&version, 1), out_version = rseq_child_dies(&version, 0);
    int in_flags = rseq_child_dies(&flagged, 1), out_flags = rseq_child_dies(&flagged, 0);
    int in_abort = rseq_child_dies(&inside, 1), out_abort = rseq_child_dies(&inside, 0);
    printf("refused signature=%d version=%d flags=%d abort-inside=%d\n", unsigned_abort, in_version, in_flags,
           in_abort);
    printf("outside version=%d flags=%d abort-inside=%d\n", out_version, out_flags, out_abort);

    /* membarrier's RSEQ command aborts another thread's critical section. */
    errno = 0;
    long unregistered = syscall(SYS_membarrier, 1 << 7, 0, 0);
    printf("membarrier unregistered=%ld errno=%d", unregistered, errno);
    printf(" register=%ld", (long)syscall(SYS_membarrier, 1 << 8, 0, 0));
    printf(" far-cpu=%ld", (long)syscall(SYS_membarrier, 1 << 7, 1, 100000));
    /* A negative CPU with the flag is every CPU, as without the flag. */
    errno = 0;
    long negative = syscall(SYS_membarrier, 1 << 7, 1, -1);
    printf(" negative-cpu=%ld errno=%d\n", negative, errno);
    pthread_t other;
    if (pthread_create(&other, 0, rseq_other_thread, 0)) return 11;
    while (!rseq_other_ready) {}
    r = syscall(SYS_membarrier, 1 << 7, 0, 0);
    rseq_other_flag = 1;
    pthread_join(other, 0);
    printf("membarrier rseq=%ld other-aborted=%d\n", r, rseq_other_result);

    /* Unregistering needs the same area, length and signature, and leaves
     * the area showing no CPU. */
    other_signature = rseq_call(&rseq_main, 32, 1, RSEQ_SIGNATURE + 1);
    other_length = rseq_call(&rseq_main, 64, 1, RSEQ_SIGNATURE);
    other_area = rseq_call(&rseq_other, 32, 1, RSEQ_SIGNATURE);
    printf("unregister other-signature=%ld other-length=%ld other-area=%ld", other_signature, other_length,
           other_area);
    r = rseq_call(&rseq_main, 32, 1, RSEQ_SIGNATURE);
    unsigned cpu = rseq_main.cpu_id, start = rseq_main.cpu_id_start;
    long again = rseq_call(&rseq_main, 32, 1, RSEQ_SIGNATURE);
    printf(" done=%ld cpu=%x start=%u again=%ld\n", r, cpu, start, again);
    return 0;
}

static int shm_case(void) {
    long page = sysconf(_SC_PAGESIZE);
    struct shm_status s;
    int id = (int)syscall(SYS_shmget, 0, 3 * page - 10, SHMX_CREAT | 0600);
    if (id < 0) return 10;
    long r = shm_status_of(id, SHMX_STAT, &s);
    printf("new stat=%ld key=%d mode=%o segsz=%lu nattch=%lu cpid-own=%d lpid=%d atime=%ld dtime=%ld "
           "ctime-set=%d owner-own=%d seq-of-id=%d\n",
           r, s.key, s.mode, s.segsz, s.nattch, s.cpid == getpid(), s.lpid, s.atime, s.dtime, s.ctime > 0,
           s.uid == geteuid() && s.cuid == geteuid() && s.gid == getegid() && s.cgid == getegid(),
           s.seq == (unsigned)(id >> 15));

    /* A key finds its segment after ipcget's checks. */
    int key = 0x5a000000 | (getpid() & 0xffffff);
    int keyed = (int)syscall(SYS_shmget, key, 100, SHMX_CREAT | SHMX_EXCL | 0604);
    if (keyed < 0) return 11;
    printf("key same=%d", syscall(SYS_shmget, key, 0, 0) == keyed);
    printf(" exclusive=%d", shm_errno(shm_call(SYS_shmget, key, 100, SHMX_CREAT | SHMX_EXCL)));
    printf(" larger=%d", shm_errno(shm_call(SYS_shmget, key, 101, 0)));
    printf(" missing=%d", shm_errno(shm_call(SYS_shmget, key ^ 0x02000000, 100, 0600)));
    printf(" empty=%d\n", shm_errno(shm_call(SYS_shmget, 0, 0, SHMX_CREAT)));

    /* Attachments share the memory, and count as their mappings. */
    char *a = (char *)syscall(SYS_shmat, id, 0, 0);
    char *b = (char *)syscall(SYS_shmat, id, 0, SHMX_RDONLY);
    if (a == (char *)-1 || b == (char *)-1) return 12;
    strcpy(a + page, "shared");
    printf("attached seen=%d zero=%d nattch=%ld\n", !strcmp(b + page, "shared"),
           b[0] == 0 && b[3 * page - 11] == 0, shm_nattch(id));
    errno = 0;
    r = mprotect(b, page, PROT_READ | PROT_WRITE);
    printf("read-only mprotect=%ld errno=%d\n", r, errno);
    shm_status_of(id, SHMX_STAT, &s);
    printf("after attach atime-set=%d lpid-own=%d\n", s.atime > 0, s.lpid == getpid());
    {
        struct maps_line line;
        int maps = open("/proc/self/maps", O_RDONLY);
        if (maps < 0 || !maps_find(maps_text(maps), (unsigned long)a, &line)) return 13;
        printf("maps from-here=%d pages=%lu %s offset=%lx device=%02x:%02x inode-is-id=%d name=[%.*s]\n",
               line.start == (unsigned long)a, (line.end - line.start) / page, line.perms, line.offset,
               line.major, line.minor, line.inode == (unsigned long)id, line.name_length, line.name);
        close(maps);
    }
    /* mprotect splits an attachment where it changes it, and the pieces do
       not merge again; an unchanged protection splits nothing. */
    if (mprotect(a + page, page, PROT_READ)) return 14;
    printf("split nattch=%ld\n", shm_nattch(id));
    if (mprotect(a + page, page, PROT_READ | PROT_WRITE)) return 15;
    maps_show("restored", a, NULL);
    maps_show("restored-middle", a + page, NULL);
    printf("restored nattch=%ld\n", shm_nattch(id));
    if (mprotect(b + page, page, PROT_READ)) return 16;
    printf("unchanged nattch=%ld\n", shm_nattch(id));

    /* A fork copies them; shmdt takes every piece of one, and an exit the rest. */
    fflush(stdout);
    pid_t child = fork();
    if (child < 0) return 17;
    if (child == 0) {
        printf("child nattch=%ld", shm_nattch(id));
        printf(" detach=%ld", syscall(SYS_shmdt, a));
        printf(" nattch=%ld", shm_nattch(id));
        printf(" again=%d", shm_errno(shm_call(SYS_shmdt, (long)a, 0, 0)));
        printf(" unaligned=%d\n", shm_errno(shm_call(SYS_shmdt, (long)a + 1, 0, 0)));
        fflush(stdout);
        _exit(0);
    }
    int status;
    if (waitpid(child, &status, 0) != child) return 18;
    shm_status_of(id, SHMX_STAT, &s);
    printf("child gone nattch=%lu lpid-child=%d dtime-set=%d\n", s.nattch, s.lpid == child, s.dtime > 0);
    /* An unmapped head leaves one piece, which shmdt from the old start
       finds by its offset. */
    if (munmap(b, page)) return 19;
    printf("unmapped head nattch=%ld", shm_nattch(id));
    printf(" detach-old-start=%ld", syscall(SYS_shmdt, b));
    printf(" nattch=%ld", shm_nattch(id));
    printf(" detach-pieces=%ld", syscall(SYS_shmdt, a));
    printf(" nattch=%ld\n", shm_nattch(id));

    /* Addresses: page-aligned unless SHM_RND rounds them, free unless
       SHM_REMAP replaces what is there. */
    printf("addresses unaligned=%d", shm_errno(shm_call(SYS_shmat, id, (long)a + 1, 0)));
    printf(" remap-without=%d", shm_errno(shm_call(SYS_shmat, id, 0, SHMX_REMAP)));
    printf(" rounded=%d", syscall(SYS_shmat, id, (long)a + 1, SHMX_RND) == (long)a);
    printf(" taken=%d", shm_errno(shm_call(SYS_shmat, id, (long)a, 0)));
    printf(" remapped=%d", syscall(SYS_shmat, id, (long)a, SHMX_REMAP) == (long)a);
    printf(" nattch=%ld", shm_nattch(id));
    printf(" kept=%d\n", !strcmp(a + page, "shared"));
    syscall(SYS_shmdt, a);

    /* Removal waits for the last detach; meanwhile no key finds it. */
    char *x = (char *)syscall(SYS_shmat, keyed, 0, 0);
    if (x == (char *)-1) return 20;
    printf("remove=%ld", syscall(SYS_shmctl, keyed, SHMX_RMID, 0));
    shm_status_of(keyed, SHMX_STAT, &s);
    printf(" key=%d mode=%o nattch=%lu", s.key, s.mode, s.nattch);
    printf(" by-key=%d", shm_errno(shm_call(SYS_shmget, key, 0, 0)));
    char *y = (char *)syscall(SYS_shmat, keyed, 0, 0);
    printf(" attach-again=%d nattch=%ld", y != (char *)-1, shm_nattch(keyed));
    syscall(SYS_shmdt, x);
    syscall(SYS_shmdt, y);
    printf(" gone=%ld\n", shm_nattch(keyed));

    /* IPC_SET, SHM_LOCK and the information. */
    {
        unsigned char ds[112];
        unsigned mode = 0640, none = (unsigned)-1;
        if (syscall(SYS_shmctl, id, SHMX_STAT, ds)) return 21;
        memcpy(ds + 20, &mode, 4);
        printf("set=%ld", syscall(SYS_shmctl, id, SHMX_SET, ds));
        shm_status_of(id, SHMX_STAT, &s);
        printf(" mode=%o", s.mode);
        memcpy(ds + 4, &none, 4);
        printf(" bad-uid=%d", shm_errno(shm_call(SYS_shmctl, id, SHMX_SET, (long)ds)));
        printf(" bad-buffer=%d\n", shm_errno(shm_call(SYS_shmctl, id, SHMX_SET, 8)));
    }
    printf("lock=%ld", syscall(SYS_shmctl, id, SHMX_LOCK, 0));
    shm_status_of(id, SHMX_STAT, &s);
    printf(" mode=%o", s.mode);
    printf(" unlock=%ld", syscall(SYS_shmctl, id, SHMX_UNLOCK, 0));
    shm_status_of(id, SHMX_STAT, &s);
    printf(" mode=%o\n", s.mode);
    {
        unsigned long info[9];
        struct {
            int used;
            unsigned long total, resident, swapped, attempts, successes;
        } all;
        memset(info, 0xff, sizeof info);
        r = syscall(SYS_shmctl, 0, SHMX_INFO, info);
        printf("info ok=%d shmmin=%lu shmmni=%lu shmseg=%lu unused=%lu", r >= id % 32768, info[1], info[2],
               info[3], info[5] | info[6] | info[7] | info[8]);
        r = syscall(SYS_shmctl, 0, SHMX_INFO_ALL, &all);
        printf(" all ok=%d", r >= id % 32768 && all.used >= 1 && all.total >= 3 && all.swapped == 0);
        printf(" by-index=%d\n", shm_status_of(id % 32768, SHMX_STAT_INDEX, &s) == id);
    }
    unsigned char ds[112];
    printf("errors negative-id=%d", shm_errno(shm_call(SYS_shmctl, -1, SHMX_STAT, (long)ds)));
    printf(" ipc64=%d", shm_errno(shm_call(SYS_shmctl, id, 0x100 | SHMX_STAT, (long)ds)));
    printf(" command=%d", shm_errno(shm_call(SYS_shmctl, id, 99, (long)ds)));
    printf(" buffer=%d", shm_errno(shm_call(SYS_shmctl, id, SHMX_STAT, 8)));
    printf(" attach-negative=%d", shm_errno(shm_call(SYS_shmat, -1, 0, 0)));
    printf(" attach-old-sequence=%d\n", shm_errno(shm_call(SYS_shmat, id ^ (1 << 15), 0, 0)));

    /* As another user the 0604 segment lets only reading through, and its
       owner's commands nothing; as its owner, everything. Each is whether
       the outcome is the one for this process's user. */
    int keyed2 = (int)syscall(SYS_shmget, 0x5b000000 | (getpid() & 0xffffff), 64, SHMX_CREAT | SHMX_EXCL | 0604);
    if (keyed2 < 0) return 22;
    fflush(stdout);
    child = fork();
    if (child < 0) return 22;
    if (child == 0) {
        int other = 0;
        if (geteuid() == 0)
            other = !setgroups(0, NULL) && !setresgid(65534, 65534, 65534) && !setresuid(65534, 65534, 65534);
        long got = shm_call(SYS_shmget, 0x5b000000 | (getppid() & 0xffffff), 0, 0600);
        int get = other ? got == -1 && errno == EACCES : got == keyed2;
        long at = shm_call(SYS_shmat, keyed2, 0, 0);
        int attach = other ? at == -1 && errno == EACCES : at != -1;
        int read_only = syscall(SYS_shmat, keyed2, 0, SHMX_RDONLY) != -1;
        unsigned char ds[112];
        syscall(SYS_shmctl, keyed2, SHMX_STAT, ds);
        long set = shm_call(SYS_shmctl, keyed2, SHMX_SET, (long)ds);
        int setting = other ? set == -1 && errno == EPERM : set == 0;
        long locked = shm_call(SYS_shmctl, keyed2, SHMX_LOCK, 0);
        int locking = other ? locked == -1 && errno == EPERM : locked == 0;
        syscall(SYS_shmctl, keyed2, SHMX_UNLOCK, 0);
        printf("permissions as-expected get=%d attach=%d read-only=%d set=%d lock=%d\n", get, attach,
               read_only, setting, locking);
        fflush(stdout);
        _exit(0);
    }
    if (waitpid(child, &status, 0) != child) return 23;
    printf("removed=%ld", syscall(SYS_shmctl, id, SHMX_RMID, 0));
    printf(" %ld\n", syscall(SYS_shmctl, keyed2, SHMX_RMID, 0));
    return 0;
}

/* System V semaphores, compared without the IDs, keys and PIDs the machine
   chooses, as the shared memory above. Each wait is seen begun through
   GETNCNT or GETZCNT before what ends it. */
enum {
    SEMX_CREAT = 01000, SEMX_EXCL = 02000, SEMX_NOWAIT = 04000, SEMX_UNDO = 0x1000,
    SEMX_RMID = 0, SEMX_SET = 1, SEMX_STAT = 2, SEMX_INFO = 3, SEMX_GETPID = 11,
    SEMX_GETVAL = 12, SEMX_GETALL = 13, SEMX_GETNCNT = 14, SEMX_GETZCNT = 15,
    SEMX_SETVAL = 16, SEMX_SETALL = 17, SEMX_STAT_INDEX = 18, SEMX_INFO_ALL = 19,
    SEMX_STAT_ANY = 20,
};
struct semx_op {
    unsigned short num;
    short op, flags;
};
static long semx_ctl(int id, int n, int cmd, long arg) { return syscall(SYS_semctl, id, n, cmd, arg); }
static int semx_errno(long r) { return r == -1 ? errno : 0; }
/* One operation, or its error. */
static int semx_op(int id, unsigned short num, short op, short flags) {
    struct semx_op o = {num, op, flags};
    return semx_errno(syscall(SYS_semop, id, &o, 1));
}
static void semx_await(int id, int n, int cmd, long count) {
    while (semx_ctl(id, n, cmd, 0) != count) usleep(1000);
}
/* A child that does one operation and exits with its error. */
static pid_t semx_child(int id, unsigned short num, short op, short flags) {
    fflush(stdout);
    pid_t child = fork();
    if (child == 0) _exit(semx_op(id, num, op, flags));
    return child;
}
static int semx_reaped(pid_t child) {
    int status;
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status)) return -1;
    return WEXITSTATUS(status);
}
static void semx_alarm(int signal) { (void)signal; }
static void *semx_thread(void *arg) {
    int id = *(int *)arg;
    semx_op(id, 0, 1, SEMX_UNDO);
    return NULL;
}
/* The msg case: raw msgsnd and msgrcv of one buffer. musl's sys/msg.h has
   no MSG_COPY, Linux's 040000. */
#ifndef MSG_COPY
#define MSG_COPY 040000
#endif
static struct {
    long kind;
    char text[64];
} msgx_buf;
static long msgx_send(int id, long kind, const char *text, int flags) {
    msgx_buf.kind = kind;
    size_t n = strlen(text);
    memcpy(msgx_buf.text, text, n);
    errno = 0;
    long r = syscall(SYS_msgsnd, id, &msgx_buf, n, flags);
    return r < 0 ? -errno : r;
}
/* Prints what a receive gave: its result or error, and the type and text. */
static void msgx_show(const char *label, int id, size_t size, long kind, int flags) {
    memset(&msgx_buf, 0, sizeof msgx_buf);
    errno = 0;
    long r = syscall(SYS_msgrcv, id, &msgx_buf, size, kind, flags);
    if (r < 0) {
        printf(" %s=-%d", label, errno);
    } else {
        printf(" %s=%ld:%ld:%.*s", label, r, msgx_buf.kind, (int)r, msgx_buf.text);
    }
}
static volatile sig_atomic_t msgx_caught;
static void msgx_handler(int signal) {
    (void)signal;
    msgx_caught++;
}
/* msqid64_ds: msg_cbytes, msg_qnum, msg_qbytes, and whether msg_lspid and
   msg_lrpid are `sender` and `receiver`. */
static void msgx_status(const char *label, int id, pid_t sender, pid_t receiver) {
    unsigned char ds[120] = {0};
    long r = syscall(SYS_msgctl, id, 2 /* IPC_STAT */, ds);
    unsigned long cbytes, qnum, qbytes;
    int lspid, lrpid;
    unsigned mode;
    memcpy(&mode, ds + 20, 4);
    memcpy(&cbytes, ds + 72, 8);
    memcpy(&qnum, ds + 80, 8);
    memcpy(&qbytes, ds + 88, 8);
    memcpy(&lspid, ds + 96, 4);
    memcpy(&lrpid, ds + 100, 4);
    printf("%s: stat=%ld mode=%o cbytes=%lu qnum=%lu qbytes=%lu lspid=%d lrpid=%d\n", label, r, mode, cbytes,
           qnum, qbytes, lspid == sender, lrpid == receiver);
}
static int msg_case(void) {
    /* Its own IPC namespace, whose queues and counts are the case's. */
    if (syscall(SYS_unshare, CLONE_NEWIPC)) return 10;
    int key = 0x4d000000 | (getpid() & 0xffffff);
    errno = 0;
    long missing = syscall(SYS_msgget, key, 0600);
    printf("get missing=%ld errno=%d", missing, errno);
    int id = (int)syscall(SYS_msgget, key, IPC_CREAT | IPC_EXCL | 0640);
    if (id < 0) return 11;
    errno = 0;
    long again = syscall(SYS_msgget, key, IPC_CREAT | IPC_EXCL | 0600);
    int again_errno = errno;
    printf(" exclusive=%ld errno=%d same=%d\n", again, again_errno, syscall(SYS_msgget, key, 0) == id);
    /* Checks before anything is sent; a bad address comes last, below. */
    long zero = msgx_send(id, 0, "x", 0);
    errno = 0;
    long big = syscall(SYS_msgsnd, id, &msgx_buf, 8193, 0) < 0 ? -errno : 0;
    long other_id = msgx_send(id + 1, 1, "x", 0);
    printf("send zero=%ld big=%ld other=%ld\n", zero, big, other_id);
    const char *texts[] = {"three", "one", "two", "uno"};
    long kinds[] = {3, 1, 2, 1};
    for (int i = 0; i < 4; i++) {
        long sent = msgx_send(id, kinds[i], texts[i], 0);
        printf("%s%ld", i ? "," : "sent=", sent);
    }
    printf("\n");
    msgx_status("after-send", id, getpid(), 0);
    printf("receive");
    msgx_show("copy", id, 64, 2, MSG_COPY | IPC_NOWAIT);
    msgx_show("copy-wait", id, 64, 2, MSG_COPY);
    msgx_show("copy-none", id, 64, 9, MSG_COPY | IPC_NOWAIT);
    msgx_show("small", id, 2, 2, 0);
    msgx_show("cut", id, 2, 2, MSG_NOERROR);
    msgx_show("except", id, 64, 3, MSG_EXCEPT);
    msgx_show("lowest", id, 64, -2, 0);
    msgx_show("any", id, 64, 0, 0);
    msgx_show("empty", id, 64, 0, IPC_NOWAIT);
    printf("\n");
    msgx_status("after-receive", id, getpid(), getpid());
    /* A smaller queue fills. */
    unsigned char ds[120] = {0};
    syscall(SYS_msgctl, id, 2, ds);
    unsigned long qbytes = 4;
    memcpy(ds + 88, &qbytes, 8);
    long set = syscall(SYS_msgctl, id, 1 /* IPC_SET */, ds);
    long fits = msgx_send(id, 1, "abc", 0);
    long full = msgx_send(id, 1, "de", IPC_NOWAIT);
    printf("set=%ld full=%ld,%ld", set, fits, full);
    msgx_show("drain", id, 64, 0, 0);
    printf("\n");
    qbytes = 16384;
    memcpy(ds + 88, &qbytes, 8);
    syscall(SYS_msgctl, id, 1, ds);
    /* A waiting receiver takes the message it waits for as it is sent. */
    int ready[2];
    if (pipe(ready)) return 12;
    fflush(stdout);
    pid_t waiter = child();
    if (waiter == 0) {
        alarm(10);
        if (write(ready[1], "x", 1) != 1) _exit(90);
        printf("waiter");
        msgx_show("first", id, 64, 5, 0);
        printf("\n");
        fflush(stdout);
        /* A signal it handles ends the next wait with EINTR, with
           SA_RESTART too. */
        for (int restart = 0; restart < 2; restart++) {
            struct sigaction action = {0};
            action.sa_handler = msgx_handler;
            action.sa_flags = restart ? SA_RESTART : 0;
            sigaction(SIGUSR1, &action, NULL);
            if (write(ready[1], "x", 1) != 1) _exit(91);
            printf("waiter restart=%d", restart);
            msgx_show("signalled", id, 64, 7, 0);
            printf(" caught=%d\n", (int)msgx_caught);
            fflush(stdout);
        }
        if (write(ready[1], "x", 1) != 1) _exit(92);
        printf("waiter");
        /* A type no message has: the wait ends with the queue. */
        msgx_show("removed", id, 64, 9, 0);
        printf("\n");
        fflush(stdout);
        _exit(0);
    }
    char byte;
    if (read(ready[0], &byte, 1) != 1) return 13;
    usleep(100000);
    long sent_other = msgx_send(id, 4, "four", 0);
    long sent_wanted = msgx_send(id, 5, "five", 0);
    printf("sent-other=%ld sent-wanted=%ld\n", sent_other, sent_wanted);
    fflush(stdout);
    for (int i = 0; i < 2; i++) {
        if (read(ready[0], &byte, 1) != 1) return 14;
        usleep(100000);
        kill(waiter, SIGUSR1);
    }
    if (read(ready[0], &byte, 1) != 1) return 15;
    usleep(100000);
    /* The other message is still there, for no one. */
    msgx_status("before-removal", id, getpid(), waiter);
    printf("removal=%ld\n", syscall(SYS_msgctl, id, IPC_RMID, NULL));
    fflush(stdout);
    result("waiter", reaped(waiter));
    errno = 0;
    long removed = syscall(SYS_msgctl, id, 2, ds);
    printf("stat-removed=%ld errno=%d\n", removed, errno);
    /* The namespace's limits and what is in use in it. */
    int info[8] = {0};
    long max = syscall(SYS_msgctl, 0, 3 /* IPC_INFO */, info);
    printf("info=%ld pool=%d map=%d max=%d mnb=%d mni=%d ssz=%d tql=%d seg=%u\n", max, info[0], info[1], info[2],
           info[3], info[4], info[5], info[6], info[7] & 0xffff);
    int other = (int)syscall(SYS_msgget, IPC_PRIVATE, 0600);
    msgx_send(other, 1, "abc", 0);
    long in_use = syscall(SYS_msgctl, 0, 12 /* MSG_INFO */, info);
    printf("in-use=%ld queues=%d messages=%d bytes=%d\n", in_use, info[0], info[1], info[6]);
    /* A text at no address, and a buffer at none, which takes the message
       all the same. */
    errno = 0;
    long fault = syscall(SYS_msgsnd, other, NULL, 1, 0);
    int fault_errno = errno;
    errno = 0;
    long lost = syscall(SYS_msgrcv, other, NULL, 64, 0, 0);
    int lost_errno = errno;
    unsigned char last[120] = {0};
    syscall(SYS_msgctl, other, 2, last);
    unsigned long qnum;
    memcpy(&qnum, last + 80, 8);
    printf("fault send=%ld errno=%d receive=%ld errno=%d left=%lu\n", fault, fault_errno, lost, lost_errno, qnum);
    syscall(SYS_msgctl, other, IPC_RMID, NULL);
    return 0;
}
static int sem_case(void) {
    int key = 0x5c000000 | (getpid() & 0xffffff);
    printf("get too-many=%d", semx_errno(syscall(SYS_semget, 0, 32001, 0600)));
    printf(" negative=%d", semx_errno(syscall(SYS_semget, 0, -1, 0600)));
    printf(" none=%d", semx_errno(syscall(SYS_semget, 0, 0, 0600)));
    int id = (int)syscall(SYS_semget, key, 3, SEMX_CREAT | SEMX_EXCL | 0640);
    if (id < 0) return 10;
    printf(" same=%d", syscall(SYS_semget, key, 0, 0) == id);
    printf(" fewer=%d", syscall(SYS_semget, key, 2, 0600) == id);
    printf(" exclusive=%d", semx_errno(syscall(SYS_semget, key, 3, SEMX_CREAT | SEMX_EXCL)));
    printf(" more=%d", semx_errno(syscall(SYS_semget, key, 4, 0)));
    printf(" missing=%d\n", semx_errno(syscall(SYS_semget, key ^ 0x01000000, 1, 0600)));

    unsigned char ds[104];
    memset(ds, 0, sizeof ds);
    printf("stat=%ld", semx_ctl(id, 0, SEMX_STAT, (long)ds));
    unsigned mode, uid, cuid;
    long otime, ctime;
    unsigned long nsems;
    memcpy(&uid, ds + 4, 4);
    memcpy(&cuid, ds + 12, 4);
    memcpy(&mode, ds + 20, 4);
    memcpy(&otime, ds + 48, 8);
    memcpy(&ctime, ds + 64, 8);
    memcpy(&nsems, ds + 80, 8);
    printf(" mode=%o nsems=%lu otime=%ld ctime-set=%d owner=%d creator=%d\n", mode, nsems, otime,
           ctime > 0, uid == geteuid(), cuid == geteuid());

    /* Values. */
    printf("setval=%ld", semx_ctl(id, 1, SEMX_SETVAL, 7));
    printf(" getval=%ld", semx_ctl(id, 1, SEMX_GETVAL, 0));
    printf(" getpid-self=%d", semx_ctl(id, 1, SEMX_GETPID, 0) == getpid());
    printf(" getpid-none=%ld", semx_ctl(id, 0, SEMX_GETPID, 0));
    printf(" too-big=%d", semx_errno(semx_ctl(id, 1, SEMX_SETVAL, 32768)));
    printf(" negative=%d", semx_errno(semx_ctl(id, 1, SEMX_SETVAL, -1)));
    printf(" too-big-bad-id=%d", semx_errno(semx_ctl(id ^ (1 << 15), 1, SEMX_SETVAL, 32768)));
    printf(" beyond=%d", semx_errno(semx_ctl(id, 3, SEMX_SETVAL, 1)));
    printf(" get-beyond=%d", semx_errno(semx_ctl(id, 3, SEMX_GETVAL, 0)));
    printf(" get-negative=%d\n", semx_errno(semx_ctl(id, -1, SEMX_GETVAL, 0)));
    unsigned short all[3] = {1, 32767, 3}, got[3] = {0};
    printf("setall=%ld", semx_ctl(id, 0, SEMX_SETALL, (long)all));
    printf(" getall=%ld", semx_ctl(id, 0, SEMX_GETALL, (long)got));
    printf(" values=%u,%u,%u", got[0], got[1], got[2]);
    all[1] = 32768;
    printf(" too-big=%d", semx_errno(semx_ctl(id, 0, SEMX_SETALL, (long)all)));
    printf(" unchanged=%ld", semx_ctl(id, 1, SEMX_GETVAL, 0));
    printf(" fault=%d", semx_errno(semx_ctl(id, 0, SEMX_GETALL, 8)));
    printf(" set-fault=%d\n", semx_errno(semx_ctl(id, 0, SEMX_SETALL, 8)));

    /* Operations, in Linux's order of checks. */
    struct semx_op ops[2] = {{0, -1, 0}, {2, 1, 0}};
    printf("op too-many=%d", semx_errno(syscall(SYS_semop, id, ops, 501)));
    printf(" none=%d", semx_errno(syscall(SYS_semop, id, ops, 0)));
    printf(" fault=%d", semx_errno(syscall(SYS_semop, id, 8, 1)));
    printf(" negative-id=%d", semx_errno(syscall(SYS_semop, -1, ops, 1)));
    printf(" old-sequence=%d", semx_errno(syscall(SYS_semop, id ^ (1 << 15), ops, 1)));
    printf(" beyond=%d", semx_op(id, 3, 1, 0));
    printf(" both=%ld", syscall(SYS_semop, id, ops, 2));
    printf(" values=%ld,%ld", semx_ctl(id, 0, SEMX_GETVAL, 0), semx_ctl(id, 2, SEMX_GETVAL, 0));
    printf(" nowait=%d", semx_op(id, 0, -1, SEMX_NOWAIT));
    printf(" zero=%d", semx_op(id, 0, 0, 0));
    printf(" not-zero=%d", semx_op(id, 2, 0, SEMX_NOWAIT));
    printf(" over=%d", semx_op(id, 1, 1, 0));
    /* The first that would wait decides on IPC_NOWAIT; the rest go back. */
    struct semx_op partly[2] = {{2, -1, 0}, {0, -1, SEMX_NOWAIT}};
    printf(" partly=%d", semx_errno(syscall(SYS_semop, id, partly, 2)));
    printf(" back=%ld", semx_ctl(id, 2, SEMX_GETVAL, 0));
    memset(ds, 0, sizeof ds);
    semx_ctl(id, 0, SEMX_STAT, (long)ds);
    memcpy(&otime, ds + 48, 8);
    printf(" otime-set=%d\n", otime > 0);

    /* semtimedop: the timeout is read first and checked after the count. */
    struct timespec timeout = {0, 1000000000};
    struct semx_op one = {0, -1, 0};
    printf("timed fault=%d", semx_errno(syscall(SYS_semtimedop, id, &one, 501, 8)));
    printf(" too-many=%d", semx_errno(syscall(SYS_semtimedop, id, &one, 501, &timeout)));
    printf(" invalid=%d", semx_errno(syscall(SYS_semtimedop, id, &one, 1, &timeout)));
    timeout.tv_nsec = 0;
    printf(" zero=%d", semx_errno(syscall(SYS_semtimedop, id, &one, 1, &timeout)));
    timeout.tv_nsec = 50000000;
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    printf(" expired=%d", semx_errno(syscall(SYS_semtimedop, id, &one, 1, &timeout)));
    clock_gettime(CLOCK_MONOTONIC, &t1);
    long waited = (t1.tv_sec - t0.tv_sec) * 1000 + (t1.tv_nsec - t0.tv_nsec) / 1000000;
    printf(" waited=%d ncnt=%ld\n", waited >= 45, semx_ctl(id, 0, SEMX_GETNCNT, 0));

    /* Waits: counted by what they wait on, let through in order. */
    pid_t first = semx_child(id, 0, -2, 0);
    semx_await(id, 0, SEMX_GETNCNT, 1);
    pid_t second = semx_child(id, 0, -1, 0);
    semx_await(id, 0, SEMX_GETNCNT, 2);
    pid_t zero = semx_child(id, 2, 0, 0);
    semx_await(id, 2, SEMX_GETZCNT, 1);
    printf("waiting ncnt=%ld zcnt=%ld", semx_ctl(id, 0, SEMX_GETNCNT, 0), semx_ctl(id, 2, SEMX_GETZCNT, 0));
    printf(" up=%d", semx_op(id, 0, 2, 0));
    printf(" first=%d", semx_reaped(first));
    printf(" by-first=%d", semx_ctl(id, 0, SEMX_GETPID, 0) == first);
    printf(" ncnt=%ld", semx_ctl(id, 0, SEMX_GETNCNT, 0));
    printf(" setval=%ld", semx_ctl(id, 0, SEMX_SETVAL, 1));
    printf(" second=%d", semx_reaped(second));
    printf(" value=%ld", semx_ctl(id, 0, SEMX_GETVAL, 0));
    printf(" down=%d", semx_op(id, 2, -4, 0));
    printf(" zero=%d", semx_reaped(zero));
    printf(" by-zero=%d\n", semx_ctl(id, 2, SEMX_GETPID, 0) == zero);

    /* A signal ends a wait with EINTR, even with SA_RESTART. */
    fflush(stdout);
    pid_t child = fork();
    if (child == 0) {
        struct sigaction action = {0};
        action.sa_handler = semx_alarm;
        action.sa_flags = SA_RESTART;
        sigaction(SIGALRM, &action, NULL);
        struct itimerval in = {{0, 0}, {0, 50000}};
        setitimer(ITIMER_REAL, &in, NULL);
        _exit(semx_op(id, 0, -1, 0));
    }
    printf("signal=%d", semx_reaped(child));
    printf(" ncnt=%ld", semx_ctl(id, 0, SEMX_GETNCNT, 0));

    /* SEM_UNDO: an exit adds the adjustments back, cut to 0, as the exiting
       process. */
    semx_ctl(id, 0, SEMX_SETVAL, 3);
    child = semx_child(id, 0, -1, SEMX_UNDO);
    printf(" undone=%d", semx_reaped(child));
    printf(" value=%ld", semx_ctl(id, 0, SEMX_GETVAL, 0));
    printf(" by-child=%d", semx_ctl(id, 0, SEMX_GETPID, 0) == child);
    fflush(stdout);
    /* The child says when it has changed the value, and exits when told. */
    int up[2], go[2];
    if (pipe(up) || pipe(go)) return 11;
    child = fork();
    if (child == 0) {
        char c;
        semx_op(id, 0, 5, SEMX_UNDO);
        if (write(up[1], "u", 1) != 1 || read(go[0], &c, 1) != 1) _exit(1);
        _exit(0);
    }
    char c;
    if (read(up[0], &c, 1) != 1) return 12;
    printf(" up=%ld", semx_ctl(id, 0, SEMX_GETVAL, 0));
    semx_op(id, 0, -7, 0);
    if (write(go[1], "u", 1) != 1) return 13;
    printf(" exited=%d", semx_reaped(child));
    printf(" cut=%ld\n", semx_ctl(id, 0, SEMX_GETVAL, 0));
    close(up[0]);
    close(up[1]);
    close(go[0]);
    close(go[1]);

    /* The undo list is a process's: threads share it (CLONE_SYSVSEM), a
       fork does not, unshare(CLONE_SYSVSEM) leaves it, SETVAL clears it. */
    semx_ctl(id, 0, SEMX_SETVAL, 0);
    fflush(stdout);
    child = fork();
    if (child == 0) {
        pthread_t thread;
        if (pthread_create(&thread, NULL, semx_thread, &id) || pthread_join(thread, NULL)) _exit(1);
        printf("threads after-thread=%ld", semx_ctl(id, 0, SEMX_GETVAL, 0));
        fflush(stdout);
        pid_t grandchild = fork();
        if (grandchild == 0) _exit(0);
        printf(" after-fork=%d", semx_reaped(grandchild));
        printf(",%ld", semx_ctl(id, 0, SEMX_GETVAL, 0));
        printf(" unshare=%ld", syscall(SYS_unshare, CLONE_SYSVSEM));
        /* The thread may not have left the list yet, which it then applies. */
        int waits = 0;
        while (semx_ctl(id, 0, SEMX_GETVAL, 0) != 0 && waits++ < 1000) usleep(1000);
        printf(" left=%ld", semx_ctl(id, 0, SEMX_GETVAL, 0));
        semx_op(id, 0, 2, SEMX_UNDO);
        semx_op(id, 1, -1, SEMX_UNDO);
        semx_ctl(id, 0, SEMX_SETVAL, 4);
        fflush(stdout);
        _exit(0);
    }
    printf(" exited=%d", semx_reaped(child));
    printf(" values=%ld", semx_ctl(id, 0, SEMX_GETVAL, 0));
    printf(",%ld\n", semx_ctl(id, 1, SEMX_GETVAL, 0));

    /* IPC_SET, the information and removal. */
    semx_ctl(id, 0, SEMX_STAT, (long)ds);
    mode = 01600;
    memcpy(ds + 20, &mode, 4);
    printf("set=%ld", semx_ctl(id, 0, SEMX_SET, (long)ds));
    semx_ctl(id, 0, SEMX_STAT, (long)ds);
    memcpy(&mode, ds + 20, 4);
    printf(" mode=%o", mode);
    unsigned none = (unsigned)-1;
    memcpy(ds + 4, &none, 4);
    printf(" bad-uid=%d", semx_errno(semx_ctl(id, 0, SEMX_SET, (long)ds)));
    printf(" bad-buffer=%d", semx_errno(semx_ctl(id, 0, SEMX_SET, 8)));
    printf(" by-index=%d", semx_ctl(id % 32768, 0, SEMX_STAT_INDEX, (long)ds) == id);
    printf(" by-index-any=%d", semx_ctl(id % 32768, 0, SEMX_STAT_ANY, (long)ds) == id);
    printf(" command=%d", semx_errno(semx_ctl(id, 0, 99, 0)));
    printf(" ipc64=%d\n", semx_errno(semx_ctl(id, 0, 0x100 | SEMX_STAT, (long)ds)));
    {
        int info[10];
        memset(info, 0xff, sizeof info);
        long r = semx_ctl(0, 0, SEMX_INFO, (long)info);
        printf("info ok=%d map=%d mni=%d mns=%d mnu=%d msl=%d opm=%d ume=%d usz=%d vmx=%d aem=%d", r >= id % 32768,
               info[0], info[1], info[2], info[3], info[4], info[5], info[6], info[7], info[8], info[9]);
        r = semx_ctl(0, 0, SEMX_INFO_ALL, (long)info);
        printf(" all ok=%d in-use=%d used=%d", r >= id % 32768, info[7] >= 1, info[9] >= 3);
        printf(" fault=%d\n", semx_errno(semx_ctl(0, 0, SEMX_INFO, 8)));
    }

    /* As another user the 0604 set lets only reading through, and its
       owner's commands nothing; as its owner, everything. */
    int keyed = (int)syscall(SYS_semget, key ^ 0x02000000, 1, SEMX_CREAT | SEMX_EXCL | 0604);
    if (keyed < 0) return 14;
    fflush(stdout);
    child = fork();
    if (child == 0) {
        int other = 0;
        if (geteuid() == 0)
            other = !setgroups(0, NULL) && !setresgid(65534, 65534, 65534) && !setresuid(65534, 65534, 65534);
        long got = syscall(SYS_semget, key ^ 0x02000000, 0, 0600);
        int get = other ? got == -1 && errno == EACCES : got == keyed;
        int reading = semx_op(keyed, 0, 0, 0) == 0 && semx_ctl(keyed, 0, SEMX_GETVAL, 0) == 0;
        int change = other ? semx_op(keyed, 0, 1, 0) == EACCES : semx_op(keyed, 0, 1, 0) == 0;
        long set = semx_ctl(keyed, 0, SEMX_SETVAL, 0);
        int setting = other ? set == -1 && errno == EACCES : set == 0;
        unsigned char ds[104];
        semx_ctl(keyed, 0, SEMX_STAT, (long)ds);
        long stat_set = semx_ctl(keyed, 0, SEMX_SET, (long)ds);
        int owner = other ? stat_set == -1 && errno == EPERM : stat_set == 0;
        printf("permissions as-expected get=%d read=%d change=%d setval=%d set=%d\n", get, reading, change, setting,
               owner);
        fflush(stdout);
        _exit(0);
    }
    if (semx_reaped(child)) return 15;

    /* Removal ends the waits with EIDRM. */
    semx_ctl(id, 0, SEMX_SETVAL, 0);
    child = semx_child(id, 0, -1, 0);
    semx_await(id, 0, SEMX_GETNCNT, 1);
    printf("remove=%ld", semx_ctl(id, 0, SEMX_RMID, 0));
    printf(" waiter=%d", semx_reaped(child));
    printf(" gone=%d", semx_errno(semx_ctl(id, 0, SEMX_GETVAL, 0)));
    printf(" by-key=%d", semx_errno(syscall(SYS_semget, key, 0, 0)));
    printf(" again=%d", semx_errno(semx_ctl(id, 0, SEMX_RMID, 0)));
    printf(" other=%ld\n", semx_ctl(keyed, 0, SEMX_RMID, 0));
    return 0;
}

int main(int argc, char **argv) {
    if (argc >= 1 && !strncmp(argv[0], "./interp", 8)) return script_show(argc, argv);
    if (argc < 3) return 99;
    const char *mode = argv[1], *self = argv[2];
    if (!strcmp(mode, "clone-vm")) {
        char *stack = mmap(NULL, 65536, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
        if (stack == MAP_FAILED) return 80;
        int parent_tid = 0, child_tid = 0;
        pid_t pid = clone(vm_child, stack + 65536, CLONE_VM|CLONE_PARENT_SETTID|CLONE_CHILD_SETTID|SIGCHLD, NULL, &parent_tid, NULL, &child_tid);
        if (pid < 0) return 79;
        finish(pid);
        result("vm", vm_value == 23);
        result("parent-tid", parent_tid == pid);
        result("child-tid", child_tid == pid);
        return 0;
    }
    if (!strcmp(mode, "clone-sighand")) {
        errno = 0;
        long r = syscall(SYS_clone, CLONE_SIGHAND|SIGCHLD, 0, 0, 0, 0);
        if (r == 0) _exit(99);
        result("needs-vm", r == -1 && errno == EINVAL);
        char *stack = mmap(NULL, 65536, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
        if (stack == MAP_FAILED) return 80;
        signal(SIGUSR2, SIG_IGN);
        pid_t pid = clone(sighand_child, stack + 65536, CLONE_VM|CLONE_SIGHAND|SIGCHLD, NULL);
        if (pid < 0) return 79;
        result("child", reaped(pid));
        struct sigaction old;
        sigaction(SIGUSR1, NULL, &old);
        result("shared", old.sa_handler == interrupted);
        received = 0;
        raise(SIGUSR1);
        result("delivered", received);
        /* execve gives the child its own dispositions again. */
        sighand_self = (char *)self;
        fflush(stdout);
        pid = clone(sighand_exec, stack + 65536, CLONE_VM|CLONE_VFORK|CLONE_SIGHAND|SIGCHLD, NULL);
        if (pid < 0) return 78;
        result("exec-child", reaped(pid));
        sigaction(SIGUSR1, NULL, &old);
        result("kept", old.sa_handler == interrupted);
        sigaction(SIGUSR2, NULL, &old);
        result("unshared", old.sa_handler == SIG_IGN);
        return 0;
    }
    if (!strcmp(mode, "clone-high-bits")) {
        /* clone reads only the low 32 bits of its flags: bit 33 is no flag,
           and bit 32 (CLONE_CLEAR_SIGHAND) only exists for clone3. */
        signal(SIGUSR1, interrupted);
        const unsigned long long high[] = { 1ULL << 33, 1ULL << 32 };
        for (int i = 0; i < 2; i++) {
            errno = 0;
            long pid = syscall(SYS_clone, high[i] | SIGCHLD, 0, 0, 0, 0);
            if (pid == 0) {
                struct sigaction old;
                sigaction(SIGUSR1, NULL, &old);
                _exit(old.sa_handler == interrupted ? 7 : 8);
            }
            result(i ? "bit32" : "bit33", pid < 0 ? -errno : reaped(pid));
        }
        return 0;
    }
    if (!strcmp(mode, "sighand-exec-child")) {
        struct sigaction old;
        sigaction(SIGUSR1, NULL, &old);
        result("exec-default", old.sa_handler == SIG_DFL);
        sigaction(SIGUSR2, NULL, &old);
        result("exec-ignored", old.sa_handler == SIG_IGN);
        signal(SIGUSR2, SIG_DFL);
        return 6;
    }
    if (!strcmp(mode, "exec-thread-child")) {
        if (argc != 5) return 77;
        close(atoi(argv[4]));
        signal(SIGPIPE, SIG_IGN);
        errno = 0;
        result("sibling-gone", write(atoi(argv[3]), "x", 1) == -1 && errno == EPIPE);
        result("replacement", 1);
        return 0;
    }
    if (!strcmp(mode, "exec-thread")) {
        pthread_t sibling;
        if (pipe(thread_ready) || pipe(thread_block) || pthread_create(&sibling, NULL, blocked_sibling, NULL)) return 83;
        char byte;
        if (read(thread_ready[0], &byte, 1) != 1) return 82;
        char writer[16], reader[16];
        snprintf(writer, sizeof writer, "%d", thread_block[1]);
        snprintf(reader, sizeof reader, "%d", thread_block[0]);
        char *args[] = { "process", "exec-thread-child", (char *)self, writer, reader, NULL };
        char *env[] = { NULL };
        execve(self, args, env);
        return 81;
    }
    if (!strcmp(mode, "child")) {
        result("argv", argc == 4 && !strcmp(argv[3], "argument"));
        result("env", getenv("PROCESSES_VALUE") && !strcmp(getenv("PROCESSES_VALUE"), "value"));
        return 7;
    }
    if (!strcmp(mode, "exec-wait")) {
        /* After the exec: says so on argv[3], then waits on argv[4]. */
        char byte = 'x';
        if (argc != 5 || write(atoi(argv[3]), &byte, 1) != 1) return 1;
        return read(atoi(argv[4]), &byte, 1) == 1 ? 0 : 2;
    }
    if (!strcmp(mode, "fd-child")) {
        errno = 0;
        result("cloexec", fcntl(9, F_GETFD) == -1 && errno == EBADF);
        result("retained", fcntl(10, F_GETFD) >= 0);
        return 0;
    }
    if (!strcmp(mode, "enoent") || !strcmp(mode, "bad-elf") || !strcmp(mode, "exec-fault")) {
        const char *path = "/paludarium-not-present";
        if (!strcmp(mode, "bad-elf")) {
            path = "/tmp/paludarium-invalid-elf";
            int fd = open(path, O_CREAT|O_TRUNC|O_WRONLY, 0700);
            if (fd < 0 || write(fd, "invalid", 7) != 7 || close(fd)) return 98;
        }
        if (!strcmp(mode, "exec-fault")) path = (const char *)1;
        char *args[] = { "child", NULL };
        char *env[] = { NULL };
        errno = 0;
        result("exec", syscall(SYS_execve, path, args, env));
        result("errno", errno);
        result("old-state", 1);
        if (!strcmp(mode, "bad-elf")) unlink(path);
        return 0;
    }
    if (!strcmp(mode, "scheduling")) {
        /* Every thread runs under SCHED_OTHER with priority 0, found as
           Linux finds a thread: 0 is the caller, and another process's
           thread counts. */
        pid_t other = child();
        if (other == 0) { pause(); _exit(0); }
        long pids[] = {0, getpid(), other, 0x3fffffff, -1};
        const char *names[] = {"self", "pid", "child", "missing", "negative"};
        for (int i = 0; i < 5; i++) {
            int param = 99;
            errno = 0;
            long r = syscall(SYS_sched_getscheduler, pids[i]);
            printf("%s: scheduler=%ld errno=%d", names[i], r, errno);
            errno = 0;
            r = syscall(SYS_sched_getparam, pids[i], &param);
            printf(" param=%ld errno=%d priority=%d", r, errno, param);
            struct timespec slice = {99, 99}, native;
            errno = 0;
            r = syscall(SYS_sched_rr_get_interval, pids[i], &slice);
            /* The caller's slice is the machine's, and so the same on both
               sides; a sleeping thread's depends on what its CPU runs. */
            sched_rr_get_interval(0, &native);
            int same = slice.tv_sec == native.tv_sec && slice.tv_nsec == native.tv_nsec;
            printf(" interval=%ld errno=%d same=%d\n", r, errno,
                   r ? slice.tv_sec == 99 : pids[i] == other || same);
        }
        errno = 0;
        result("param-null", syscall(SYS_sched_getparam, 0x3fffffff, NULL));
        result("errno", errno);
        errno = 0;
        result("param-fault", syscall(SYS_sched_getparam, 0, (void *)1));
        result("errno", errno);
        errno = 0;
        result("interval-fault", syscall(SYS_sched_rr_get_interval, 0, (void *)1));
        result("errno", errno);
        /* The upper half of an int argument is not read. */
        result("dirty-pid", syscall(SYS_sched_getscheduler, 0xffffffff00000000UL));
        long policies[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, -1, 0x100000001L};
        for (int i = 0; i < 11; i++) {
            errno = 0;
            long max = syscall(SYS_sched_get_priority_max, policies[i]);
            int max_errno = errno;
            errno = 0;
            long min = syscall(SYS_sched_get_priority_min, policies[i]);
            printf("policy %ld: max=%ld errno=%d min=%ld errno=%d\n", policies[i], max, max_errno, min, errno);
        }
        /* ioprio_get: no thread has set an I/O priority; one reports none,
           several the best-effort level 4 ioprio_best counts them as. */
        long who[][2] = {{1, 0}, {1, getpid()}, {1, other}, {1, 0x3fffffff}, {1, -1}, {2, 0},
                         {2, getpgrp()}, {2, 0x3fffffff}, {3, 0}, {3, getuid()}, {3, -1}, {0, 0}, {4, 0},
                         {0x100000001L, 0}};
        for (int i = 0; i < 14; i++) {
            errno = 0;
            long r = syscall(SYS_ioprio_get, who[i][0], who[i][1]);
            printf("ioprio %ld: %ld errno=%d\n", who[i][0], r, errno);
        }
        kill(other, SIGKILL);
        result("reaped", reaped(other));
        return 0;
    }
    if (!strcmp(mode, "scheduling-set")) {
        /* The policies and attributes sched_setscheduler, sched_setparam and
           sched_setattr set, and what the sched_get* calls and children see.
           Linux runs this case as root, as the guest is. */
        int param = 10;
        result("fifo", syscall(SYS_sched_setscheduler, 0, SCHED_FIFO, &param));
        sched_show("fifo");
        param = 5;
        result("rr-reset", syscall(SYS_sched_setscheduler, 0, SCHED_RR | 0x40000000, &param));
        sched_show("rr");
        param = 20;
        result("setparam", syscall(SYS_sched_setparam, 0, &param));
        sched_show("setparam");
        fflush(stdout);
        pid_t pid = child();
        if (pid == 0) {
            sched_show("reset-child");
            fflush(stdout);
            _exit(0);
        }
        result("reaped", reaped(pid));
        /* The checks, in order. */
        struct { long pid, policy; int value; int null; } bad[] = {
            {0, SCHED_RR, 0, 0}, {0, 4, 0, 0}, {0, SCHED_FIFO, 100, 0}, {0, SCHED_OTHER, 1, 0},
            {0, SCHED_OTHER, 0, 1}, {-1, SCHED_OTHER, 0, 0}, {0x3fffffff, SCHED_OTHER, 0, 0}, {0, -1, 0, 0},
        };
        for (int i = 0; i < 8; i++) {
            param = bad[i].value;
            errno = 0;
            long r = syscall(SYS_sched_setscheduler, bad[i].pid, bad[i].policy, bad[i].null ? NULL : &param);
            printf("bad %d: %ld errno=%d\n", i, r, errno);
        }
        errno = 0;
        long r = syscall(SYS_sched_setscheduler, 0, SCHED_OTHER, (void *)1);
        printf("fault: %ld errno=%d\n", r, errno);
        /* The normal policies, and their nice value and slice. */
        long policies[] = {SCHED_BATCH, SCHED_IDLE, 7, SCHED_OTHER};
        for (int i = 0; i < 4; i++) {
            param = 0;
            errno = 0;
            r = syscall(SYS_sched_setscheduler, 0, policies[i], &param);
            printf("policy %ld: %ld errno=%d\n", policies[i], r, errno);
            sched_show("normal");
        }
        struct attr a = {.size = 48, .policy = SCHED_OTHER, .nice = 5, .runtime = 3000000};
        result("attr-nice", syscall(SYS_sched_setattr, 0, &a, 0));
        sched_show("attr-nice");
        /* A child keeps a custom slice when the reset flag is not set. */
        fflush(stdout);
        pid = child();
        if (pid == 0) {
            sched_show("slice-child");
            fflush(stdout);
            _exit(0);
        }
        result("reaped", reaped(pid));
        /* SCHED_EXT takes a nice value and a slice as the fair policies do. */
        a = (struct attr){.size = 48, .policy = 7, .nice = 3, .runtime = 500000};
        result("ext-nice", syscall(SYS_sched_setattr, 0, &a, 0));
        sched_show("ext-nice");
        a = (struct attr){.size = 48, .policy = SCHED_OTHER, .nice = 5, .runtime = 1};
        result("attr-short", syscall(SYS_sched_setattr, 0, &a, 0));
        sched_show("attr-short");
        a = (struct attr){.size = 48, .flags = 0x08 | 0x10};
        result("keep", syscall(SYS_sched_setattr, 0, &a, 0));
        sched_show("keep");
        /* SCHED_DEADLINE: 10 ms every 100 ms, by 30 ms. It may not fork,
           nor leave a CPU out of its mask. */
        a = (struct attr){.size = 48, .policy = 6, .runtime = 10000000, .deadline = 30000000, .period = 100000000};
        result("deadline", syscall(SYS_sched_setattr, 0, &a, 0));
        sched_show("deadline");
        errno = 0;
        result("deadline-fork", syscall(SYS_fork));
        result("errno", errno);
        unsigned long one[16] = {1};
        errno = 0;
        r = syscall(SYS_sched_setaffinity, 0, sizeof one, one);
        printf("deadline-affinity: one-cpu=%d %ld errno=%d\n", sysconf(_SC_NPROCESSORS_ONLN) == 1, r, errno);
        struct attr deadlines[] = {
            {.size = 48, .policy = 6, .runtime = 40000000, .deadline = 30000000, .period = 100000000},
            {.size = 48, .policy = 6, .runtime = 10000000, .deadline = 30000000, .period = 50000},
            {.size = 48, .policy = 6, .runtime = 1000, .deadline = 30000000},
            {.size = 48, .policy = 6, .runtime = 10000000, .deadline = 0},
        };
        for (int i = 0; i < 4; i++) {
            errno = 0;
            r = syscall(SYS_sched_setattr, 0, &deadlines[i], 0);
            printf("bad deadline %d: %ld errno=%d\n", i, r, errno);
        }
        a = (struct attr){.size = 48, .policy = SCHED_OTHER};
        result("normal-again", syscall(SYS_sched_setattr, 0, &a, 0));
        /* Sizes and flags. */
        unsigned char big[64] = {0};
        struct attr *b = (struct attr *)big;
        b->size = 64;
        result("size-64", syscall(SYS_sched_setattr, 0, big, 0));
        big[60] = 1;
        errno = 0;
        r = syscall(SYS_sched_setattr, 0, big, 0);
        printf("size-64-dirty: %ld errno=%d size=%u\n", r, errno, b->size);
        a = (struct attr){.size = 40};
        errno = 0;
        r = syscall(SYS_sched_setattr, 0, &a, 0);
        printf("size-40: %ld errno=%d size=%u\n", r, errno, a.size);
        a = (struct attr){.size = 0};
        result("size-0", syscall(SYS_sched_setattr, 0, &a, 0));
        long setattr_bad[][3] = {{0, 0, 0}, {0, 1, 1}, {-1, 1, 0}, {0x3fffffff, 1, 0}};
        a = (struct attr){.size = 48};
        for (int i = 0; i < 4; i++) {
            errno = 0;
            r = syscall(SYS_sched_setattr, setattr_bad[i][0], setattr_bad[i][1] ? &a : NULL, setattr_bad[i][2]);
            printf("setattr bad %d: %ld errno=%d\n", i, r, errno);
        }
        a = (struct attr){.size = 48, .flags = 0x80};
        errno = 0;
        r = syscall(SYS_sched_setattr, 0, &a, 0);
        printf("unknown-flag: %ld errno=%d\n", r, errno);
        a = (struct attr){.size = 48, .policy = 0x80000000};
        errno = 0;
        r = syscall(SYS_sched_setattr, 0, &a, 0);
        printf("negative-policy: %ld errno=%d\n", r, errno);
        /* The utilization clamps. */
        long clamps[][2] = {{100, 200}, {-1, 200}, {300, 200}, {2000, 0}, {0, -1}};
        for (int i = 0; i < 5; i++) {
            a = (struct attr){.size = 56, .flags = 0x60, .util_min = clamps[i][0], .util_max = clamps[i][1]};
            errno = 0;
            r = syscall(SYS_sched_setattr, 0, &a, 0);
            printf("clamp %d: %ld errno=%d\n", i, r, errno);
            sched_show("clamp");
        }
        a = (struct attr){.size = 48, .flags = 0x20};
        errno = 0;
        r = syscall(SYS_sched_setattr, 0, &a, 0);
        printf("clamp-short: %ld errno=%d\n", r, errno);
        /* sched_getattr's checks, and a short copy. */
        long getattr_bad[][4] = {{0, 0, 56, 0}, {0, 1, 47, 0}, {0, 1, 4097, 0}, {0, 1, 56, 1}, {-1, 1, 56, 0}, {0x3fffffff, 1, 56, 0}};
        for (int i = 0; i < 6; i++) {
            errno = 0;
            r = syscall(SYS_sched_getattr, getattr_bad[i][0], getattr_bad[i][1] ? &a : NULL, getattr_bad[i][2], getattr_bad[i][3]);
            printf("getattr bad %d: %ld errno=%d\n", i, r, errno);
        }
        memset(big, 0xee, sizeof big);
        r = syscall(SYS_sched_getattr, 0, big, 48, 0);
        printf("getattr-48: %ld size=%u after=%#x\n", r, b->size, big[48]);
        r = syscall(SYS_sched_getattr, 0, big, 64, 0);
        printf("getattr-64: %ld size=%u after=%#x\n", r, b->size, big[60]);
        /* A user: no real-time policy without RLIMIT_RTPRIO, no lower nice
           value without RLIMIT_NICE, no way back from SCHED_IDLE, and no
           clearing of SCHED_RESET_ON_FORK. */
        fflush(stdout);
        pid = child();
        if (pid == 0) {
            if (setresgid(65534, 65534, 65534) || setresuid(65534, 65534, 65534)) _exit(90);
            param = 1;
            errno = 0;
            r = syscall(SYS_sched_setscheduler, 0, SCHED_FIFO, &param);
            printf("user fifo: %ld errno=%d\n", r, errno);
            a = (struct attr){.size = 48, .nice = -5};
            errno = 0;
            r = syscall(SYS_sched_setattr, 0, &a, 0);
            printf("user nice: %ld errno=%d\n", r, errno);
            a = (struct attr){.size = 48, .policy = 6, .runtime = 10000000, .deadline = 30000000};
            errno = 0;
            r = syscall(SYS_sched_setattr, 0, &a, 0);
            printf("user deadline: %ld errno=%d\n", r, errno);
            param = 0;
            errno = 0;
            r = syscall(SYS_sched_setscheduler, getppid(), SCHED_BATCH, &param);
            printf("user other's: %ld errno=%d\n", r, errno);
            result("user reset", syscall(SYS_sched_setscheduler, 0, SCHED_OTHER | 0x40000000, &param));
            errno = 0;
            r = syscall(SYS_sched_setscheduler, 0, SCHED_OTHER, &param);
            printf("user unreset: %ld errno=%d\n", r, errno);
            result("user idle", syscall(SYS_sched_setscheduler, 0, SCHED_IDLE | 0x40000000, &param));
            errno = 0;
            r = syscall(SYS_sched_setscheduler, 0, SCHED_OTHER | 0x40000000, &param);
            printf("user from idle: %ld errno=%d\n", r, errno);
            fflush(stdout);
            _exit(0);
        }
        result("user", reaped(pid));
        /* ioprio_set: the priority is kept and reported, and passes to a
           child when it has a class. */
        setpriority(PRIO_PROCESS, 0, 0);
        long ioprios[] = {2 << 13 | 3, 2 << 13 | 1 << 3 | 3, 0, 1 << 13 | 7, 3 << 13, 4 << 13, 7 << 13, 1, -1};
        for (int i = 0; i < 9; i++) {
            errno = 0;
            r = syscall(SYS_ioprio_set, 1, 0, ioprios[i]);
            int set_errno = errno;
            printf("ioprio %#lx: %ld errno=%d now=%#lx\n", ioprios[i], r, set_errno, syscall(SYS_ioprio_get, 1, 0));
        }
        setpriority(PRIO_PROCESS, 0, 10);
        syscall(SYS_ioprio_set, 1, 0, 0);
        printf("ioprio niced: %#lx\n", syscall(SYS_ioprio_get, 1, 0));
        setpriority(PRIO_PROCESS, 0, 0);
        long whos[][2] = {{0, 0}, {1, 0x3fffffff}, {2, 0x3fffffff}, {3, -1}};
        for (int i = 0; i < 4; i++) {
            errno = 0;
            r = syscall(SYS_ioprio_set, whos[i][0], whos[i][1], 2 << 13);
            printf("ioprio who %d: %ld errno=%d\n", i, r, errno);
        }
        syscall(SYS_ioprio_set, 1, 0, 2 << 13 | 2);
        fflush(stdout);
        pid = child();
        if (pid == 0) {
            printf("child ioprio: %#lx\n", syscall(SYS_ioprio_get, 1, 0));
            if (setresgid(65534, 65534, 65534) || setresuid(65534, 65534, 65534)) _exit(90);
            errno = 0;
            r = syscall(SYS_ioprio_set, 1, 0, 1 << 13);
            printf("user ioprio rt: %ld errno=%d\n", r, errno);
            errno = 0;
            r = syscall(SYS_ioprio_set, 1, getppid(), 2 << 13);
            printf("user ioprio other's: %ld errno=%d\n", r, errno);
            result("user ioprio idle", syscall(SYS_ioprio_set, 1, 0, 3 << 13));
            fflush(stdout);
            _exit(0);
        }
        result("reaped", reaped(pid));
        syscall(SYS_ioprio_set, 1, 0, 0);
        pid = child();
        if (pid == 0) {
            printf("child of none: %#lx\n", syscall(SYS_ioprio_get, 1, 0));
            fflush(stdout);
            _exit(0);
        }
        result("reaped", reaped(pid));
        return 0;
    }
    if (!strcmp(mode, "personality-layout") || !strcmp(mode, "layout-exec")) {
        /* ADDR_COMPAT_LAYOUT and MMAP_PAGE_ZERO, which an exec applies.
           Linux runs this case as root, whose page 0 it may map (a user's
           exec maps none, which the kernel's unit tests check). */
        if (!strcmp(mode, "layout-exec")) {
            char *first = mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
            char *second = mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
            unsigned long persona = syscall(SYS_personality, 0xffffffffUL);
            printf("exec %#lx: upward=%d legacy-base=%d\n", persona, second > first,
                   (unsigned long)first >= 0x2aaaaaaab000UL && (unsigned long)first < 0x500000000000UL);
            maps_show("page-zero", (void *)0, NULL);
            if (persona & 0x100000) printf("page-zero byte=%d\n", *(volatile char *)0);
            fflush(stdout);
            return 0;
        }
        unsigned long personas[] = {0, 0x200000, 0x100000, 0x300000};
        for (int i = 0; i < 4; i++) {
            fflush(stdout);
            pid_t pid = child();
            if (pid == 0) {
                syscall(SYS_personality, personas[i]);
                char *arguments[] = {(char *)self, "layout-exec", (char *)self, NULL};
                execv(self, arguments);
                _exit(120);
            }
            result("reaped", reaped(pid));
        }
        return 0;
    }
    if (!strcmp(mode, "personality") || !strcmp(mode, "personality-exec")) {
        struct utsname names;
        uname(&names);
        printf("%s: personality=%#lx machine=%s release-2.6=%d\n", mode,
               syscall(SYS_personality, 0xffffffffUL), names.machine, !strncmp(names.release, "2.6.", 4));
        if (!strcmp(mode, "personality-exec")) return 0;
        /* Any value is kept; the upper half of the register is not read. */
        result("set", syscall(SYS_personality, 0xffffffff80000001UL));
        result("get", syscall(SYS_personality, 0xffffffffUL));
        /* UNAME26 and PER_LINUX32. */
        syscall(SYS_personality, 0x20008UL);
        uname(&names);
        printf("uname26: machine=%s release-2.6=%d\n", names.machine, !strncmp(names.release, "2.6.", 4));
        /* READ_IMPLIES_EXEC: a readable mapping is executable too. */
        result("rie", syscall(SYS_personality, 0x400000UL));
        char *page = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
        maps_show("read", page, NULL);
        mprotect(page, 4096, PROT_NONE);
        maps_show("none", page, NULL);
        mprotect(page, 4096, PROT_READ|PROT_WRITE);
        maps_show("read-write", page, NULL);
        syscall(SYS_personality, 0UL);
        mprotect(page, 4096, PROT_READ);
        maps_show("read-after", page, NULL);
        /* A child keeps the personality, and an exec keeps it but for
           READ_IMPLIES_EXEC. */
        result("set-flags", syscall(SYS_personality, 0x400008UL | 0x40000UL));
        pid_t pid = child();
        if (pid == 0) {
            printf("child: personality=%#lx\n", syscall(SYS_personality, 0xffffffffUL));
            fflush(stdout);
            char *arguments[] = {(char *)self, "personality-exec", (char *)self, NULL};
            execv(self, arguments);
            _exit(120);
        }
        result("reaped", reaped(pid));
        result("kept", syscall(SYS_personality, 0UL));
        return 0;
    }
    if (!strcmp(mode, "membarrier")) {
        /* The commands each need their registration, which belongs to the
           address space: its threads share it, and a fork's copy keeps it. */
        result("query", syscall(SYS_membarrier, 0, 0, 0));
        long commands[] = {1, 2, 3, 8, 32, 128, 512, 1024, -1};
        for (int i = 0; i < 9; i++) {
            errno = 0;
            long r = syscall(SYS_membarrier, commands[i], 0, 0);
            printf("command %ld: %ld errno=%d\n", commands[i], r, errno);
        }
        long steps[][3] = {{64, 0, 0}, {512, 0, 0}, {32, 0, 0}, {8, 0, 0}, {16, 0, 0}, {8, 0, 0},
                           {8, 1, 0}, {128, 1, 0}, {256, 0, 0}, {128, 1, 3}, {128, 1, 99999}, {128, 0, 0},
                           {128, 2, 0}, {0, 1, 0}, {4, 0, 0}, {4, 0, 0}, {512, 0, 0}};
        for (int i = 0; i < 17; i++) {
            errno = 0;
            long r = syscall(SYS_membarrier, steps[i][0], steps[i][1], steps[i][2]);
            printf("step %ld %ld: %ld errno=%d\n", steps[i][0], steps[i][1], r, errno);
        }
        pthread_t thread;
        pthread_create(&thread, NULL, membarrier_thread, NULL);
        pthread_join(thread, NULL);
        fflush(stdout);
        pid_t pid = child();
        if (pid == 0) {
            printf("fork: registrations=%ld\n", syscall(SYS_membarrier, 512, 0, 0));
            errno = 0;
            long r = syscall(SYS_membarrier, 8, 0, 0);
            printf("fork: private=%ld errno=%d\n", r, errno);
            fflush(stdout);
            _exit(0);
        }
        result("reaped", reaped(pid));
        return 0;
    }
    if (!strcmp(mode, "unshare")) {
        /* Nothing to unshare: one thread, its own dispositions and memory. */
        long flags[] = {0, CLONE_VM, CLONE_FS, CLONE_FILES, CLONE_SIGHAND, CLONE_THREAD, CLONE_SYSVSEM,
                        CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM,
                        0x8, 0x1000, 0x100000000L};
        for (int i = 0; i < 11; i++) {
            errno = 0;
            long r = syscall(SYS_unshare, flags[i]);
            printf("unshare %#lx: %ld errno=%d\n", flags[i], r, errno);
        }
        /* The namespaces need CAP_SYS_ADMIN, which a user does not have.
           (Root, as this case runs, may create them on Linux.) */
        fflush(stdout);
        pid_t user = child();
        if (user == 0) {
            if (setresgid(65534, 65534, 65534) || setresuid(65534, 65534, 65534)) _exit(90);
            long spaces[] = {CLONE_NEWNS, CLONE_NEWUTS, CLONE_NEWIPC, CLONE_NEWPID, CLONE_NEWNET,
                             CLONE_NEWCGROUP, 0x80 /* CLONE_NEWTIME */, CLONE_NEWNS|CLONE_FILES};
            for (int i = 0; i < 8; i++) {
                errno = 0;
                long r = syscall(SYS_unshare, spaces[i]);
                printf("namespace %#lx: %ld errno=%d\n", spaces[i], r, errno);
            }
            fflush(stdout);
            _exit(0);
        }
        result("user", reaped(user));
        /* CLONE_FILES and CLONE_FS: the thread's own table, directory and
           umask, which a thread sharing them no longer sees change. */
        pthread_t thread;
        pthread_create(&thread, NULL, unshare_thread, NULL);
        pthread_join(thread, NULL);
        int fd = open("/", O_RDONLY);
        char cwd[256];
        mode_t mask = umask(022);
        umask(mask);
        printf("after-thread: fd-open=%d moved=%d masked=%d\n", fcntl(fd, F_GETFD) >= 0,
               getcwd(cwd, sizeof cwd) && !strcmp(cwd, "/proc"), mask == 077);
        close(fd);
        /* A second thread: CLONE_THREAD, CLONE_SIGHAND and CLONE_VM are
           EINVAL, CLONE_NEWUSER (which takes CLONE_THREAD) too. */
        pthread_create(&thread, NULL, unshare_waiter, NULL);
        long threaded[] = {CLONE_THREAD, CLONE_SIGHAND, CLONE_VM, CLONE_NEWUSER, CLONE_FILES};
        for (int i = 0; i < 5; i++) {
            errno = 0;
            long r = syscall(SYS_unshare, threaded[i]);
            printf("threaded %#lx: %ld errno=%d\n", threaded[i], r, errno);
        }
        unshare_release = 1;
        pthread_join(thread, NULL);
        unshare_wait_gone(unshare_waiter_tid);
        /* Memory, and then dispositions too, shared with a CLONE_VM child,
           which tries to unshare them while the parent waits. */
        char *stack = mmap(NULL, 65536, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
        long shared[] = {CLONE_VM, CLONE_VM|CLONE_SIGHAND};
        for (int i = 0; i < 2; i++) {
            fflush(stdout);
            unshare_child_done = unshare_release = 0;
            pid_t pid = clone(unshare_vm_child, stack + 65536, shared[i]|SIGCHLD, NULL);
            while (!unshare_child_done) sched_yield();
            long tries[] = {CLONE_SIGHAND, CLONE_VM};
            for (int j = 0; j < 2; j++) {
                errno = 0;
                long r = syscall(SYS_unshare, tries[j]);
                printf("parent %#lx: %ld errno=%d\n", tries[j], r, errno);
            }
            unshare_release = 1;
            result("reaped", reaped(pid));
        }
        errno = 0;
        result("alone", syscall(SYS_unshare, CLONE_VM|CLONE_SIGHAND));
        result("errno", errno);
        return 0;
    }
    if (!strcmp(mode, "user-namespaces")) {
        /* Root makes files of three owners, and a child that makes a user
           namespace, whose maps root writes for it. */
        char dir[] = "/tmp/userns-XXXXXX";
        if (!mkdtemp(dir) || chmod(dir, 0755)) return 90;
        char own[64], other[64], roots[64];
        snprintf(own, sizeof own, "%s/own", dir);
        snprintf(other, sizeof other, "%s/other", dir);
        snprintf(roots, sizeof roots, "%s/root", dir);
        const char *names[] = {own, other, roots};
        uid_t owners[] = {1000, 2005, 0};
        for (int i = 0; i < 3; i++) {
            int fd = open(names[i], O_CREAT | O_WRONLY, 0644);
            if (fd < 0 || fchown(fd, owners[i], owners[i])) return 91;
            close(fd);
        }
        int ready[2], mapped[2];
        if (pipe(ready) || pipe(mapped)) return 92;
        fflush(stdout);
        pid_t inner = child();
        if (inner == 0) {
            char before[64], after[64], byte;
            ns_link("self", "user", before, sizeof before);
            errno = 0;
            long made = syscall(SYS_unshare, CLONE_NEWUSER);
            ns_link("self", "user", after, sizeof after);
            struct caps_word caps[2];
            caps_get(CAPS_V3, 0, caps);
            uint64_t effective = caps[0].effective | (uint64_t)caps[1].effective << 32;
            printf("inner: unshare=%ld errno=%d changed=%d uid=%d gid=%d full=%d\n", made, errno,
                   strcmp(before, after) != 0, getuid(), getgid(), effective == CAPS_ALL);
            char text[256] = {0};
            int fd = open("/proc/self/uid_map", O_RDONLY);
            long n = fd >= 0 ? read(fd, text, sizeof text - 1) : -1;
            printf("inner: uid_map=%ld", n);
            close(fd);
            fd = open("/proc/self/setgroups", O_RDONLY);
            n = fd >= 0 ? read(fd, text, sizeof text - 1) : -1;
            text[n > 0 ? n : 0] = 0;
            printf(" setgroups=%s", text);
            close(fd);
            fflush(stdout);
            if (write(ready[1], "x", 1) != 1 || read(mapped[0], &byte, 1) != 1) _exit(93);
            /* Mapped: root is root, 1 is 1000 and 5 and 6 are 2005 and 2006
               outside. */
            struct stat st;
            printf("mapped: uid=%d gid=%d", getuid(), getgid());
            for (int i = 0; i < 3; i++) {
                stat(names[i], &st);
                printf(" %s=%d,%d", i == 0 ? "own" : i == 1 ? "other" : "root", st.st_uid, st.st_gid);
            }
            printf("\n");
            fd = open("/proc/self/uid_map", O_RDONLY);
            n = fd >= 0 ? read(fd, text, sizeof text - 1) : -1;
            text[n > 0 ? n : 0] = 0;
            printf("mapped: uid_map=\n%s", text);
            close(fd);
            fd = open("/proc/self/uid_map", O_WRONLY);
            errno = 0;
            long again = write(fd, "0 1000 1\n", 9);
            printf("mapped: again=%ld errno=%d\n", again, errno);
            close(fd);
            /* Capabilities count for what the namespace maps: its own file,
               not root's; a group list it may set. */
            errno = 0;
            long mine = chmod(own, 0600);
            int mine_errno = errno;
            errno = 0;
            long theirs = chmod(roots, 0600);
            printf("mapped: chmod-own=%ld errno=%d chmod-root=%ld errno=%d", mine, mine_errno, theirs,
                   errno);
            errno = 0;
            long unmapped = setuid(50);
            printf(" setuid-unmapped=%ld errno=%d", unmapped, errno);
            errno = 0;
            long groups = setgroups(0, NULL);
            printf(" setgroups=%ld errno=%d\n", groups, errno);
            /* Its capabilities do not reach the first UTS namespace, but
               one it makes is its own. */
            fflush(stdout);
            pid_t named = child();
            if (named == 0) {
                errno = 0;
                long first = sethostname("inner", 5);
                int first_errno = errno;
                long uts = syscall(SYS_unshare, CLONE_NEWUTS);
                long second = sethostname("inner", 5);
                struct utsname names_now;
                uname(&names_now);
                printf("named: first=%ld errno=%d unshare=%ld second=%ld nodename=%s\n", first, first_errno,
                       uts, second, names_now.nodename);
                fflush(stdout);
                _exit(0);
            }
            result("named", reaped(named));
            /* An ID it maps it may become, and it is then that ID outside. */
            errno = 0;
            long became = setresuid(6, 6, 6);
            int became_errno = errno;
            long stated = stat(other, &st);
            printf("mapped: setresuid=%ld errno=%d uid=%d stat=%ld other=%d\n", became, became_errno,
                   getuid(), stated, st.st_uid);
            fflush(stdout);
            _exit(0);
        }
        char byte;
        if (read(ready[0], &byte, 1) != 1) return 94;
        char path[64], text[256] = {0};
        snprintf(path, sizeof path, "/proc/%d/uid_map", inner);
        int fd = open(path, O_WRONLY);
        const char *map = "0 0 1\n1 1000 1\n5 2005 2\n";
        long uid_written = write(fd, map, strlen(map));
        close(fd);
        snprintf(path, sizeof path, "/proc/%d/gid_map", inner);
        fd = open(path, O_WRONLY);
        long gid_written = write(fd, map, strlen(map));
        close(fd);
        snprintf(path, sizeof path, "/proc/%d/uid_map", inner);
        fd = open(path, O_RDONLY);
        long n = read(fd, text, sizeof text - 1);
        text[n > 0 ? n : 0] = 0;
        close(fd);
        printf("outer: uid=%ld gid=%ld uid_map=\n%s", uid_written, gid_written, text);
        fflush(stdout);
        if (write(mapped[1], "x", 1) != 1) return 95;
        result("inner", reaped(inner));
        for (int i = 0; i < 3; i++) unlink(names[i]);
        rmdir(dir);
        return 0;
    }
    if (!strcmp(mode, "netlink")) {
        /* A child makes a network namespace, whose loopback, its only
           interface, NETLINK_ROUTE shows and brings up and down. */
        fflush(stdout);
        pid_t maker = child();
        if (maker == 0) {
            printf("unshare=%ld\n", netns_result(syscall(SYS_unshare, CLONE_NEWNET)));
            printf("socket: stream=%d protocol=%d\n", socket(NL_AF_NETLINK, SOCK_STREAM, NL_ROUTE) < 0 ? -errno : 0,
                   socket(NL_AF_NETLINK, SOCK_RAW, 40) < 0 ? -errno : 0);
            int fd = socket(NL_AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NL_ROUTE);
            struct nl_address name = {0};
            socklen_t name_len = sizeof name;
            getsockname(fd, (void *)&name, &name_len);
            printf("unbound: family=%u pid=%u groups=%u len=%u\n", name.family, name.pid, name.groups, name_len);
            struct nl_address any = {.family = NL_AF_NETLINK};
            long short_bind = netns_result(bind(fd, (void *)&any, sizeof any - 1));
            long bound = netns_result(bind(fd, (void *)&any, sizeof any));
            name_len = sizeof name;
            getsockname(fd, (void *)&name, &name_len);
            unsigned port = name.pid;
            int other = socket(NL_AF_NETLINK, SOCK_DGRAM, NL_ROUTE);
            struct nl_address taken = {.family = NL_AF_NETLINK, .pid = port};
            long in_use = netns_result(bind(other, (void *)&taken, sizeof taken));
            long other_bound = netns_result(bind(other, (void *)&any, sizeof any));
            struct nl_address other_name = {0};
            name_len = sizeof other_name;
            getsockname(other, (void *)&other_name, &name_len);
            int type = 0, domain = 0;
            socklen_t option_len = sizeof type;
            getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &option_len);
            option_len = sizeof domain;
            getsockopt(fd, SOL_SOCKET, SO_DOMAIN, &domain, &option_len);
            printf("bound: short=%ld bound=%ld own=%d in_use=%ld other=%ld negative=%d type=%d domain=%d\n",
                   short_bind, bound, port == (unsigned)getpid(), in_use, other_bound, (int)other_name.pid < 0, type,
                   domain);
            char index_name[IF_NAMESIZE] = "", unknown_name[IF_NAMESIZE] = "";
            const char *named = if_indextoname(1, index_name);
            errno = 0;
            const char *unnamed = if_indextoname(1000000, unknown_name);
            printf("index: lo=%u nope=%u name=%s other=%d errno=%d\n", if_nametoindex("lo"), if_nametoindex("nope"),
                   named ? named : "-", unnamed != NULL, errno);
            /* Down: the link alone, and no address. */
            unsigned char family = 0;
            nl_answer(fd, nl_send(fd, 18, NL_F_REQUEST | NL_F_DUMP, &family, 1), port, "down link");
            nl_answer(fd, nl_send(fd, 22, NL_F_REQUEST | NL_F_DUMP, &family, 1), port, "down addr");
            nl_getifaddrs("down ifaddrs");
            /* Errors and acknowledgements. */
            struct nl_link link = {.index = 1, .flags = IFF_UP, .change = IFF_UP};
            nl_answer(fd, nl_send(fd, 26, NL_F_REQUEST, &family, 1), port, "no route doit");
            struct nl_link nowhere = {.index = 1000000, .flags = IFF_UP, .change = IFF_UP};
            nl_answer(fd, nl_send(fd, 16, NL_F_REQUEST | NL_F_ACK, &nowhere, sizeof nowhere), port, "nowhere");
            nl_answer(fd, nl_send(fd, 18, NL_F_REQUEST, &family, 1), port, "short");
            nl_answer(fd, nl_send(fd, 16, NL_F_ACK, &link, sizeof link), port, "no request");
            /* Unprivileged, setting is EPERM and getting works. */
            fflush(stdout);
            pid_t user = child();
            if (user == 0) {
                if (setresgid(65534, 65534, 65534) || setresuid(65534, 65534, 65534)) _exit(90);
                int own = socket(NL_AF_NETLINK, SOCK_RAW, NL_ROUTE);
                struct nl_address mine = {0};
                socklen_t mine_len = sizeof mine;
                nl_send(own, 18, NL_F_REQUEST | NL_F_DUMP, &family, 1);
                getsockname(own, (void *)&mine, &mine_len);
                nl_answer(own, nl_seq, mine.pid, "user link");
                nl_answer(own, nl_send(own, 16, NL_F_REQUEST, &link, sizeof link), mine.pid, "user set");
                fflush(stdout);
                _exit(0);
            }
            result("user", reaped(user));
            /* Up, without an acknowledgement, then with one. */
            long up = nl_send(fd, 16, NL_F_REQUEST, &link, sizeof link);
            printf("up: answer=%ld\n", nl_answer(fd, up, port, "up"));
            nl_answer(fd, nl_send(fd, 16, NL_F_REQUEST | NL_F_ACK, &link, sizeof link), port, "up again");
            nl_answer(fd, nl_send(fd, 18, NL_F_REQUEST | NL_F_DUMP, &family, 1), port, "up link");
            nl_answer(fd, nl_send(fd, 22, NL_F_REQUEST | NL_F_DUMP, &family, 1), port, "up addr");
            unsigned char inet6 = AF_INET6;
            nl_answer(fd, nl_send(fd, 22, NL_F_REQUEST | NL_F_DUMP, &inet6, 1), port, "up addr6");
            char by_name[24] = {0};
            unsigned short attribute[2] = {7, 3};
            memcpy(by_name + 16, attribute, 4);
            memcpy(by_name + 20, "lo", 3);
            nl_answer(fd, nl_send(fd, 18, NL_F_REQUEST, by_name, 23), port, "by name");
            nl_getifaddrs("up ifaddrs");
            /* Down again: 127.0.0.1 stays, ::1 goes. */
            struct nl_link down = {.index = 1, .flags = 0, .change = IFF_UP};
            nl_answer(fd, nl_send(fd, 19, NL_F_REQUEST | NL_F_ACK, &down, sizeof down), port, "down again");
            nl_answer(fd, nl_send(fd, 18, NL_F_REQUEST | NL_F_DUMP, &family, 1), port, "down again link");
            nl_answer(fd, nl_send(fd, 22, NL_F_REQUEST | NL_F_DUMP, &family, 1), port, "down again addr");
            nl_getifaddrs("down again ifaddrs");
            fflush(stdout);
            _exit(0);
        }
        result("maker", reaped(maker));
        return 0;
    }
    if (!strcmp(mode, "net-namespaces")) {
        /* A child makes a network namespace, which has only a loopback,
           down and without addresses, and abstract socket names of its
           own; the first namespace's name stays out of its reach. */
        fflush(stdout);
        pid_t maker = child();
        if (maker == 0) {
            char before[64], after[64];
            ns_link("self", "net", before, sizeof before);
            int first_ns = ns_open("self", "net");
            struct sockaddr_un name = {.sun_family = AF_UNIX};
            memcpy(name.sun_path, "\0paludarium-netns", 17);
            socklen_t name_len = offsetof(struct sockaddr_un, sun_path) + 17;
            int first = socket(AF_UNIX, SOCK_STREAM, 0);
            long bound = netns_result(bind(first, (void *)&name, name_len));
            listen(first, 1);
            errno = 0;
            long made = syscall(SYS_unshare, CLONE_NEWNET);
            printf("maker: bound=%ld unshare=%ld errno=%d", bound, made, errno);
            ns_link("self", "net", after, sizeof after);
            printf(" changed=%d\n", strcmp(before, after) != 0);
            int unix_fd = socket(AF_UNIX, SOCK_STREAM, 0);
            long reached = netns_result(connect(unix_fd, (void *)&name, name_len));
            int own = socket(AF_UNIX, SOCK_STREAM, 0);
            long own_bound = netns_result(bind(own, (void *)&name, name_len));
            printf("abstract: reached=%ld bound=%ld\n", reached, own_bound);
            int tcp = socket(AF_INET, SOCK_STREAM, 0), udp = socket(AF_INET, SOCK_DGRAM, 0);
            printf("down: tcp=%d udp=%d flags=%ld index=%ld eth0=%ld\n", tcp >= 0, udp >= 0,
                   netns_lo(tcp, SIOCGIFFLAGS, "lo", 0), netns_lo(tcp, SIOCGIFINDEX, "lo", 0),
                   netns_lo(tcp, SIOCGIFFLAGS, "eth0", 0));
            struct sockaddr_in local = netns_v4("127.0.0.1", 0), closed = netns_v4("127.0.0.1", 1);
            struct sockaddr_in dns = netns_v4("8.8.8.8", 53), far = netns_v4("192.0.2.1", 80);
            long bind_down = netns_result(bind(udp, (void *)&local, sizeof local));
            long connect_down = netns_result(connect(tcp, (void *)&closed, sizeof closed));
            long send_down = netns_result(sendto(udp, "x", 1, 0, (void *)&closed, sizeof closed));
            long dns_down = netns_result(sendto(udp, "x", 1, 0, (void *)&dns, sizeof dns));
            printf("down: bind=%ld connect=%ld send=%ld dns=%ld\n", bind_down, connect_down, send_down,
                   dns_down);
            /* Up, the loopback has its addresses and works; nothing else
               is reachable. */
            long up = netns_lo(tcp, SIOCSIFFLAGS, "lo", IFF_UP);
            printf("up: set=%ld flags=%ld\n", up, netns_lo(udp, SIOCGIFFLAGS, "lo", 0));
            int receiver = socket(AF_INET, SOCK_DGRAM, 0), sender = socket(AF_INET, SOCK_DGRAM, 0);
            struct sockaddr_in at;
            socklen_t at_len = sizeof at;
            long udp_bound = netns_result(bind(receiver, (void *)&local, sizeof local));
            getsockname(receiver, (void *)&at, &at_len);
            long sent = netns_result(sendto(sender, "hi", 2, 0, (void *)&at, sizeof at));
            char buf[8];
            long got = netns_result(recv(receiver, buf, sizeof buf, MSG_DONTWAIT));
            printf("up: udp bound=%ld sent=%ld got=%ld\n", udp_bound, sent, got);
            int listener = socket(AF_INET, SOCK_STREAM, 0), client = socket(AF_INET, SOCK_STREAM, 0);
            at_len = sizeof at;
            long tcp_bound = netns_result(bind(listener, (void *)&local, sizeof local));
            listen(listener, 1);
            getsockname(listener, (void *)&at, &at_len);
            long connected = netns_result(connect(client, (void *)&at, sizeof at));
            int accepted = accept(listener, NULL, NULL);
            long written = netns_result(write(client, "x", 1));
            long read_back = accepted >= 0 ? netns_result(read(accepted, buf, sizeof buf)) : -1;
            printf("up: tcp bound=%ld connected=%ld accepted=%d moved=%ld,%ld\n", tcp_bound, connected,
                   accepted >= 0, written, read_back);
            int refused = socket(AF_INET, SOCK_STREAM, 0), outside = socket(AF_INET, SOCK_STREAM, 0);
            long closed_up = netns_result(connect(refused, (void *)&closed, sizeof closed));
            long far_up = netns_result(connect(outside, (void *)&far, sizeof far));
            long dns_up = netns_result(sendto(sender, "x", 1, 0, (void *)&dns, sizeof dns));
            printf("up: closed=%ld far=%ld dns=%ld\n", closed_up, far_up, dns_up);
            /* Back in the first namespace, its abstract name is reached
               again; a socket made in the other stays in that one. */
            long back = ns_setns(first_ns, CLONE_NEWNET);
            int again = socket(AF_UNIX, SOCK_STREAM, 0);
            long reached_again = netns_result(connect(again, (void *)&name, name_len));
            printf("back: setns=%ld reached=%ld flags=%ld\n", back, reached_again,
                   netns_lo(udp, SIOCGIFFLAGS, "lo", 0));
            /* Without CAP_NET_ADMIN, setting flags is EPERM, whatever the
               name. */
            fflush(stdout);
            pid_t user = child();
            if (user == 0) {
                if (setresgid(65534, 65534, 65534) || setresuid(65534, 65534, 65534)) _exit(90);
                printf("user: lo=%ld nope=%ld get=%ld\n", netns_lo(udp, SIOCSIFFLAGS, "lo", 0),
                       netns_lo(udp, SIOCSIFFLAGS, "nope", 0), netns_lo(udp, SIOCGIFFLAGS, "lo", 0));
                fflush(stdout);
                _exit(0);
            }
            result("user", reaped(user));
            fflush(stdout);
            _exit(0);
        }
        result("maker", reaped(maker));
        return 0;
    }
    if (!strcmp(mode, "pid-set-tid")) {
        /* clone3's set_tid (the native side runs as root), and the NS*
           lines of /proc/<pid>/status, which number a task in /proc's PID
           namespace and each one below it down to its own. */
        const unsigned long long thread = CLONE_VM | CLONE_THREAD | CLONE_SIGHAND;
        settid_lines("first");
        pid_t tids[3] = {1, 1, 1};
        result("too-many", settid_error(0, SIGCHLD, tids, 2));
        tids[0] = 0;
        result("zero", settid_error(0, SIGCHLD, tids, 1));
        tids[0] = 4194304;
        result("pid-max", settid_error(0, SIGCHLD, tids, 1));
        tids[0] = 1;
        result("taken-init", settid_error(0, SIGCHLD, tids, 1));
        tids[0] = getpid();
        result("taken-self", settid_error(0, SIGCHLD, tids, 1));
        result("thread-taken", settid_error(thread, 0, tids, 1));
        result("fault", settid_error(0, SIGCHLD, (const pid_t *)1, 1));
        result("too-many-at-most", settid_error(0, SIGCHLD, tids, 33));
        /* An ID no task has: natively the first free one of a few far
           ahead, which another process may have taken. */
        long taken = -EEXIST;
        pid_t wanted = 0;
        for (int i = 0; i < 16 && taken == -EEXIST; i++) {
            wanted = getpid() + 100000 + i * 7919;
            tids[0] = wanted;
            taken = settid_clone(0, SIGCHLD, tids, 1);
            if (taken == 0) _exit(getpid() == wanted ? 0 : 1);
        }
        printf("first: taken=%d status=%d\n", taken == wanted, taken > 0 ? reaped(taken) : -1);
        /* Without the capability over the first namespace. */
        pid_t nobody = child();
        if (nobody == 0) {
            if (setresuid(65534, 65534, 65534)) _exit(90);
            tids[0] = getpid() + 100000;
            result("unprivileged", settid_error(0, SIGCHLD, tids, 1));
            fflush(stdout);
            _exit(0);
        }
        result("nobody", reaped(nobody));
        /* A new PID namespace: its first task must be 1. */
        tids[0] = 2;
        result("new-not-init", settid_error(CLONE_NEWPID, SIGCHLD, tids, 1));
        tids[0] = 1;
        result("new-outer-taken", settid_error(CLONE_NEWPID, SIGCHLD, tids, 2));
        result("new-too-many", settid_error(CLONE_NEWPID, SIGCHLD, tids, 3));
        long init = settid_clone(CLONE_NEWPID, SIGCHLD, tids, 1);
        if (init == 0) {
            long numbers[4];
            printf("init: pid=%d\n", getpid());
            settid_lines("init");
            int count = settid_numbers("NSpid", numbers);
            pid_t outer = count == 2 ? numbers[0] : 0;
            pid_t inner[3] = {1, outer, 1};
            result("init-taken", settid_error(0, SIGCHLD, inner, 1));
            inner[0] = 3;
            result("init-outer-taken", settid_error(0, SIGCHLD, inner, 2));
            result("init-too-many", settid_error(0, SIGCHLD, inner, 3));
            inner[0] = 1;
            result("init-thread-taken", settid_error(thread, 0, inner, 1));
            /* 5 here, then the next one takes 2, the first after the last
               handed out that is free. */
            inner[0] = 5;
            long five = settid_clone(0, SIGCHLD, inner, 1);
            if (five == 0) {
                count = settid_numbers("NSpid", numbers);
                _exit(getpid() == 5 && count == 2 && numbers[1] == 5 ? 0 : 1);
            }
            printf("init: five=%ld status=%d\n", five, five > 0 ? reaped(five) : -1);
            fflush(stdout);
            pid_t next = child();
            if (next == 0) _exit(0);
            printf("init: next=%d status=%d\n", next, reaped(next));
            /* Two levels: 1 in a namespace of its own, 7 here. */
            pid_t two[2] = {1, 7};
            long nested = settid_clone(CLONE_NEWPID, SIGCHLD, two, 2);
            if (nested == 0) {
                count = settid_numbers("NSpid", numbers);
                _exit(getpid() == 1 && count == 3 && numbers[1] == 7 && numbers[2] == 1 ? 0 : 1);
            }
            printf("init: nested=%ld status=%d\n", nested, nested > 0 ? reaped(nested) : -1);
            /* In a user namespace of its own: the new PID namespace is its
               own, this one is not. */
            fflush(stdout);
            pid_t user = child();
            if (user == 0) {
                if (syscall(SYS_unshare, CLONE_NEWUSER)) _exit(90);
                pid_t own[2] = {1, 9};
                result("user-outer", settid_error(CLONE_NEWPID, SIGCHLD, own, 2));
                long made = settid_clone(CLONE_NEWPID, SIGCHLD, own, 1);
                if (made == 0) _exit(getpid() == 1 ? 0 : 1);
                printf("user: made=%d status=%d\n", made > 0, made > 0 ? reaped(made) : -1);
                fflush(stdout);
                _exit(0);
            }
            result("user", reaped(user));
            fflush(stdout);
            _exit(0);
        }
        result("init", reaped(init));
        return 0;
    }
    if (!strcmp(mode, "pid-namespaces")) {
        /* clone with CLONE_NEWPID: the child is the init of a new
           namespace, its parent outside it. */
        fflush(stdout);
        long cloned = syscall(SYS_clone, CLONE_NEWPID | SIGCHLD, 0, 0, 0, 0);
        if (cloned == 0) {
            printf("cloned: pid=%d ppid=%d\n", getpid(), getppid());
            fflush(stdout);
            _exit(0);
        }
        result("cloned", reaped(cloned));
        /* A child makes one for its children, which has no process, nor a
           link, until the first of them, its init. */
        fflush(stdout);
        pid_t maker = child();
        if (maker == 0) {
            char buf[64];
            int outer = ns_open("self", "pid");
            errno = 0;
            long made = syscall(SYS_unshare, CLONE_NEWPID);
            printf("maker: unshare=%ld errno=%d", made, errno);
            errno = 0;
            ns_link("self", "pid_for_children", buf, sizeof buf);
            printf(" link=%d errno=%d", buf[0] != 0, errno);
            errno = 0;
            long again = syscall(SYS_unshare, CLONE_NEWPID);
            printf(" again=%ld errno=%d", again, errno);
            errno = 0;
            long nested = syscall(SYS_clone, CLONE_NEWPID | SIGCHLD, 0, 0, 0, 0);
            if (nested == 0) _exit(99);
            printf(" clone=%ld errno=%d", nested, errno);
            /* A thread would be numbered outside its process's namespace. */
            ns_spin_go = 1;
            pthread_t thread;
            int threaded = pthread_create(&thread, NULL, ns_spinner, NULL);
            if (!threaded) pthread_join(thread, NULL);
            printf(" thread=%d\n", threaded);
            int go[2], done[2];
            if (pipe(go) || pipe(done)) _exit(90);
            fflush(stdout);
            pid_t init = child();
            if (init == 0) {
                close(go[1]);
                close(done[0]);
                _exit(pidns_init(outer, go[0], done[1]));
            }
            close(go[0]);
            close(done[1]);
            char byte, who[16];
            if (read(done[0], &byte, 1) != 1) _exit(91);
            snprintf(who, sizeof who, "%d", init);
            printf("maker: same=%d own=%d\n", ns_same("self", "pid_for_children", who, "pid"),
                   ns_same("self", "pid", "self", "pid_for_children"));
            fflush(stdout);
            kill(init, SIGTERM);
            kill(init, SIGUSR1);
            if (write(go[1], "x", 1) != 1) _exit(92);
            /* Its init has exited: no process may join it any more. */
            int status = 0;
            pid_t waited = waitpid(init, &status, 0);
            printf("maker: init-waited=%d status=%d\n", waited == init,
                   WIFEXITED(status) ? WEXITSTATUS(status) : -1);
            errno = 0;
            pid_t late = child();
            if (late == 0) _exit(98);
            printf("maker: late=%d errno=%d\n", late, errno);
            fflush(stdout);
            _exit(0);
        }
        result("maker", reaped(maker));
        return 0;
    }
    if (!strcmp(mode, "namespaces")) {
        /* The links of /proc/self/ns, in Linux's order, each naming a
           namespace of its kind; the ones for children are the thread's own
           until it unshares. */
        DIR *dir = opendir("/proc/self/ns");
        printf("listing:");
        for (struct dirent *entry; dir && (entry = readdir(dir));) printf(" %s/%d", entry->d_name, entry->d_type);
        printf("\n");
        if (dir) closedir(dir);
        char buf[64];
        for (int i = 0; i < 10; i++) {
            const char *kind = ns_kinds[i];
            const char *name = !strcmp(kind, "pid_for_children") ? "pid"
                               : !strcmp(kind, "time_for_children") ? "time" : kind;
            printf("%s: named=%d\n", kind, ns_named(ns_link("self", kind, buf, sizeof buf), name));
        }
        printf("for-children: pid=%d time=%d\n", ns_same("self", "pid", "self", "pid_for_children"),
               ns_same("self", "time", "self", "time_for_children"));
        /* The link and the namespace's file it leads to, whose inode is the
           number in the link. */
        struct stat link, file;
        int listed = lstat("/proc/self/ns/uts", &link), stated = stat("/proc/self/ns/uts", &file);
        unsigned long number = 0;
        sscanf(ns_link("self", "uts", buf, sizeof buf), "uts:[%lu]", &number);
        printf("lstat=%d mode=%o stat=%d mode=%o links=%lu size=%ld inode=%d\n", listed, link.st_mode, stated,
               file.st_mode, (unsigned long)file.st_nlink, (long)file.st_size, file.st_ino == number);
        errno = 0;
        printf("missing=%d errno=%d\n", lstat("/proc/self/ns/nothing", &link), errno);
        /* An open namespace file is a handle: reading is EINVAL, seeking
           ESPIPE, and its descriptor's link names the namespace. */
        int fd = ns_open("self", "uts");
        char byte;
        errno = 0;
        long got = read(fd, &byte, 1);
        printf("read=%ld errno=%d", got, errno);
        errno = 0;
        got = lseek(fd, 0, SEEK_SET);
        printf(" lseek=%ld errno=%d", got, errno);
        struct stat held;
        fstat(fd, &held);
        char fd_path[64], fd_link[64];
        snprintf(fd_path, sizeof fd_path, "/proc/self/fd/%d", fd);
        ssize_t n = readlink(fd_path, fd_link, sizeof fd_link - 1);
        fd_link[n < 0 ? 0 : n] = 0;
        printf(" fstat-inode=%d fd-link=%d\n", held.st_ino == file.st_ino, !strcmp(fd_link, buf));
        close(fd);
        errno = 0;
        printf("o-directory=%d errno=%d\n", open("/proc/self/ns/uts", O_RDONLY | O_DIRECTORY), errno);
        /* sethostname and setdomainname: CAP_SYS_ADMIN, then at most 64
           bytes; a negative length is EINVAL too. All of it in a new UTS
           namespace, which the parent does not see. */
        uname(&ns_before);
        char before_uts[64];
        ns_link("self", "uts", before_uts, sizeof before_uts);
        int ready[2], go[2];
        if (pipe(ready) || pipe(go)) return 90;
        fflush(stdout);
        pid_t first = child();
        if (first == 0) {
            char was[10][64];
            for (int i = 0; i < 10; i++) ns_link("self", ns_kinds[i], was[i], sizeof was[i]);
            errno = 0;
            long r = syscall(SYS_unshare, CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWNS | CLONE_NEWCGROUP | NS_NEWTIME);
            printf("first: unshare=%ld errno=%d changed:", r, errno);
            for (int i = 0; i < 10; i++) {
                char now[64];
                printf(" %s=%d", ns_kinds[i], strcmp(was[i], ns_link("self", ns_kinds[i], now, sizeof now)) != 0);
            }
            printf("\n");
            long host_set = syscall(SYS_sethostname, "first-host", 10);
            long domain_set = syscall(SYS_setdomainname, "first.example", 13);
            printf("first: sethostname=%ld setdomainname=%ld\n", host_set, domain_set);
            ns_names("first");
            struct utsname set;
            uname(&set);
            printf("first: domainname=%s\n", set.domainname);
            char long_name[66];
            memset(long_name, 'a', sizeof long_name);
            errno = 0;
            r = syscall(SYS_sethostname, long_name, 65);
            printf("first: long=%ld errno=%d", r, errno);
            errno = 0;
            r = syscall(SYS_sethostname, long_name, 64);
            printf(" full=%ld", r);
            errno = 0;
            r = syscall(SYS_setdomainname, long_name, -1);
            printf(" negative=%ld errno=%d", r, errno);
            errno = 0;
            r = syscall(SYS_sethostname, (void *)1, 4);
            printf(" fault=%ld errno=%d\n", r, errno);
            struct utsname full;
            uname(&full);
            printf("first: full-length=%zu\n", strlen(full.nodename));
            syscall(SYS_sethostname, "first-host", 10);
            /* A fork is in the time namespace for children, which the
               process itself is not. */
            fflush(stdout);
            pid_t grandchild = child();
            if (grandchild == 0) {
                printf("grandchild: time=%d\n", ns_same("self", "time", "self", "time_for_children"));
                ns_names("grandchild");
                fflush(stdout);
                _exit(0);
            }
            result("grandchild", reaped(grandchild));
            printf("first: time=%d\n", ns_same("self", "time", "self", "time_for_children"));
            fflush(stdout);
            close(ready[0]);
            close(go[1]);
            if (write(ready[1], "r", 1) != 1) _exit(91);
            if (read(go[0], &byte, 1) != 1) _exit(92);
            _exit(0);
        }
        char who[16];
        snprintf(who, sizeof who, "%d", first);
        close(ready[1]);
        close(go[0]);
        if (read(ready[0], &byte, 1) != 1) return 93;
        ns_kept("parent");
        printf("parent: uts-kept=%d\n", !strcmp(ns_link("self", "uts", buf, sizeof buf), before_uts));
        /* setns with a namespace file: its kind or 0; another is EINVAL. */
        fflush(stdout);
        pid_t joiner = child();
        if (joiner == 0) {
            int uts = ns_open(who, "uts"), mnt = ns_open(who, "mnt"), time = ns_open(who, "time_for_children");
            long wrong = ns_setns(uts, CLONE_NEWIPC);
            long right = ns_setns(uts, CLONE_NEWUTS);
            printf("joiner: opened=%d wrong=%ld right=%ld", uts >= 0 && mnt >= 0 && time >= 0, wrong, right);
            printf(" same-uts=%d\n", ns_same("self", "uts", who, "uts"));
            ns_names("joiner");
            struct utsname joined;
            uname(&joined);
            printf("joiner: domainname=%s\n", joined.domainname);
            /* Away from the root, to the program's own directory, which
               both sides have. */
            char home[256];
            snprintf(home, sizeof home, "%s", self);
            char *slash = strrchr(home, '/');
            if (!slash || slash == home) _exit(94);
            *slash = 0;
            if (chdir(home)) _exit(94);
            printf("joiner: mnt=%ld", ns_setns(mnt, 0));
            char cwd[64];
            printf(" cwd=%s same-mnt=%d", getcwd(cwd, sizeof cwd) ? cwd : "?", ns_same("self", "mnt", who, "mnt"));
            long entered = ns_setns(time, 0);
            printf(" time=%ld same-time=%d", entered, ns_same("self", "time", who, "time_for_children"));
            printf(" children=%d\n", ns_same("self", "time_for_children", who, "time_for_children"));
            int regular = open("/proc/self/stat", O_RDONLY);
            printf("joiner: regular=%ld badf=%ld\n", ns_setns(regular, 0), ns_setns(-1, 0));
            fflush(stdout);
            _exit(0);
        }
        result("joiner", reaped(joiner));
        /* setns with a pidfd and the namespaces to enter. */
        fflush(stdout);
        pid_t follower = child();
        if (follower == 0) {
            int pidfd = syscall(SYS_pidfd_open, first, 0);
            long none = ns_setns(pidfd, 0), unknown = ns_setns(pidfd, CLONE_VM);
            long user_too = ns_setns(pidfd, CLONE_NEWUSER | CLONE_NEWUTS);
            printf("follower: none=%ld unknown=%ld user=%ld", none, unknown, user_too);
            printf(" same-uts=%d", ns_same("self", "uts", who, "uts"));
            long all = CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWNS | CLONE_NEWCGROUP | CLONE_NEWNET | CLONE_NEWPID |
                       NS_NEWTIME;
            printf(" all=%ld\n", ns_setns(pidfd, all));
            printf("follower: same:");
            for (int i = 0; i < 10; i++) printf(" %s=%d", ns_kinds[i], ns_same("self", ns_kinds[i], who, ns_kinds[i]));
            printf("\n");
            ns_names("follower");
            fflush(stdout);
            _exit(0);
        }
        result("follower", reaped(follower));
        /* A time namespace needs the thread alone (EUSERS); a mount
           namespace a working directory it alone has, unless more than the
           mount namespace is entered. */
        fflush(stdout);
        pid_t threaded = child();
        if (threaded == 0) {
            int time = ns_open(who, "time_for_children"), mnt = ns_open(who, "mnt");
            int pidfd = syscall(SYS_pidfd_open, first, 0);
            pthread_t thread;
            pthread_create(&thread, NULL, ns_spinner, NULL);
            long timed_in = ns_setns(time, 0), mnt_in = ns_setns(mnt, 0);
            long more = ns_setns(pidfd, CLONE_NEWNS | CLONE_NEWUTS);
            printf("threaded: time=%ld mnt=%ld more=%ld", timed_in, mnt_in, more);
            printf(" same-mnt=%d\n", ns_same("self", "mnt", who, "mnt"));
            __atomic_store_n(&ns_spin_go, 1, __ATOMIC_SEQ_CST);
            pthread_join(thread, NULL);
            fflush(stdout);
            _exit(0);
        }
        result("threaded", reaped(threaded));
        /* Without CAP_SYS_ADMIN, EPERM; another user's links are EACCES. */
        fflush(stdout);
        pid_t user = child();
        if (user == 0) {
            int uts = ns_open(who, "uts");
            if (setresgid(65534, 65534, 65534) || setresuid(65534, 65534, 65534)) _exit(95);
            errno = 0;
            int other = ns_open(who, "ipc");
            int opened_errno = errno;
            long refused_setns = ns_setns(uts, 0);
            printf("user: setns=%ld open=%d errno=%d", refused_setns, other, opened_errno);
            char path[64];
            snprintf(path, sizeof path, "/proc/%s/ns/uts", who);
            errno = 0;
            n = readlink(path, buf, sizeof buf);
            printf(" readlink=%ld errno=%d", (long)n, errno);
            errno = 0;
            long r = syscall(SYS_sethostname, "x", 1);
            printf(" sethostname=%ld errno=%d\n", r, errno);
            fflush(stdout);
            _exit(0);
        }
        result("user", reaped(user));
        if (write(go[1], "g", 1) != 1) return 96;
        result("first", reaped(first));
        /* clone with namespace flags: a child in a new UTS namespace; a new
           mount namespace with CLONE_FS, or an IPC one with CLONE_SYSVSEM,
           is EINVAL. */
        char *stack = mmap(NULL, 65536, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        fflush(stdout);
        pid_t cloned = clone(ns_uts_child, stack + 65536, CLONE_NEWUTS | SIGCHLD, NULL);
        result("cloned", reaped(cloned));
        ns_kept("after-clone");
        long refused[] = {CLONE_NEWNS | CLONE_FS, CLONE_NEWIPC | CLONE_SYSVSEM};
        for (int i = 0; i < 2; i++) {
            errno = 0;
            pid_t r = clone(ns_exit_child, stack + 65536, refused[i] | SIGCHLD, NULL);
            printf("refused %#lx: %d errno=%d\n", refused[i], r < 0 ? -1 : 0, errno);
            if (r > 0) reaped(r);
        }
        /* clone3's CLONE_NEWTIME: the child is in the new time namespace,
           which is its children's too, and its exit signal is SIGCHLD. */
        uint64_t args[11] = {NS_NEWTIME, 0, 0, 0, SIGCHLD};
        char parent[16];
        snprintf(parent, sizeof parent, "%d", getpid());
        fflush(stdout);
        long timed = syscall(NS_SYS_CLONE3, args, 88);
        if (timed == 0) {
            printf("clone3-child: own=%d new=%d\n", ns_same("self", "time", "self", "time_for_children"),
                   !ns_same("self", "time", parent, "time") && ns_named(ns_link("self", "time", buf, sizeof buf), "time"));
            fflush(stdout);
            _exit(0);
        }
        int status;
        printf("clone3: waited=%d\n", timed > 0 && waitpid(timed, &status, 0) == timed && status == 0);
        /* A thread with a new UTS namespace of its own, which /proc/self
           (the leader's) does not show but /proc/thread-self does. */
        fflush(stdout);
        pid_t host = child();
        if (host == 0) {
            int tid = clone(ns_thread, stack + 65536,
                            CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD | CLONE_SYSVSEM | CLONE_NEWUTS,
                            NULL);
            while (tid > 0 && !ns_thread_done) sched_yield();
            printf("thread: cloned=%d set=%ld name=%s own=%d leader=%d\n", tid > 0, ns_thread_set, ns_thread_name,
                   ns_named(ns_thread_link, "uts") && strcmp(ns_thread_link, ns_link("self", "uts", buf, sizeof buf)),
                   !strcmp(ns_link("self", "uts", buf, sizeof buf), before_uts));
            ns_kept("thread-leader");
            fflush(stdout);
            _exit(0);
        }
        result("host", reaped(host));
        ns_kept("end");
        return 0;
    }
    if (!strcmp(mode, "uname")) {
        struct utsname names;
        result("uname", uname(&names));
        result("sysname", !strcmp(names.sysname, "Linux"));
        result("machine", !strcmp(names.machine, "x86_64"));
        result("nodename", names.nodename[0] != 0);
        result("release", names.release[0] >= '0' && names.release[0] <= '9');
        errno = 0;
        result("fault", syscall(SYS_uname, (void *)1));
        result("errno", errno);
        return 0;
    }
    if (!strcmp(mode, "mempolicy")) {
        /* NUMA memory policies on a machine with one node, node 0, which the
           emulator shows and the CI runners have. Modes: 0 default, 1
           preferred, 2 bind, 3 interleave, 4 local, 5 preferred-many, 6
           weighted interleave; flags 0x8000 static, 0x4000 relative, 0x2000
           NUMA balancing. */
        policy("default", 65, NULL, 0);
        policy("default-129", 129, NULL, 0);
        policy("default-1", 1, NULL, 0);
        policy("maxnode-0", 0, NULL, 0);
        policy("mems-allowed", 65, NULL, 4);
        policy("mems-and-node", 65, NULL, 5);
        policy("unknown-flag", 65, NULL, 8);
        policy("addr-without-flag", 65, (void *)4096, 0);
        policy("node-of-default", 65, NULL, 1);
        errno = 0;
        outcome("mode-fault", syscall(SYS_get_mempolicy, (void *)1, NULL, 0, NULL, 0));
        outcome("mask-fault", syscall(SYS_get_mempolicy, NULL, (void *)1, 65, NULL, 0));
        outcome("mask-too-big", syscall(SYS_get_mempolicy, NULL, (void *)1, 4096 * 8 + 2, NULL, 0));

        set_policy("bind-0", 2, 1, 65);
        policy("bind-0-get", 65, NULL, 0);
        set_policy("bind-01", 2, 3, 65);
        policy("bind-01-get", 65, NULL, 0);
        set_policy("bind-1", 2, 2, 65);
        policy("after-bind-1", 65, NULL, 0);
        set_policy("bind-empty", 2, 0, 65);
        set_policy("bind-maxnode-1", 2, 1, 1);
        set_policy("interleave", 3, 1, 65);
        policy("interleave-node", 65, NULL, 1);
        set_policy("weighted", 6, 1, 65);
        policy("weighted-get", 65, NULL, 0);
        policy("weighted-node", 65, NULL, 1);
        set_policy("preferred-empty", 1, 0, 65);
        policy("preferred-empty-get", 65, NULL, 0);
        set_policy("preferred-01", 1, 3, 65);
        policy("preferred-01-get", 65, NULL, 0);
        set_policy("preferred-many", 5, 1, 65);
        policy("preferred-many-get", 65, NULL, 0);
        set_policy("local", 4, 0, 65);
        policy("local-get", 65, NULL, 0);
        set_policy("local-nodes", 4, 1, 65);
        set_policy("default-nodes", 0, 1, 65);
        set_policy("mode-7", 7, 1, 65);
        set_policy("static", 2 | 0x8000, 3, 65);
        policy("static-get", 65, NULL, 0);
        set_policy("relative", 3 | 0x4000, 4, 65);
        policy("relative-get", 65, NULL, 0);
        set_policy("static-relative", 2 | 0xc000, 1, 65);
        set_policy("preferred-static-empty", 1 | 0x8000, 0, 65);
        set_policy("balancing", 2 | 0x2000, 1, 65);
        policy("balancing-get", 65, NULL, 0);
        set_policy("balancing-interleave", 3 | 0x2000, 1, 65);
        {
            /* Bits up to MAX_NUMNODES (1024) beyond the nodes are dropped;
               one past it is EINVAL. */
            unsigned long mask[32] = {1};
            mask[15] = 1UL << 63;
            outcome("bit-1023", syscall(SYS_set_mempolicy, 2, mask, 1025));
            mask[15] = 0;
            mask[16] = 1;
            outcome("bit-1024", syscall(SYS_set_mempolicy, 2, mask, 2000));
            outcome("too-long", syscall(SYS_set_mempolicy, 2, mask, 4096 * 8 + 2));
            outcome("nodes-fault", syscall(SYS_set_mempolicy, 2, (void *)1, 65));
            outcome("null-nodes", syscall(SYS_set_mempolicy, 2, NULL, 65));
        }

        /* A thread starts with its creator's policy, and a new process with
           the forking thread's. */
        set_policy("interleave-again", 3, 1, 65);
        pthread_t thread;
        pthread_create(&thread, NULL, policy_thread, NULL);
        pthread_join(thread, NULL);
        policy("main-after-thread", 65, NULL, 0);
        fflush(stdout);
        pid_t pid = child();
        if (pid == 0) {
            policy("child-inherits", 65, NULL, 0);
            fflush(stdout);
            _exit(0);
        }
        waitpid(pid, NULL, 0);
        set_policy("back-to-default", 0, 0, 65);
        policy("default-again", 65, NULL, 0);

        /* mbind: a policy for the pages of a range, which F_ADDR reports. */
        char *map = mmap(NULL, 4 * 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        unsigned long one[2] = {1};
#define MBIND(a, l, m, n, f) syscall(SYS_mbind, (a), (l), (m), (n), 65, (f))
        outcome("mbind", MBIND(map, 2 * 4096, 2, one, 0));
        policy("addr-bound", 65, map + 4096 + 7, 2);
        policy("addr-after", 65, map + 2 * 4096, 2);
        policy("addr-node", 65, map, 3);
        policy("task-unchanged", 65, NULL, 0);
        outcome("mbind-unaligned", MBIND(map + 1, 4096, 2, one, 0));
        outcome("mbind-zero", MBIND(map, 0, 2, one, 0));
        outcome("mbind-zero-bad-mode", MBIND(map, 0, 7, one, 0));
        outcome("mbind-empty", MBIND(map, 4096, 2, NULL, 0));
        outcome("mbind-flag", MBIND(map, 4096, 2, one, 8));
        outcome("mbind-strict", MBIND(map + 3 * 4096, 4096, 3, one, 1));
        outcome("mbind-move", MBIND(map + 3 * 4096, 4096, 3, one, 2));
        policy("addr-interleave", 65, map + 3 * 4096, 2);
        outcome("mbind-default-part", MBIND(map + 4096, 4096, 0, NULL, 0));
        policy("addr-split-low", 65, map, 2);
        policy("addr-split-high", 65, map + 4096, 2);
        munmap(map + 2 * 4096, 4096);
        policy("addr-unmapped", 65, map + 2 * 4096, 2);
        outcome("mbind-hole", MBIND(map, 4 * 4096, 2, one, 0));
        outcome("mbind-hole-default", MBIND(map, 4 * 4096, 0, NULL, 0));
        policy("hole-default-low", 65, map, 2);
        outcome("mbind-all-hole", MBIND(map + 2 * 4096, 4096, 0, NULL, 0));
        /* A new mapping over a range has no policy; a moved one keeps it. */
        outcome("mbind-again", MBIND(map, 4096, 2, one, 0));
        fflush(stdout);
        pid = child();
        if (pid == 0) {
            policy("child-range", 65, map, 2);
            fflush(stdout);
            _exit(0);
        }
        waitpid(pid, NULL, 0);
        char *moved = mmap(NULL, 2 * 4096, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        policy("addr-none-node", 65, moved, 3);
        munmap(moved, 2 * 4096);
        char *to = mremap(map, 4096, 4096, MREMAP_MAYMOVE | MREMAP_FIXED, moved);
        result("moved", to == moved);
        policy("moved-policy", 65, moved, 2);
        policy("moved-from", 65, map, 2);
        char *fresh = mmap(moved, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
        result("fresh", fresh == moved);
        policy("fresh-policy", 65, moved, 2);
        /* The heap: a brk that maps or unmaps no page keeps the policy of
           the page that holds an unaligned break. */
        char *heap = (char *)syscall(SYS_brk, 0);
        char *top = heap + 2 * 4096 + 100;
        result("grown", (char *)syscall(SYS_brk, top) == top);
        char *last = (char *)((unsigned long)(top - 1) & ~4095UL);
        outcome("mbind-heap", MBIND(last, 4096, 2, one, 0));
        syscall(SYS_brk, 0);
        result("same-page", (char *)syscall(SYS_brk, top + 50) == top + 50);
        policy("heap-kept", 65, last, 2);
        result("shrunk", (char *)syscall(SYS_brk, last) == last);
        policy("heap-gone", 65, last, 2);
        result("regrown", (char *)syscall(SYS_brk, top) == top);
        policy("heap-new", 65, last, 2);
#undef MBIND
        return 0;
    }
    if (!strcmp(mode, "landlock")) {
        /* A directory with a and b inside, each with a file f; c in a. */
        char top[64], a[80], b[80], af[96], bf[96], ac[96], tmp[128];
        snprintf(top, sizeof top, "/tmp/paludarium-landlock-%d", getpid());
        snprintf(a, sizeof a, "%s/a", top);
        snprintf(b, sizeof b, "%s/b", top);
        snprintf(af, sizeof af, "%s/f", a);
        snprintf(bf, sizeof bf, "%s/f", b);
        snprintf(ac, sizeof ac, "%s/c", a);
        mkdir(top, 0755);
        mkdir(a, 0755);
        mkdir(b, 0755);
        close(open(af, O_CREAT | O_WRONLY, 0644));
        close(open(bf, O_CREAT | O_WRONLY, 0644));
        mkdir(ac, 0755);

        long abi = syscall(444, NULL, 0, 1);
        result("abi-at-least-3", abi >= 3);
        result("abi-at-least-5", abi >= 5);
        result("abi-at-least-8", abi >= 8);
        /* Errata 1 to 4, which the runner's kernel has. */
        long errata = syscall(444, NULL, 0, 2);
        result("errata-1-to-4", errata >= 0 && (errata & 15) == 15);
        errno = 0;
        unsigned long long big[8] = {LL_READ_FILE};
        result("version-with-attr", ll_call(syscall(444, big, 8, 1)));
        result("unknown-flag", ll_call(syscall(444, NULL, 0, 4)));
        result("null-attr", ll_call(syscall(444, NULL, 8, 0)));
        result("short-attr", ll_call(syscall(444, big, 4, 0)));
        result("huge-attr", ll_call(syscall(444, big, 4097, 0)));
        big[5] = 1;
        result("nonzero-tail", ll_call(syscall(444, big, sizeof big, 0)));
        big[5] = 0;
        long zeros = syscall(444, big, sizeof big, 0);
        result("zero-tail", zeros >= 0);
        close(zeros);
        unsigned long long none = 0, unknown = 1ULL << 40;
        result("nothing-handled", ll_call(syscall(444, &none, 8, 0)));
        result("unknown-right", ll_call(syscall(444, &unknown, 8, 0)));
        long rs = ll_ruleset(LL_READ_FILE | LL_MAKE_REG);
        result("ruleset", rs >= 0);
        result("cloexec", fcntl(rs, F_GETFD) & FD_CLOEXEC);
        char target[64] = {0};
        snprintf(tmp, sizeof tmp, "/proc/self/fd/%ld", rs);
        readlink(tmp, target, sizeof target - 1);
        printf("link=%s\n", target);
        char byte;
        result("read", ll_call(read(rs, &byte, 1)));
        struct ll_path_beneath rule = {LL_READ_FILE, open(a, O_PATH)};
        result("rule-flags", ll_call(syscall(445, rs, 1, &rule, 1)));
        result("rule-bad-fd", ll_call(syscall(445, 9999, 1, &rule, 0)));
        int ev = eventfd(0, 0);
        result("rule-not-ruleset", ll_call(syscall(445, ev, 1, &rule, 0)));
        result("rule-type", ll_call(syscall(445, rs, 3, &rule, 0)));
        result("rule-null", ll_call(syscall(445, rs, 1, NULL, 0)));
        rule.allowed = 0;
        result("rule-empty", ll_call(syscall(445, rs, 1, &rule, 0)));
        rule.allowed = LL_WRITE_FILE;
        result("rule-unhandled", ll_call(syscall(445, rs, 1, &rule, 0)));
        rule.allowed = LL_READ_FILE;
        int parent = rule.parent_fd;
        rule.parent_fd = -1;
        result("rule-parent-bad", ll_call(syscall(445, rs, 1, &rule, 0)));
        rule.parent_fd = ev;
        result("rule-parent-eventfd", ll_call(syscall(445, rs, 1, &rule, 0)));
        rule.parent_fd = open(af, O_PATH);
        rule.allowed = LL_MAKE_REG;
        result("rule-file-make", ll_call(syscall(445, rs, 1, &rule, 0)));
        rule.allowed = LL_READ_FILE;
        result("rule-file-read", ll_call(syscall(445, rs, 1, &rule, 0)));
        close(rule.parent_fd);
        rule.parent_fd = parent;
        result("rule-dir", ll_call(syscall(445, rs, 1, &rule, 0)));
        close(parent);
        /* The native side runs unprivileged, which no_new_privs lets
           restrict itself; the flags and the descriptor come after. */
        prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
        result("restrict-flags", ll_call(syscall(446, rs, 1 << 10)));
        result("restrict-not-ruleset", ll_call(syscall(446, ev, 0)));
        close(ev);
        close(rs);
        fflush(stdout);

        /* Reading and writing: a allows both, b nothing; one layer. */
        pid_t pid = child();
        if (pid == 0) {
            int before = open(bf, O_WRONLY);
            long r = ll_ruleset(LL_READ_FILE | LL_WRITE_FILE | LL_READ_DIR | LL_TRUNCATE);
            ll_rule(r, a, LL_READ_FILE | LL_WRITE_FILE | LL_READ_DIR | LL_TRUNCATE);
            result("enforce", ll_call(ll_enforce(r)));
            result("read-a", ll_open(af, O_RDONLY));
            result("write-a", ll_open(af, O_WRONLY));
            result("read-b", ll_open(bf, O_RDONLY));
            result("write-b", ll_open(bf, O_WRONLY));
            result("dir-a", ll_open(a, O_RDONLY | O_DIRECTORY));
            result("dir-b", ll_open(b, O_RDONLY | O_DIRECTORY));
            result("path-b", ll_open(bf, O_PATH));
            struct stat st;
            result("stat-b", ll_call(stat(bf, &st)));
            result("trunc-open-a", ll_open(af, O_WRONLY | O_TRUNC));
            result("truncate-a", ll_call(truncate(af, 0)));
            result("truncate-b", ll_call(truncate(bf, 0)));
            result("ftruncate-before", ll_call(ftruncate(before, 0)));
            int fa = open(af, O_WRONLY);
            result("ftruncate-a", ll_call(ftruncate(fa, 0)));
            close(fa);
            result("proc-status", ll_open("/proc/self/status", O_RDONLY));
            /* A child keeps the domain. */
            fflush(stdout);
            fflush(stdout);
            pid_t grandchild = child();
            if (grandchild == 0) {
                result("child-read-b", ll_open(bf, O_RDONLY));
                fflush(stdout);
                _exit(0);
            }
            waitpid(grandchild, NULL, 0);
            fflush(stdout);
            _exit(0);
        }
        waitpid(pid, NULL, 0);

        /* Truncation without TRUNCATE, and a second layer. */
        pid = child();
        if (pid == 0) {
            long r = ll_ruleset(LL_READ_FILE | LL_WRITE_FILE | LL_TRUNCATE);
            ll_rule(r, a, LL_READ_FILE | LL_WRITE_FILE);
            ll_rule(r, b, LL_READ_FILE | LL_WRITE_FILE | LL_TRUNCATE);
            ll_enforce(r);
            result("trunc-no-right", ll_open(af, O_WRONLY | O_TRUNC));
            result("write-no-trunc", ll_open(af, O_WRONLY));
            result("trunc-b", ll_open(bf, O_WRONLY | O_TRUNC));
            r = ll_ruleset(LL_READ_FILE);
            ll_rule(r, a, LL_READ_FILE);
            result("second-layer", ll_call(ll_enforce(r)));
            result("layered-read-a", ll_open(af, O_RDONLY));
            result("layered-read-b", ll_open(bf, O_RDONLY));
            result("layered-write-b", ll_open(bf, O_WRONLY));
            fflush(stdout);
            _exit(0);
        }
        waitpid(pid, NULL, 0);

        /* Making and removing names. */
        pid = child();
        if (pid == 0) {
            unsigned long long make = LL_MAKE_REG | LL_MAKE_DIR | LL_MAKE_SYM | LL_MAKE_FIFO |
                                      LL_MAKE_SOCK | LL_REMOVE_FILE | LL_REMOVE_DIR;
            long r = ll_ruleset(make);
            ll_rule(r, a, make);
            ll_enforce(r);
            snprintf(tmp, sizeof tmp, "%s/new", a);
            result("create-a", ll_open(tmp, O_CREAT | O_WRONLY));
            result("unlink-a", ll_call(unlink(tmp)));
            snprintf(tmp, sizeof tmp, "%s/new", b);
            result("create-b", ll_open(tmp, O_CREAT | O_WRONLY));
            result("create-existing-b", ll_open(bf, O_CREAT | O_WRONLY));
            result("mkdir-b", ll_call(mkdir(tmp, 0755)));
            result("symlink-b", ll_call(symlink("x", tmp)));
            result("mkfifo-b", ll_call(mkfifo(tmp, 0644)));
            result("unlink-b", ll_call(unlink(bf)));
            result("unlink-missing-b", ll_call(unlink(tmp)));
            snprintf(tmp, sizeof tmp, "%s/d", a);
            result("mkdir-a", ll_call(mkdir(tmp, 0755)));
            result("rmdir-a", ll_call(rmdir(tmp)));
            int s = socket(AF_UNIX, SOCK_STREAM, 0);
            struct sockaddr_un sun = {AF_UNIX};
            snprintf(sun.sun_path, sizeof sun.sun_path, "%s/s", b);
            result("bind-b", ll_call(bind(s, (void *)&sun, sizeof sun)));
            close(s);
            fflush(stdout);
            _exit(0);
        }
        waitpid(pid, NULL, 0);

        /* Moving between directories: REFER, and no new rights. */
        pid = child();
        if (pid == 0) {
            unsigned long long move = LL_MAKE_REG | LL_REMOVE_FILE | LL_READ_FILE | LL_REFER;
            long r = ll_ruleset(move);
            ll_rule(r, a, LL_MAKE_REG | LL_REMOVE_FILE | LL_REFER);
            ll_rule(r, b, LL_MAKE_REG | LL_REMOVE_FILE | LL_REFER | LL_READ_FILE);
            ll_enforce(r);
            char x[128], y[128];
            snprintf(x, sizeof x, "%s/g", a);
            snprintf(y, sizeof y, "%s/g", b);
            result("same-dir-rename", ll_call(rename(af, x)));
            result("gaining-rename", ll_call(rename(x, y)));
            result("gaining-link", ll_call(link(x, y)));
            result("losing-rename", ll_call(rename(bf, x)));
            result("exchange", ll_call(syscall(316, AT_FDCWD, x, AT_FDCWD, y, 2)));
            fflush(stdout);
            _exit(0);
        }
        waitpid(pid, NULL, 0);
        pid = child();
        if (pid == 0) {
            /* Without REFER handled, moving to another directory is EXDEV. */
            long r = ll_ruleset(LL_MAKE_REG | LL_REMOVE_FILE);
            ll_rule(r, top, LL_MAKE_REG | LL_REMOVE_FILE);
            ll_enforce(r);
            char x[128];
            snprintf(x, sizeof x, "%s/h", b);
            snprintf(tmp, sizeof tmp, "%s/g", a);
            result("no-refer-rename", ll_call(rename(tmp, x)));
            fflush(stdout);
            _exit(0);
        }
        waitpid(pid, NULL, 0);

        /* A rule names the file its descriptor holds, even renamed since. */
        pid = child();
        if (pid == 0) {
            char d1[128], d2[128], inner[160];
            snprintf(d1, sizeof d1, "%s/d1", top);
            snprintf(d2, sizeof d2, "%s/d2", top);
            snprintf(inner, sizeof inner, "%s/f", d2);
            mkdir(d1, 0755);
            int held = open(d1, O_PATH | O_DIRECTORY);
            result("renamed", ll_call(rename(d1, d2)));
            close(open(inner, O_CREAT | O_WRONLY, 0644));
            long r = ll_ruleset(LL_READ_FILE);
            struct ll_path_beneath held_rule = {LL_READ_FILE, held};
            result("rule-renamed", ll_call(syscall(445, r, 1, &held_rule, 0)));
            ll_enforce(r);
            result("read-renamed", ll_open(inner, O_RDONLY));
            result("read-other", ll_open(af, O_RDONLY));
            fflush(stdout);
            _exit(0);
        }
        waitpid(pid, NULL, 0);

        /* Running a program: EXECUTE. */
        pid = child();
        if (pid == 0) {
            /* Removed files, one in a and one outside, which execveat runs
               from their descriptors: Landlock still walks up from where
               each was (EACCES outside a), and the one in a is no program. */
            char removed_in[112], removed_out[112];
            snprintf(removed_in, sizeof removed_in, "%s/removed", a);
            snprintf(removed_out, sizeof removed_out, "%s/removed", b);
            /* Open for reading only: a file open for writing is ETXTBSY. */
            close(open(removed_in, O_CREAT | O_WRONLY, 0755));
            close(open(removed_out, O_CREAT | O_WRONLY, 0755));
            chmod(removed_in, 0755);
            chmod(removed_out, 0755);
            int in = open(removed_in, O_RDONLY), out = open(removed_out, O_RDONLY);
            unlink(removed_in);
            unlink(removed_out);
            long r = ll_ruleset(LL_EXECUTE);
            ll_rule(r, a, LL_EXECUTE);
            ll_enforce(r);
            {
                char *argv[] = {"x", NULL}, *envp[] = {NULL};
                errno = 0;
                syscall(SYS_execveat, in, "", argv, envp, AT_EMPTY_PATH);
                result("exec-removed-inside", errno);
                errno = 0;
                syscall(SYS_execveat, out, "", argv, envp, AT_EMPTY_PATH);
                result("exec-removed-outside", errno);
            }
            /* A file that may be executed, outside a: Landlock refuses the
               open for execution before the file is read. */
            snprintf(tmp, sizeof tmp, "%s/x", b);
            close(open(tmp, O_CREAT | O_WRONLY, 0755));
            chmod(tmp, 0755);
            char *argv[] = {"x", NULL};
            execv(tmp, argv);
            result("exec-outside", errno);
            fflush(stdout);
            _exit(0);
        }
        waitpid(pid, NULL, 0);

        /* ABI 4: the ruleset's network rights, and rules on TCP ports. */
        {
            struct ll_ruleset_attr unknown_net = {0, 1ULL << 40};
            result("unknown-net-right", ll_call(syscall(444, &unknown_net, sizeof unknown_net, 0)));
            long only_net = ll_net_ruleset(0, LL_BIND_TCP);
            result("net-only-ruleset", only_net >= 0);
            result("port-empty", ll_call(ll_port(only_net, 80, 0)));
            result("port-unhandled", ll_call(ll_port(only_net, 80, LL_CONNECT_TCP)));
            result("port-too-big", ll_call(ll_port(only_net, 65536, LL_BIND_TCP)));
            result("port-null", ll_call(syscall(445, only_net, 2, NULL, 0)));
            result("port", ll_call(ll_port(only_net, 80, LL_BIND_TCP)));
            struct ll_path_beneath rule = {LL_READ_FILE, open(a, O_PATH)};
            result("path-on-net-only", ll_call(syscall(445, only_net, 1, &rule, 0)));
            close(rule.parent_fd);
            close(only_net);
            long only_fs = ll_ruleset(LL_READ_FILE);
            result("port-on-fs-only", ll_call(ll_port(only_fs, 80, LL_BIND_TCP)));
            rule.allowed = LL_IOCTL_DEV;
            rule.parent_fd = open(a, O_PATH);
            result("ioctl-unhandled", ll_call(syscall(445, only_fs, 1, &rule, 0)));
            close(rule.parent_fd);
            close(only_fs);
        }
        fflush(stdout);
        pid = child();
        if (pid == 0) {
            long r = ll_net_ruleset(0, LL_BIND_TCP | LL_CONNECT_TCP);
            result("enforce-net", ll_call(ll_enforce(r)));
            /* A layer that handles only the network still checks REFER for
               the file layers' moves; a domain of only network layers checks
               no file at all. */
            char x[128];
            snprintf(x, sizeof x, "%s/moved", b);
            snprintf(tmp, sizeof tmp, "%s/net-only", a);
            close(open(tmp, O_CREAT | O_WRONLY, 0644));
            result("net-only-rename", ll_call(rename(tmp, x)));
            result("net-only-read", ll_open(x, O_RDONLY));
            long fs = ll_ruleset(LL_READ_FILE | LL_MAKE_REG | LL_REMOVE_FILE | LL_REFER);
            ll_rule(fs, top, LL_READ_FILE | LL_MAKE_REG | LL_REMOVE_FILE | LL_REFER);
            ll_enforce(fs);
            result("mixed-rename", ll_call(rename(x, tmp)));
            result("mixed-read", ll_open(x, O_RDONLY));
            fflush(stdout);
            _exit(0);
        }
        waitpid(pid, NULL, 0);

        /* ABI 5: ioctl on a device needs IOCTL_DEV, but for the commands
           every file answers; what an open kept stays. */
        fflush(stdout);
        pid = child();
        if (pid == 0) {
            int before = open("/dev/null", O_RDONLY);
            snprintf(tmp, sizeof tmp, "%s/regular", a);
            int file = open(tmp, O_CREAT | O_RDONLY, 0644);
            long r = ll_ruleset(LL_IOCTL_DEV);
            result("ioctl-file-rule", ll_call(ll_rule(r, "/dev/zero", LL_IOCTL_DEV)));
            result("enforce-ioctl", ll_call(ll_enforce(r)));
            int null = open("/dev/null", O_RDONLY), zero = open("/dev/zero", O_RDONLY);
            int n = 0;
            result("fionread-null", ll_call(ioctl(null, FIONREAD, &n)));
            result("tcgets-null", ll_call(ioctl(null, TCGETS, &n)));
            result("fioclex-null", ll_call(ioctl(null, FIOCLEX)));
            result("fionbio-null", ll_call(ioctl(null, FIONBIO, &n)));
            result("figetbsz-null", ll_call(ioctl(null, FIGETBSZ, &n)));
            result("fionread-zero", ll_call(ioctl(zero, FIONREAD, &n)));
            result("fionread-before", ll_call(ioctl(before, FIONREAD, &n)));
            result("fionread-file", ll_call(ioctl(file, FIONREAD, &n)));
            int pipes[2];
            pipe(pipes);
            result("fionread-pipe", ll_call(ioctl(pipes[0], FIONREAD, &n)));
            result("ioctl-bad-fd", ll_call(ioctl(9999, FIONREAD, &n)));
            int path = open("/dev/null", O_PATH);
            result("ioctl-o-path", ll_call(ioctl(path, FIONREAD, &n)));
            /* Passed on: the right stays with the open file description. */
            fflush(stdout);
            pid_t grandchild = child();
            if (grandchild == 0) {
                result("child-fionread-null", ll_call(ioctl(null, FIONREAD, &n)));
                fflush(stdout);
                _exit(0);
            }
            waitpid(grandchild, NULL, 0);
            fflush(stdout);
            _exit(0);
        }
        waitpid(pid, NULL, 0);

        /* ABI 6: scopes in the ruleset, ABI 7 and 8: restrict_self flags. */
        {
            struct ll_scoped_attr attr = {0, 0, 1ULL << 40};
            result("unknown-scope", ll_call(syscall(444, &attr, sizeof attr, 0)));
            long only_scope = ll_scoped(0, LL_SCOPE_SIGNAL);
            result("scope-only-ruleset", only_scope >= 0);
            close(only_scope);
            unsigned long long longer[4] = {LL_READ_FILE, 0, 0, 1};
            result("past-scoped", ll_call(syscall(444, longer, sizeof longer, 0)));
            prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
            long r = ll_ruleset(LL_READ_FILE);
            result("restrict-unknown-flag", ll_call(syscall(446, r, 1U << 4)));
            result("subdomains-off-alone", ll_call(syscall(446, -1, LL_LOG_SUBDOMAINS_OFF)));
            result("no-ruleset", ll_call(syscall(446, -1, 0)));
            /* -1 may come with TSYNC too, but with no other flag. */
            result("subdomains-off-and-more",
                   ll_call(syscall(446, -1, LL_LOG_SUBDOMAINS_OFF | LL_TSYNC)));
            result("subdomains-off-and-log",
                   ll_call(syscall(446, -1, LL_LOG_SUBDOMAINS_OFF | LL_LOG_SAME_EXEC_OFF)));
            close(r);
        }
        fflush(stdout);
        pid_t outsider = child();
        if (outsider == 0) {
            pause();
            _exit(0);
        }
        /* Abstract unix sockets made outside the domain: a listener and a
           datagram socket. */
        char abstract_name[64];
        int name_len = snprintf(abstract_name, sizeof abstract_name, "%cpaludarium-ll-%d", 0, getpid());
        struct sockaddr_un outside = {AF_UNIX};
        memcpy(outside.sun_path, abstract_name, name_len);
        socklen_t outside_len = offsetof(struct sockaddr_un, sun_path) + name_len;
        int listener = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        bind(listener, (void *)&outside, outside_len);
        listen(listener, 8);
        struct sockaddr_un outside_dgram = outside;
        outside_dgram.sun_path[1] = 'D';
        int dgram = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        bind(dgram, (void *)&outside_dgram, outside_len);
        fflush(stdout);
        pid = child();
        if (pid == 0) {
            long r = ll_scoped(0, LL_SCOPE_SIGNAL | LL_SCOPE_ABSTRACT_UNIX);
            result("enforce-scoped",
                   ll_call(syscall(446, r, LL_LOG_SAME_EXEC_OFF | LL_LOG_NEW_EXEC_ON)));
            close(r);
            /* Signals: outside the domain is EPERM, its own process and
               what it starts are not. */
            result("kill-outsider", ll_call(kill(outsider, 0)));
            result("kill-parent", ll_call(kill(getppid(), 0)));
            result("kill-self", ll_call(kill(getpid(), 0)));
            result("kill-missing", ll_call(kill(999999, 0)));
            fflush(stdout);
            pid_t inside = child();
            if (inside == 0) {
                result("inside-kill-parent", ll_call(kill(getppid(), 0)));
                fflush(stdout);
                _exit(0);
            }
            /* Until it is reaped, a zombie keeps its domain. */
            siginfo_t info;
            waitid(P_PID, inside, &info, WEXITED | WNOWAIT);
            result("kill-inside", ll_call(kill(inside, 0)));
            waitpid(inside, NULL, 0);
            ll_main_tid = syscall(SYS_gettid);
            int from_thread = -1;
            pthread_t thread;
            pthread_create(&thread, NULL, ll_thread_signal, &from_thread);
            pthread_join(thread, NULL);
            result("thread-signals-main", from_thread);
            /* /proc: a task outside the domain is as ptrace sees it. */
            char environ_path[64];
            snprintf(environ_path, sizeof environ_path, "/proc/%d/environ", getppid());
            result("environ-outside", ll_open(environ_path, O_RDONLY));
            result("environ-self", ll_open("/proc/self/environ", O_RDONLY));
            /* Abstract unix sockets made outside: EPERM; one made inside and
               a pathname socket are not scoped. */
            int s = socket(AF_UNIX, SOCK_STREAM, 0);
            result("connect-outside", ll_call(connect(s, (void *)&outside, outside_len)));
            close(s);
            s = socket(AF_UNIX, SOCK_DGRAM, 0);
            result("sendto-outside",
                   ll_call(sendto(s, "x", 1, 0, (void *)&outside_dgram, outside_len)));
            result("connect-dgram-outside",
                   ll_call(connect(s, (void *)&outside_dgram, outside_len)));
            close(s);
            struct sockaddr_un own = outside;
            own.sun_path[1] = 'I';
            int own_listener = socket(AF_UNIX, SOCK_STREAM, 0);
            bind(own_listener, (void *)&own, outside_len);
            listen(own_listener, 8);
            s = socket(AF_UNIX, SOCK_STREAM, 0);
            result("connect-inside", ll_call(connect(s, (void *)&own, outside_len)));
            close(s);
            struct sockaddr_un named = {AF_UNIX};
            snprintf(named.sun_path, sizeof named.sun_path, "%s/sock", top);
            int path_listener = socket(AF_UNIX, SOCK_STREAM, 0);
            bind(path_listener, (void *)&named, sizeof named);
            listen(path_listener, 8);
            fflush(stdout);
            pid_t path_child = child();
            if (path_child == 0) {
                long more = ll_scoped(0, LL_SCOPE_ABSTRACT_UNIX);
                syscall(446, more, 0);
                s = socket(AF_UNIX, SOCK_STREAM, 0);
                result("connect-pathname", ll_call(connect(s, (void *)&named, sizeof named)));
                s = socket(AF_UNIX, SOCK_STREAM, 0);
                /* The parent's domain is not this child's new one. */
                result("connect-parent-made", ll_call(connect(s, (void *)&own, outside_len)));
                fflush(stdout);
                _exit(0);
            }
            waitpid(path_child, NULL, 0);
            close(own_listener);
            unlink(named.sun_path);
            fflush(stdout);
            _exit(0);
        }
        waitpid(pid, NULL, 0);
        kill(outsider, SIGKILL);
        waitpid(outsider, NULL, 0);
        close(listener);
        close(dgram);

        /* ABI 8: LANDLOCK_RESTRICT_SELF_TSYNC gives every thread the domain;
           without it a sibling keeps its own. */
        for (int tsync = 0; tsync <= 1; tsync++) {
            fflush(stdout);
            pid = child();
            if (pid == 0) {
                snprintf(tmp, sizeof tmp, "%s/tsync", b);
                close(open(tmp, O_CREAT | O_WRONLY, 0644));
                char writable[128];
                snprintf(writable, sizeof writable, "%s/tsync-write", a);
                close(open(writable, O_CREAT | O_WRONLY, 0644));
                ll_target = tmp;
                ll_writable = writable;
                pipe(ll_go);
                pipe(ll_done);
                pipe(ll_ready);
                prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
                pthread_t thread;
                pthread_create(&thread, NULL, ll_thread_open, NULL);
                int own = -1;
                if (read(ll_ready[0], &own, sizeof own) != sizeof own)
                    own = -1;
                result("sibling-own-layer", own);
                long r = ll_ruleset(LL_READ_FILE);
                ll_rule(r, a, LL_READ_FILE);
                result(tsync ? "enforce-tsync" : "enforce-alone",
                       ll_call(syscall(446, r, tsync ? LL_TSYNC : 0)));
                close(r);
                /* TSYNC replaces the sibling's own domain with the caller's,
                   whatever it was, so its WRITE_FILE layer goes. */
                int found[2];
                ll_ask_thread(found);
                result(tsync ? "sibling-with-tsync" : "sibling-without", found[0]);
                result(tsync ? "sibling-write-with-tsync" : "sibling-write-without", found[1]);
                result(tsync ? "self-with-tsync" : "self-without", ll_open(tmp, O_RDONLY));
                pthread_join(thread, NULL);
                fflush(stdout);
                _exit(0);
            }
            waitpid(pid, NULL, 0);
        }

        /* Erratum 4: a whiteout (a character device 0) needs MAKE_REG, not
           MAKE_CHAR. */
        fflush(stdout);
        pid = child();
        if (pid == 0) {
            long r = ll_ruleset(LL_MAKE_REG | (1ULL << 6));
            ll_rule(r, a, 1ULL << 6);
            ll_enforce(r);
            snprintf(tmp, sizeof tmp, "%s/whiteout", a);
            result("whiteout-needs-make-reg", ll_call(mknod(tmp, S_IFCHR | 0600, 0)));
            snprintf(tmp, sizeof tmp, "%s/whiteout", b);
            result("whiteout-outside", ll_call(mknod(tmp, S_IFCHR | 0600, 0)));
            fflush(stdout);
            _exit(0);
        }
        waitpid(pid, NULL, 0);

        snprintf(tmp, sizeof tmp, "rm -rf %s", top);
        system(tmp);
        return 0;
    }
    if (!strcmp(mode, "affinity")) {
        unsigned long mask[16] = {0};
        long size = syscall(SYS_sched_getaffinity, 0, 8, mask);
        result("size", size);
        /* The same machine runs both sides, so the CPU counts agree. */
        result("cpus", __builtin_popcountl(mask[0]));
        result("online", sysconf(_SC_NPROCESSORS_ONLN) == __builtin_popcountl(mask[0]));
        result("pid", syscall(SYS_sched_getaffinity, getpid(), 8, mask));
        result("tid", syscall(SYS_sched_getaffinity, syscall(SYS_gettid), 8, mask));
        long lengths[] = {12, 0, 4};
        for (int i = 0; i < 3; i++) {
            errno = 0;
            result("length", syscall(SYS_sched_getaffinity, 0, lengths[i], mask));
            result("errno", errno);
        }
        errno = 0;
        result("missing", syscall(SYS_sched_getaffinity, 0x3fffffff, 8, mask));
        result("errno", errno);
        errno = 0;
        result("fault", syscall(SYS_sched_getaffinity, 0, 8, (void *)1));
        result("errno", errno);

        /* sched_setaffinity: a mask kept for the thread, read up to a CPU
           mask's size, inherited by threads and processes, and settable for
           another process. */
        int cpus = __builtin_popcountl(mask[0]);
        unsigned long all[16] = {0}, one[16] = {1}, none[16] = {0};
        syscall(SYS_sched_getaffinity, 0, sizeof all, all);
        result("set-one", syscall(SYS_sched_setaffinity, 0, sizeof one, one));
        syscall(SYS_sched_getaffinity, 0, sizeof mask, mask);
        result("got-one", mask[0] == 1);
        /* getcpu: pinned to CPU 0, the thread runs there, on node 0. */
        unsigned cpu = 99, node = 99;
        result("getcpu", syscall(SYS_getcpu, &cpu, &node, NULL));
        result("cpu", cpu);
        result("node", node);
        result("getcpu-null", syscall(SYS_getcpu, NULL, NULL, NULL));
        errno = 0;
        result("getcpu-fault", syscall(SYS_getcpu, (void *)1, NULL, NULL));
        result("errno", errno);
        unsigned char short_mask = 1;
        result("set-short", syscall(SYS_sched_setaffinity, 0, 1, &short_mask));
        errno = 0;
        result("set-none", syscall(SYS_sched_setaffinity, 0, sizeof none, none));
        result("errno", errno);
        errno = 0;
        result("set-fault", syscall(SYS_sched_setaffinity, 0, sizeof one, (void *)1));
        result("errno", errno);
        errno = 0;
        result("set-missing", syscall(SYS_sched_setaffinity, 0x3fffffff, sizeof one, one));
        result("errno", errno);
        /* The mask is read before the thread is looked for, and that before
           an empty mask is refused. */
        errno = 0;
        result("set-missing-fault", syscall(SYS_sched_setaffinity, 0x3fffffff, sizeof one, (void *)1));
        result("errno", errno);
        errno = 0;
        result("set-missing-none", syscall(SYS_sched_setaffinity, 0x3fffffff, sizeof none, none));
        result("errno", errno);
        pthread_t thread;
        static unsigned long seen[16];
        pthread_create(&thread, NULL, affinity_of_thread, seen);
        pthread_join(thread, NULL);
        result("thread-inherits", seen[0] == 1);
        int wait_pipe[2], ready_pipe[2];
        if (pipe(wait_pipe) || pipe(ready_pipe)) return 1;
        fflush(stdout);
        pid_t child = fork();
        if (!child) {
            unsigned long inherited[16] = {0};
            syscall(SYS_sched_getaffinity, 0, sizeof inherited, inherited);
            char byte;
            /* The parent changes the mask only once this one was read. */
            if (write(ready_pipe[1], "r", 1) != 1 || read(wait_pipe[0], &byte, 1) != 1) _exit(99);
            unsigned long now[16] = {0};
            syscall(SYS_sched_getaffinity, 0, sizeof now, now);
            _exit((inherited[0] == 1) | (__builtin_popcountl(now[0]) == cpus) << 1);
        }
        char ready;
        if (read(ready_pipe[0], &ready, 1) != 1) return 1;
        result("set-other", syscall(SYS_sched_setaffinity, child, sizeof all, all));
        unsigned long other[16] = {0};
        syscall(SYS_sched_getaffinity, child, sizeof other, other);
        result("got-other", __builtin_popcountl(other[0]) == cpus);
        if (write(wait_pipe[1], "x", 1) != 1) return 1;
        int status;
        waitpid(child, &status, 0);
        result("child", WEXITSTATUS(status));
        syscall(SYS_sched_setaffinity, 0, sizeof all, all);
        return 0;
    }
    if (!strcmp(mode, "ids")) {
        /* Native IDs are the runner's and emulated ones root, so compare
           each with the owner of a newly created file. */
        const char *path = "/tmp/paludarium-processes-ids";
        unlink(path);
        int fd = open(path, O_CREAT|O_RDWR, 0600);
        struct stat st;
        result("stat", fstat(fd, &st));
        result("uid", getuid() == st.st_uid);
        result("euid", geteuid() == getuid());
        result("gid", getgid() == st.st_gid);
        result("egid", getegid() == getgid());
        close(fd);
        unlink(path);
        return 0;
    }
    if (!strcmp(mode, "chown")) {
        /* The native side is an ordinary user and the emulated one root, so
           only their own IDs and -1 are given, and owners are compared with
           them rather than printed. */
        const char *path = "/tmp/paludarium-processes-chown";
        const char *link = "/tmp/paludarium-processes-chown-link";
        const char *dir = "/tmp/paludarium-processes-chown-dir";
        unlink(path);
        unlink(link);
        rmdir(dir);
        int fd = open(path, O_CREAT|O_RDWR, 0644);
        symlink(path, link);
        mkdir(dir, 0755);
        uid_t uid = getuid();
        gid_t gid = getgid();
        struct stat st;
        outcome("chown", chown(path, uid, gid));
        stat(path, &st);
        result("owner", st.st_uid == uid && st.st_gid == gid);
        /* A file loses set-user-ID, and set-group-ID with group execution,
           even when nothing changes; a directory keeps both. */
        chmod(path, 06755);
        outcome("unchanged", chown(path, -1, -1));
        stat(path, &st);
        printf("mode=%o\n", st.st_mode & 07777);
        chmod(path, 06745);
        outcome("fchown", fchown(fd, uid, -1));
        fstat(fd, &st);
        printf("mode=%o\n", st.st_mode & 07777);
        chmod(dir, 06755);
        outcome("directory", chown(dir, -1, gid));
        stat(dir, &st);
        printf("mode=%o\n", st.st_mode & 07777);
        /* What is made in a set-group-ID directory takes its group, and a
           directory the bit. */
        mkdir("/tmp/paludarium-processes-chown-dir/sub", 0755);
        stat("/tmp/paludarium-processes-chown-dir/sub", &st);
        printf("sub=%o group=%d\n", st.st_mode & 07777, st.st_gid == gid);
        rmdir("/tmp/paludarium-processes-chown-dir/sub");
        chmod(path, 04755);
        outcome("lchown", lchown(link, uid, gid));
        stat(path, &st);
        printf("mode=%o\n", st.st_mode & 07777);
        outcome("nofollow", fchownat(AT_FDCWD, link, -1, -1, AT_SYMLINK_NOFOLLOW));
        stat(path, &st);
        printf("mode=%o\n", st.st_mode & 07777);
        outcome("follow", fchownat(AT_FDCWD, link, -1, -1, 0));
        stat(path, &st);
        printf("mode=%o\n", st.st_mode & 07777);
        chmod(path, 04755);
        outcome("empty-path", fchownat(fd, "", -1, -1, AT_EMPTY_PATH));
        fstat(fd, &st);
        printf("mode=%o\n", st.st_mode & 07777);
        outcome("empty-no-flag", fchownat(fd, "", -1, -1, 0));
        outcome("bad-flag", fchownat(AT_FDCWD, path, -1, -1, 0x200));
        outcome("missing", chown("/tmp/paludarium-processes-chown-missing", -1, -1));
        outcome("not-a-directory", chown("/tmp/paludarium-processes-chown/x", -1, -1));
        outcome("bad-fd", fchown(999, -1, -1));
        outcome("bad-path", syscall(SYS_chown, (char *)8, -1, -1));
        close(fd);
        unlink(link);
        unlink(path);
        rmdir(dir);
        return 0;
    }
    if (!strcmp(mode, "fd-attributes")) {
        /* Pipes and sockets have inodes whose mode and owner fchmod and
           fchown change; only the caller's own IDs are given. */
        int pipe_fds[2], pair[2];
        pipe(pipe_fds);
        socketpair(AF_UNIX, SOCK_STREAM, 0, pair);
        uid_t uid = getuid();
        gid_t gid = getgid();
        struct stat st;
        fstat(pipe_fds[1], &st);
        printf("pipe=%o owner=%d\n", st.st_mode, st.st_uid == uid && st.st_gid == gid);
        outcome("pipe-fchmod", fchmod(pipe_fds[0], 04640));
        fstat(pipe_fds[1], &st);
        printf("pipe=%o\n", st.st_mode);
        outcome("pipe-fchown", fchown(pipe_fds[1], uid, gid));
        fstat(pipe_fds[0], &st);
        printf("pipe=%o owner=%d\n", st.st_mode, st.st_uid == uid && st.st_gid == gid);
        fstat(pair[0], &st);
        printf("socket=%o owner=%d\n", st.st_mode, st.st_uid == uid && st.st_gid == gid);
        outcome("socket-fchmod", fchmod(pair[0], 0600));
        outcome("socket-fchown", fchown(pair[0], -1, gid));
        fstat(pair[0], &st);
        printf("socket=%o owner=%d\n", st.st_mode, st.st_uid == uid && st.st_gid == gid);
        fstat(pair[1], &st);
        printf("peer=%o\n", st.st_mode);
        return 0;
    }
    if (!strcmp(mode, "shared-file-mapping")) {
        /* A shared mapping shows the file's page cache: stores reach reads
           of the file and a child's mapping, writes to the file reach the
           mapping, and whether it may write follows the file's access. */
        const char *path = "/tmp/paludarium-processes-shared-mapping";
        unlink(path);
        int fd = open(path, O_CREAT|O_RDWR|O_TRUNC, 0600);
        write(fd, "hello", 5);
        char *map = mmap(NULL, 8192, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
        printf("mapped=%d first=%.5s\n", map != MAP_FAILED, map);
        char buf[16] = {0};
        map[0] = 'J';
        pread(fd, buf, 8, 0);
        printf("read=%s\n", buf);
        pwrite(fd, "xy", 2, 3);
        printf("map=%.5s\n", map);
        lseek(fd, 0, SEEK_END);
        write(fd, "!", 1);
        printf("grown=%.6s\n", map);
        /* Truncating clears what lies past the end, and a store there
           stays out of the file. */
        ftruncate(fd, 2);
        printf("cut=%d\n", map[2]);
        map[100] = 'q';
        struct stat st;
        fstat(fd, &st);
        printf("size=%ld\n", (long)st.st_size);
        ftruncate(fd, 4);
        memset(buf, 1, sizeof buf);
        int n = pread(fd, buf, 8, 0);
        printf("n=%d bytes=%d,%d,%d,%d\n", n, buf[0], buf[1], buf[2], buf[3]);
        pid_t pid = fork();
        if (pid == 0) {
            map[1] = 'E';
            _exit(0);
        }
        waitpid(pid, NULL, 0);
        printf("child=%c\n", map[1]);
        /* Another shared mapping shows the same pages; a private one copies
           them and keeps its own stores. */
        char *again = mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
        again[2] = 'L';
        char *copy = mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE, fd, 0);
        printf("again=%c copy=%.3s\n", map[2], copy);
        copy[0] = 'p';
        printf("private=%c\n", map[0]);
        outcome("msync", msync(map, 4096, MS_SYNC));
        munmap(again, 4096);
        munmap(copy, 4096);
        map[3] = 'Z';
        munmap(map, 8192);
        memset(buf, 0, sizeof buf);
        pread(fd, buf, 8, 0);
        printf("after=%s\n", buf);
        int read_only = open(path, O_RDONLY);
        errno = 0;
        void *refused = mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_SHARED, read_only, 0);
        printf("read-only-write=%d errno=%d\n", refused != MAP_FAILED, errno);
        char *view = mmap(NULL, 4096, PROT_READ, MAP_SHARED, read_only, 0);
        outcome("read-only-protect", mprotect(view, 4096, PROT_READ|PROT_WRITE));
        munmap(view, 4096);
        view = mmap(NULL, 4096, PROT_READ, MAP_SHARED, fd, 0);
        outcome("read-write-protect", mprotect(view, 4096, PROT_READ|PROT_WRITE));
        view[0] = 'w';
        munmap(view, 4096);
        pread(fd, buf, 1, 0);
        printf("protected=%c\n", buf[0]);
        /* A memfd: F_SEAL_WRITE waits for its writable mappings to go. So
           does F_SEAL_EXEC on an executable one since Linux 7.1's fix
           (3b041514cb6e), which older runner kernels lack, so only the kernel
           unit tests check it. */
        int memfd = memfd_create("shared", MFD_ALLOW_SEALING);
        ftruncate(memfd, 4096);
        char *shm = mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_SHARED, memfd, 0);
        memcpy(shm, "memfd", 5);
        memset(buf, 0, sizeof buf);
        pread(memfd, buf, 5, 0);
        printf("memfd=%s\n", buf);
        outcome("seal-mapped", fcntl(memfd, F_ADD_SEALS, F_SEAL_WRITE));
        munmap(shm, 4096);
        outcome("seal", fcntl(memfd, F_ADD_SEALS, F_SEAL_WRITE));
        errno = 0;
        refused = mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_SHARED, memfd, 0);
        printf("sealed-write=%d errno=%d\n", refused != MAP_FAILED, errno);
        close(memfd);
        close(read_only);
        close(fd);
        unlink(path);
        return 0;
    }
    if (!strcmp(mode, "file-mapping-end")) {
        /* A page of a file mapping wholly past the end of the file raises
           SIGBUS with BUS_ADRERR, for shared and private mappings alike;
           the end moves with the file, and mremap grows a mapping over
           more of the file. */
        struct sigaction action = {0};
        action.sa_sigaction = on_bus;
        action.sa_flags = SA_SIGINFO;
        sigaction(SIGBUS, &action, NULL);
        const char *path = "/tmp/paludarium-processes-file-mapping-end";
        unlink(path);
        int fd = open(path, O_CREAT|O_RDWR|O_TRUNC, 0600);
        int pipe_fds[2];
        pipe(pipe_fds);
        char data[100];
        memset(data, 'd', sizeof data);
        write(fd, data, sizeof data);
        const char *kinds[] = {"shared", "private"};
        for (int k = 0; k < 2; k++) {
            ftruncate(fd, 100);
            char *map = mmap(NULL, 3 * 4096, PROT_READ|PROT_WRITE, k ? MAP_PRIVATE : MAP_SHARED, fd, 0);
            printf("%s: mapped=%d\n", kinds[k], map != MAP_FAILED);
            touch("in-file", map + 50, 0);
            touch("last-page", map + 200, 0);
            touch("past-read", map + 4096, 0);
            touch("past-write", map + 2 * 4096 + 7, 1);
            errno = 0;
            long wrote = write(pipe_fds[1], map + 4096, 1);
            printf("past-syscall=%ld errno=%d\n", wrote, errno);
            /* The file grows: the page reads it now. */
            ftruncate(fd, 5000);
            pwrite(fd, "grow", 4, 4200);
            touch("grown-zero", map + 4096 + 10, 0);
            touch("grown-data", map + 4200, 0);
            /* It shrinks: even a page read before is past the end. */
            ftruncate(fd, 100);
            touch("shrunk", map + 4096 + 10, 0);
            touch("kept", map + 50, 0);
            /* mremap grows the mapping over more of the file. */
            ftruncate(fd, 3 * 4096 + 1);
            pwrite(fd, "far", 3, 3 * 4096);
            char *grown = mremap(map, 3 * 4096, 5 * 4096, MREMAP_MAYMOVE);
            printf("remapped=%d\n", grown != MAP_FAILED);
            touch("remap-data", grown + 3 * 4096, 0);
            touch("remap-past", grown + 4 * 4096, 0);
            munmap(grown, 5 * 4096);
        }
        close(pipe_fds[0]);
        close(pipe_fds[1]);
        close(fd);
        unlink(path);
        return 0;
    }
    if (!strcmp(mode, "fork-copy-on-write")) {
        /* After fork, each process's write to a private page leaves the
           other's page as it was, either way round, and a page written
           before the fork stays private. A truncation drops the copies of
           a private file mapping in both processes. */
        char *anon = mmap(NULL, 3 * 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
        memset(anon, 'a', 3 * 4096);
        const char *path = "/tmp/paludarium-processes-fork-copy-on-write";
        unlink(path);
        int fd = open(path, O_CREAT|O_RDWR|O_TRUNC, 0600);
        ftruncate(fd, 4096);
        char *file = mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE, fd, 0);
        file[0] = 'x';
        int to_child[2], to_parent[2];
        pipe(to_child);
        pipe(to_parent);
        fflush(stdout);
        char b = 0;
        pid_t pid = fork();
        if (pid == 0) {
            anon[0] = 'c';
            printf("child: own=%c other=%c file=%c\n", anon[0], anon[4096], file[0]);
            fflush(stdout);
            write(to_parent[1], "1", 1);
            read(to_child[0], &b, 1);
            printf("child: after-parent=%c last=%c\n", anon[4096], anon[2 * 4096]);
            ftruncate(fd, 0);
            ftruncate(fd, 4096);
            printf("child: truncated=%d\n", file[0]);
            fflush(stdout);
            write(to_parent[1], "2", 1);
            _exit(0);
        }
        read(to_parent[0], &b, 1);
        printf("parent: after-child=%c\n", anon[0]);
        anon[4096] = 'p';
        printf("parent: own=%c\n", anon[4096]);
        fflush(stdout);
        write(to_child[1], "1", 1);
        read(to_parent[0], &b, 1);
        printf("parent: truncated=%d last=%c\n", file[0], anon[2 * 4096]);
        int status;
        waitpid(pid, &status, 0);
        printf("status=%d\n", status);
        munmap(file, 4096);
        munmap(anon, 3 * 4096);
        close(fd);
        unlink(path);
        return 0;
    }
    if (!strcmp(mode, "dontneed-read-only-segment")) {
        /* A page of a read-only segment that mprotect made writable and
           that was written reads the executable again after MADV_DONTNEED,
           as a private file mapping does. */
        static const char text[] = "read-only segment";
        volatile const char *at = text;
        char *page = (char *)((uintptr_t)text & ~(uintptr_t)4095);
        printf("before=%c%c%c%c\n", at[0], at[1], at[2], at[3]);
        int protect = mprotect(page, 4096, PROT_READ|PROT_WRITE);
        ((volatile char *)at)[0] = 'R';
        printf("protect=%d written=%c%c%c%c\n", protect, at[0], at[1], at[2], at[3]);
        int advice = madvise(page, 4096, MADV_DONTNEED);
        printf("dontneed=%d again=%c%c%c%c\n", advice, at[0], at[1], at[2], at[3]);
        return 0;
    }
    if (!strcmp(mode, "private-file-mapping")) {
        /* A private file mapping shows the file's later changes in the
           pages it has not written, and its first write to a page copies
           it, for this process alone. A truncation drops the copies it
           leaves wholly past the end of the file, even when the file grows
           again, and MADV_DONTNEED drops them too. */
        struct sigaction action = {0};
        action.sa_sigaction = on_bus;
        action.sa_flags = SA_SIGINFO;
        sigaction(SIGBUS, &action, NULL);
        const char *path = "/tmp/paludarium-processes-private-file-mapping";
        unlink(path);
        int fd = open(path, O_CREAT|O_RDWR|O_TRUNC, 0600);
        ftruncate(fd, 2 * 4096);
        pwrite(fd, "hello", 5, 0);
        pwrite(fd, "pages", 5, 4096);
        char *map = mmap(NULL, 2 * 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE, fd, 0);
        printf("mapped=%d first=%.5s\n", map != MAP_FAILED, map);
        pwrite(fd, "HELLO", 5, 0);
        printf("unwritten=%.5s\n", map);
        map[0] = 'j';
        char file[6] = {0};
        pread(fd, file, 5, 0);
        pwrite(fd, "world", 5, 0);
        printf("copied=%.5s file=%s other=%.5s\n", map, file, map + 4096);
        fflush(stdout);
        pid_t child = fork();
        if (child == 0) {
            /* The child shows the file in the page neither wrote, and its
               write copies the page for itself alone. */
            pwrite(fd, "kid", 3, 4096 + 10);
            printf("child: shown=%.3s copy=%.5s\n", map + 4096 + 10, map);
            map[4096] = 'C';
            printf("child: wrote=%.5s\n", map + 4096);
            fflush(stdout);
            _exit(0);
        }
        int status;
        waitpid(child, &status, 0);
        printf("parent: shown=%.3s page=%.5s copy=%.5s\n", map + 4096 + 10, map + 4096, map);
        map[4096 + 1] = 'x';
        ftruncate(fd, 4096);
        touch("truncated", map + 4096, 0);
        ftruncate(fd, 2 * 4096);
        touch("regrown", map + 4096 + 1, 0);
        printf("kept=%.5s\n", map);
        madvise(map, 4096, MADV_DONTNEED);
        printf("dontneed=%.5s\n", map);
        munmap(map, 2 * 4096);
        close(fd);
        unlink(path);
        return 0;
    }
    if (!strcmp(mode, "access")) {
        /* The native side is an ordinary user and the emulated one root:
           only results both give are compared (no write without permission). */
        const char *path = "/tmp/paludarium-processes-access";
        unlink(path);
        int fd = open(path, O_CREAT|O_RDWR, 0644);
        result("exists", access(path, F_OK));
        result("read-write", access(path, R_OK|W_OK));
        errno = 0;
        result("execute", access(path, X_OK));
        result("errno", errno);
        chmod(path, 0755);
        result("executable", access(path, X_OK));
        result("directory", faccessat(AT_FDCWD, "/tmp", X_OK, 0));
        result("empty-path", syscall(439, fd, "", R_OK, AT_EMPTY_PATH));
        errno = 0;
        result("missing", access("/tmp/paludarium-processes-missing", F_OK));
        result("errno", errno);
        errno = 0;
        result("bad-mode", syscall(SYS_access, path, 8));
        result("errno", errno);
        errno = 0;
        result("bad-flags", syscall(439, AT_FDCWD, path, F_OK, 0x400));
        result("errno", errno);
        close(fd);
        unlink(path);
        return 0;
    }
    if (!strcmp(mode, "fsize-limit")) {
        /* RLIMIT_FSIZE cuts a regular file's writes at the limit, and a write
           or growing truncate past it raises SIGXFSZ and fails with EFBIG. */
        const char *path = "/tmp/paludarium-fsize";
        struct sigaction action = {0};
        action.sa_handler = interrupted;
        sigaction(SIGXFSZ, &action, NULL);
        struct rlimit limit;
        getrlimit(RLIMIT_FSIZE, &limit);
        limit.rlim_cur = 10;
        result("set", setrlimit(RLIMIT_FSIZE, &limit));
        int fd = open(path, O_CREAT|O_RDWR|O_TRUNC, 0600);
        char buf[32] = {0};
        received = 0;
        result("write", write(fd, buf, 4));
        result("cut", write(fd, buf, 10));
        result("empty", write(fd, buf, 0));
        result("signals-before", received);
        errno = 0;
        result("past", write(fd, buf, 1) < 0 ? -errno : 0);
        result("signals", received);
        lseek(fd, 7, SEEK_SET);
        struct iovec io[2] = {{buf, 2}, {buf, 2}};
        result("writev-cut", writev(fd, io, 2));
        errno = 0;
        result("writev-past", writev(fd, io, 2) < 0 ? -errno : 0);
        result("pwrite-cut", pwrite(fd, buf, 5, 8));
        errno = 0;
        result("pwrite-past", pwrite(fd, buf, 1, 10) < 0 ? -errno : 0);
        errno = 0;
        result("ftruncate-past", ftruncate(fd, 11) < 0 ? -errno : 0);
        result("ftruncate-shrink", ftruncate(fd, 3));
        result("ftruncate-to", ftruncate(fd, 10));
        errno = 0;
        result("truncate-past", truncate(path, 20) < 0 ? -errno : 0);
        result("signals-after", received);
        int appender = open(path, O_WRONLY|O_APPEND);
        errno = 0;
        result("append-past", write(appender, buf, 1) < 0 ? -errno : 0);
        /* An O_APPEND pwrite appends, so its offset does not count. */
        errno = 0;
        result("append-pwrite-past", pwrite(appender, buf, 1, 0) < 0 ? -errno : 0);
        close(appender);
        struct stat st;
        fstat(fd, &st);
        result("size", st.st_size);
        /* fork keeps the limit. */
        pid_t pid = child();
        if (pid == 0) {
            errno = 0;
            _exit(pwrite(fd, buf, 1, 10) < 0 && errno == EFBIG ? 0 : 1);
        }
        result("child", reaped(pid));
        close(fd);
        unlink(path);
        return 0;
    }
    if (!strcmp(mode, "nofile-limit")) {
        /* The soft RLIMIT_NOFILE bounds the descriptor numbers: room for two
           more past the lowest free one. */
        const char *a_path = "/tmp/paludarium-nofile-a", *b_path = "/tmp/paludarium-nofile-b";
        const char *c_path = "/tmp/paludarium-nofile-c";
        unlink(c_path);
        int base = dup(0);
        close(base);
        struct rlimit limit;
        getrlimit(RLIMIT_NOFILE, &limit);
        limit.rlim_cur = base + 2;
        result("set", setrlimit(RLIMIT_NOFILE, &limit));
        int a = open(a_path, O_CREAT|O_RDWR, 0600), b = open(b_path, O_CREAT|O_RDWR, 0600);
        result("opened", a == base && b == base + 1);
        int pair[2];
        struct stat st;
        errno = 0;
        result("open", open(c_path, O_CREAT|O_RDWR, 0600) < 0 ? -errno : 0);
        errno = 0;
        result("not-created", stat(c_path, &st) < 0 ? -errno : 0);
        errno = 0;
        result("dup", dup(a) < 0 ? -errno : 0);
        errno = 0;
        result("pipe", pipe(pair) < 0 ? -errno : 0);
        errno = 0;
        result("dup2", dup2(a, base + 2) < 0 ? -errno : 0);
        errno = 0;
        result("dupfd-past", fcntl(a, F_DUPFD, base + 2) < 0 ? -errno : 0);
        errno = 0;
        result("dupfd-full", fcntl(a, F_DUPFD, base) < 0 ? -errno : 0);
        fcntl(a, F_SETFD, FD_CLOEXEC);
        result("dup2-self", dup2(a, a) == a && fcntl(a, F_GETFD) == FD_CLOEXEC);
        /* With one descriptor free, pipe takes neither. */
        close(b);
        errno = 0;
        result("pipe-one", pipe(pair) < 0 ? -errno : 0);
        result("reused", dup(a) == base + 1);
        unlink(a_path);
        unlink(b_path);
        return 0;
    }
    if (!strcmp(mode, "rlimit")) {
        struct rlimit limit, old;
        getrlimit(RLIMIT_NOFILE, &limit);
        rlim_t hard = limit.rlim_max;
        limit.rlim_cur = 256;
        result("set", setrlimit(RLIMIT_NOFILE, &limit));
        getrlimit(RLIMIT_NOFILE, &old);
        result("soft", old.rlim_cur);
        result("hard-kept", old.rlim_max == hard);
        result("prlimit", syscall(SYS_prlimit64, 0, RLIMIT_NOFILE, NULL, &old));
        result("prlimit-soft", old.rlim_cur);
        pid_t pid = child();
        if (pid == 0) {
            struct rlimit inherited;
            getrlimit(RLIMIT_NOFILE, &inherited);
            _exit(inherited.rlim_cur == 256 ? 0 : 1);
        }
        finish(pid);
        limit.rlim_cur = hard;
        limit.rlim_max = 1;
        errno = 0;
        result("soft-above-hard", setrlimit(RLIMIT_NOFILE, &limit));
        result("errno", errno);
        errno = 0;
        result("bad-resource", syscall(SYS_prlimit64, 0, 99, NULL, &old));
        result("errno", errno);
        errno = 0;
        result("missing", syscall(SYS_prlimit64, 0x3fffffff, RLIMIT_NOFILE, NULL, &old));
        result("errno", errno);
        errno = 0;
        result("bad-new", syscall(SYS_prlimit64, 0, RLIMIT_NOFILE, (void *)1, &old));
        result("errno", errno);
        /* The new limit is set before the old one is written out. */
        limit.rlim_cur = 128;
        limit.rlim_max = hard;
        errno = 0;
        result("bad-old", syscall(SYS_prlimit64, 0, RLIMIT_NOFILE, &limit, (void *)1));
        result("errno", errno);
        getrlimit(RLIMIT_NOFILE, &old);
        result("applied", old.rlim_cur);
        return 0;
    }
    if (!strcmp(mode, "pgid")) {
        result("same", getpgrp() == getpgid(0));
        result("own", setpgid(0, 0));
        result("leader", getpgrp() == getpid());
        int ready[2], go[2];
        if (pipe(ready) || pipe(go)) return 81;
        pid_t pid = child();
        if (pid == 0) {
            char byte;
            int inherited = getpgid(0) == getppid();
            if (write(ready[1], &byte, 1) != 1) _exit(85);
            if (read(go[0], &byte, 1) != 1) _exit(86);
            _exit(inherited && getpgid(0) == getpid() ? 0 : 1);
        }
        char byte;
        if (read(ready[0], &byte, 1) != 1) return 82;
        result("child-inherits", getpgid(pid) == getpid());
        result("child-own", setpgid(pid, pid));
        result("child-moved", getpgid(pid) == pid);
        errno = 0;
        result("no-group", setpgid(pid, 0x3ffffff0));
        result("errno", errno);
        if (write(go[1], &byte, 1) != 1) return 83;
        finish(pid);
        errno = 0;
        result("no-process", setpgid(0x3fffffff, 0));
        result("errno", errno);
        errno = 0;
        result("negative", setpgid(0, -1));
        result("errno", errno);
        errno = 0;
        result("getpgid-missing", getpgid(0x3fffffff));
        result("errno", errno);
        return 0;
    }
    if (!strcmp(mode, "priority")) {
        /* Nice values are per thread. Each check only raises them, which
           needs no privilege, and compares them with the starting one. */
        fflush(stdout);
        pid_t pid = fork();
        if (pid == 0) {
            long base = raw_priority(PRIO_PROCESS, 0), nice0 = 20 - base;
            char byte;
            int status;
            if (setpgid(0, 0) || pipe(priority_ready) || pipe(priority_go)) _exit(81);
            result("raise", setpriority(PRIO_PROCESS, 0, nice0 + 3));
            result("raised", raw_priority(PRIO_PROCESS, 0) - base);
            pthread_t worker;
            if (pthread_create(&worker, NULL, priority_thread, (void *)base)) _exit(82);
            if (read(priority_ready[0], &byte, 1) != 1) _exit(83);
            result("thread-inherits", priority_thread_start - base);
            result("thread-own", raw_priority(PRIO_PROCESS, priority_tid) - base);
            result("main-kept", raw_priority(PRIO_PROCESS, 0) - base);
            result("group-highest", raw_priority(PRIO_PGRP, 0) - base);
            result("group-set", setpriority(PRIO_PGRP, 0, nice0 + 6));
            result("group-thread", raw_priority(PRIO_PROCESS, priority_tid) - base);
            if (write(priority_go[1], "x", 1) != 1 || pthread_join(worker, NULL)) _exit(84);
            result("thread-after", priority_thread_after - base);
            pid_t inheritor = fork();
            if (inheritor == 0) _exit(raw_priority(PRIO_PROCESS, 0) - base == -6 ? 0 : 1);
            result("fork-inherits", waitpid(inheritor, &status, 0) == inheritor && status == 0);
            pid_t zombie = fork();
            if (zombie == 0) {
                setpriority(PRIO_PROCESS, 0, 19);
                _exit(0);
            }
            siginfo_t info;
            result("exited", waitid(P_PID, zombie, &info, WEXITED | WNOWAIT) == 0);
            result("zombie", raw_priority(PRIO_PROCESS, zombie));
            waitpid(zombie, &status, 0);
            errno = 0;
            result("reaped", raw_priority(PRIO_PROCESS, zombie));
            result("errno", errno);
            result("clamped", setpriority(PRIO_PROCESS, 0, 1000));
            result("lowest", raw_priority(PRIO_PROCESS, 0));
            errno = 0;
            result("bad-which", setpriority(3, 0, 0));
            result("errno", errno);
            errno = 0;
            result("bad-which-get", raw_priority(-1, 0));
            result("errno", errno);
            errno = 0;
            result("missing", raw_priority(PRIO_PROCESS, 0x3fffffff));
            result("errno", errno);
            errno = 0;
            result("negative", raw_priority(PRIO_PROCESS, -1));
            result("errno", errno);
            errno = 0;
            result("missing-group", raw_priority(PRIO_PGRP, 0x3fffffff));
            result("errno", errno);
            errno = 0;
            result("missing-set", setpriority(PRIO_PROCESS, 0x3fffffff, 19));
            result("errno", errno);
            fflush(stdout);
            _exit(0);
        }
        finish(pid);
        return 0;
    }
    if (!strcmp(mode, "pgid-exec")) {
        /* A child that has run execve keeps its group (EACCES). */
        int ready[2], go[2];
        if (pipe(ready) || pipe(go)) return 81;
        char byte, ready_fd[16], go_fd[16];
        snprintf(ready_fd, sizeof ready_fd, "%d", ready[1]);
        snprintf(go_fd, sizeof go_fd, "%d", go[0]);
        fflush(stdout);
        pid_t pid = child();
        if (pid == 0) {
            char *args[] = { "process", "exec-wait", (char *)self, ready_fd, go_fd, NULL };
            char *env[] = { NULL };
            execve(self, args, env);
            _exit(92);
        }
        if (read(ready[0], &byte, 1) != 1) return 82;
        errno = 0;
        result("executed-own", setpgid(pid, pid));
        result("errno", errno);
        errno = 0;
        result("executed-same", setpgid(pid, getpgrp()));
        result("errno", errno);
        if (write(go[1], "x", 1) != 1) return 83;
        finish(pid);
        /* An exited child not yet reaped still holds its group. */
        pid_t zombie = child();
        if (zombie == 0) _exit(0);
        result("zombie-own", setpgid(zombie, zombie));
        siginfo_t info;
        result("exited", waitid(P_PID, zombie, &info, WEXITED | WNOWAIT) == 0 && info.si_pid == zombie);
        int release[2];
        if (pipe(release)) return 84;
        pid_t member = child();
        if (member == 0) {
            if (read(release[0], &byte, 1) != 1) _exit(1);
            _exit(0);
        }
        result("zombie-group", setpgid(member, zombie));
        result("joined", getpgid(member) == zombie);
        result("back", setpgid(member, getpgrp()));
        finish(zombie);
        errno = 0;
        result("reaped-group", setpgid(member, zombie));
        result("errno", errno);
        if (write(release[1], "x", 1) != 1) return 85;
        finish(member);
        return 0;
    }
    if (!strcmp(mode, "pid-namespace")) {
        /* The emulated program is the first process of a PID namespace, its
           parent, group and session outside it. Natively root makes such a
           namespace and the case goes on in its first process. */
        if (!(getpid() == 1 && getppid() == 0 && getpgrp() == 0)) {
            if (unshare(CLONE_NEWPID)) return 90;
            fflush(stdout);
            pid_t pid = child();
            if (pid < 0) return 91;
            if (pid > 0) {
                int status;
                if (waitpid(pid, &status, 0) != pid) return 92;
                return WIFEXITED(status) ? WEXITSTATUS(status) : 93;
            }
        }
        printf("pid=%d ppid=%d pgrp=%d pgid=%d sid=%d\n", getpid(), getppid(), getpgrp(), getpgid(0), getsid(0));
        int status;
        fflush(stdout);
        pid_t kid = child();
        if (kid == 0) {
            printf("child pid=%d ppid=%d pgrp=%d sid=%d\n", getpid(), getppid(), getpgrp(), getsid(0));
            fflush(stdout);
            _exit(0);
        }
        printf("waited=%d\n", waitpid(kid, &status, 0) == kid && status == 0);
        /* F_SETOWN finds the ID, not a group: -1 names this process's ID. */
        int ends[2];
        if (pipe(ends)) return 94;
        errno = 0;
        long owned = fcntl(ends[0], F_SETOWN, -1);
        struct f_owner_ex ex = {0};
        printf("setown=%ld errno=%d getown=%d", owned, owned < 0 ? errno : 0, fcntl(ends[0], F_GETOWN));
        printf(" getown-ex=%d,%d", fcntl(ends[0], F_GETOWN_EX, &ex), ex.pid);
        printf(" type=%d\n", ex.type == F_OWNER_PGRP);
        errno = 0;
        long started = setsid();
        printf("setsid=%ld errno=%d pgrp=%d sid=%d\n", started, started < 0 ? errno : 0, getpgrp(), getsid(0));
        /* Now group 1 exists, and the owner reads back as it. */
        printf("getown=%d\n", fcntl(ends[0], F_GETOWN));
        close(ends[0]);
        close(ends[1]);
        return 0;
    }
    if (!strcmp(mode, "session")) {
        /* The case names its own group, which the emulated first process,
           like a PID namespace's, is not in until it makes one. */
        if (setpgid(0, 0)) return 80;
        /* setsid in a child, which is not a group leader; what each check
           gives is a bit, sent back through a pipe. */
        int bits_pipe[2], go[2];
        if (pipe(bits_pipe) || pipe(go)) return 81;
        fflush(stdout);
        pid_t pid = child();
        if (pid == 0) {
            int bits = 0, n = 0, status;
            char byte;
#define BIT(check) (bits |= (!!(check)) << n++)
            BIT(getsid(0) == getsid(getppid()));
            BIT(getpgrp() != getpid());
            pid_t parent_group = getpgid(getppid());
            BIT(setsid() == getpid());
            BIT(getsid(0) == getpid() && getpgrp() == getpid());
            errno = 0;
            BIT(setsid() == -1 && errno == EPERM);
            errno = 0;
            BIT(setpgid(0, 0) == -1 && errno == EPERM); /* a session leader */
            int release[2];
            if (pipe(release)) _exit(81);
            pid_t member = child();
            if (member == 0) {
                if (read(release[0], &byte, 1) != 1) _exit(1);
                _exit(0);
            }
            BIT(getsid(member) == getpid() && getpgid(member) == getpid());
            errno = 0;
            BIT(setpgid(member, parent_group) == -1 && errno == EPERM); /* another session's group */
            BIT(setpgid(member, member) == 0 && getpgid(member) == member);
            BIT(setpgid(member, getpid()) == 0 && getpgid(member) == getpid());
            if (write(release[1], "x", 1) != 1) _exit(82);
            BIT(waitpid(member, &status, 0) == member && status == 0);
            /* A process whose PID names a group cannot start a session. */
            pid_t leader = child();
            if (leader == 0) {
                if (setpgid(0, 0)) _exit(2);
                errno = 0;
                _exit(setsid() == -1 && errno == EPERM ? 0 : 1);
            }
            BIT(waitpid(leader, &status, 0) == leader && status == 0);
            /* A member of a session can start its own. */
            pid_t starter = child();
            if (starter == 0) _exit(setsid() == getpid() && getsid(getppid()) == getppid() ? 0 : 1);
            BIT(waitpid(starter, &status, 0) == starter && status == 0);
#undef BIT
            if (write(bits_pipe[1], &bits, sizeof bits) != sizeof bits) _exit(83);
            if (read(go[0], &byte, 1) != 1) _exit(84);
            _exit(0);
        }
        int bits = 0;
        if (read(bits_pipe[0], &bits, sizeof bits) != sizeof bits) return 82;
        result("child", bits);
        result("child-sid", getsid(pid) == pid);
        errno = 0;
        result("other-session", setpgid(pid, getpgrp()));
        result("errno", errno);
        if (write(go[1], "x", 1) != 1) return 83;
        finish(pid);
        errno = 0;
        result("getsid-missing", getsid(0x3fffffff));
        result("errno", errno);
        result("getsid-self", getsid(0) == getsid(getpid()));
        return 0;
    }
    if (!strcmp(mode, "sysinfo")) {
        struct sysinfo info;
        result("sysinfo", sysinfo(&info));
        result("unit", info.mem_unit >= 1);
        result("ram", info.totalram > 0 && info.freeram <= info.totalram);
        result("procs", info.procs >= 1);
        errno = 0;
        result("fault", syscall(SYS_sysinfo, (void *)1));
        result("errno", errno);
        result("yield", sched_yield());
        result("groups", getgroups(0, NULL) >= 0);
        errno = 0;
        result("negative-groups", syscall(SYS_getgroups, -1, NULL));
        result("errno", errno);
        return 0;
    }
    if (!strcmp(mode, "seqpacket")) {
        int pair[2];
        result("socketpair", socketpair(AF_UNIX, SOCK_SEQPACKET, 0, pair));
        result("first", write(pair[0], "abc", 3));
        result("empty", write(pair[0], "", 0));
        result("second", write(pair[0], "defgh", 5));
        char buf[8] = {0};
        result("truncated", read(pair[1], buf, 2));
        result("start", buf[0] == 'a' && buf[1] == 'b');
        result("empty-read", read(pair[1], buf, 0));
        result("empty-message", read(pair[1], buf, sizeof buf));
        result("whole", read(pair[1], buf, sizeof buf));
        result("bytes", !memcmp(buf, "defgh", 5));
        fcntl(pair[1], F_SETFL, O_NONBLOCK);
        errno = 0;
        result("drained", read(pair[1], buf, sizeof buf));
        result("errno", errno);
        static char large[212961];
        errno = 0;
        result("too-large", write(pair[0], large, sizeof large));
        result("errno", errno);
        result("largest", write(pair[0], large, sizeof large - 1));
        result("read-largest", read(pair[1], large, sizeof large));
        close(pair[0]);
        result("eof", read(pair[1], buf, sizeof buf));
        close(pair[1]);
        return 0;
    }
    if (!strcmp(mode, "dgram")) {
        /* SIGPIPE comes only from SOCK_STREAM; count it instead of dying. */
        signal(SIGPIPE, interrupted);
        int pair[2];
        char buf[8] = {0};
        result("socketpair", socketpair(AF_UNIX, SOCK_DGRAM, 0, pair));
        result("first", write(pair[0], "abc", 3));
        result("empty", write(pair[0], "", 0));
        result("truncated", read(pair[1], buf, 2));
        result("start", buf[0] == 'a' && buf[1] == 'b');
        result("empty-message", read(pair[1], buf, sizeof buf));
        static char large[212961];
        errno = 0;
        result("too-large", write(pair[0], large, sizeof large));
        result("errno", errno);
        struct pollfd poll_fd = {pair[1], POLLIN | POLLOUT, 0};
        result("poll", poll(&poll_fd, 1, 0));
        result("revents", poll_fd.revents);
        /* A shutdown is this side's own: the peer still writes and gets no end of file. */
        result("shut-wr", shutdown(pair[0], SHUT_WR));
        errno = 0;
        result("after-shut-wr", write(pair[0], "x", 1));
        result("errno", errno);
        result("peer-writes", write(pair[1], "y", 1));
        result("read-own", read(pair[0], buf, sizeof buf));
        fcntl(pair[1], F_SETFL, O_NONBLOCK);
        errno = 0;
        result("no-eof", read(pair[1], buf, sizeof buf));
        result("errno", errno);
        result("shut-rd", shutdown(pair[1], SHUT_RD));
        poll_fd.revents = 0;
        result("poll-shut-rd", poll(&poll_fd, 1, 0));
        result("revents", poll_fd.revents);
        errno = 0;
        result("shut-rd-nonblocking", read(pair[1], buf, sizeof buf));
        result("errno", errno);
        fcntl(pair[1], F_SETFL, 0);
        result("shut-rd-blocking", read(pair[1], buf, sizeof buf));
        int closed[2];
        socketpair(AF_UNIX, SOCK_DGRAM, 0, closed);
        write(closed[1], "zz", 2);
        close(closed[1]);
        result("queued-after-close", read(closed[0], buf, sizeof buf));
        fcntl(closed[0], F_SETFL, O_NONBLOCK);
        errno = 0;
        result("no-eof-after-close", read(closed[0], buf, sizeof buf));
        result("errno", errno);
        struct pollfd closed_poll = {closed[0], POLLIN | POLLOUT, 0};
        result("poll-closed", poll(&closed_poll, 1, 0));
        result("revents", closed_poll.revents);
        errno = 0;
        result("refused", write(closed[0], "q", 1));
        result("errno", errno);
        errno = 0;
        result("not-connected", write(closed[0], "q", 1));
        result("errno", errno);
        int reader_shut[2];
        socketpair(AF_UNIX, SOCK_DGRAM, 0, reader_shut);
        shutdown(reader_shut[1], SHUT_RD);
        errno = 0;
        result("to-shut-rd", write(reader_shut[0], "a", 1));
        result("errno", errno);
        int packets[2];
        socketpair(AF_UNIX, SOCK_SEQPACKET, 0, packets);
        close(packets[1]);
        errno = 0;
        result("seqpacket-closed", write(packets[0], "a", 1));
        result("errno", errno);
        result("sigpipes", received);
        int stream[2];
        socketpair(AF_UNIX, SOCK_STREAM, 0, stream);
        close(stream[1]);
        errno = 0;
        result("stream-closed", write(stream[0], "a", 1));
        result("errno", errno);
        result("stream-sigpipes", received);
        return 0;
    }
    if (!strcmp(mode, "socket-addresses")) {
        int stream[2], packets[2], datagram[2], pipe_fds[2];
        socketpair(AF_UNIX, SOCK_STREAM, 0, stream);
        socketpair(AF_UNIX, SOCK_SEQPACKET, 0, packets);
        socketpair(AF_UNIX, SOCK_DGRAM, 0, datagram);
        pipe(pipe_fds);
        struct sockaddr_un address = {.sun_family = AF_UNIX};
        char buf[16] = {0};
        int length = 77;
        outcome("stream-address", send_to(stream[0], "a", 1, 0, &address, sizeof address));
        outcome("stream-no-length", send_to(stream[0], "b", 1, 0, &address, 0));
        outcome("too-long", send_to(stream[0], "c", 1, 0, &address, 129));
        outcome("negative", send_to(stream[0], "c", 1, 0, &address, -1));
        outcome("bad-address", send_to(stream[0], "c", 1, 0, (void *)8, 16));
        outcome("flags", send_to(stream[0], "d", 1, MSG_DONTWAIT | MSG_NOSIGNAL, NULL, 0));
        outcome("received", receive_from(stream[1], buf, sizeof buf, 0, &address, &length));
        printf("data=%s length=%d\n", buf, length);
        outcome("empty", receive_from(stream[1], buf, sizeof buf, MSG_DONTWAIT, NULL, NULL));
        send_to(stream[0], "ef", 2, 0, NULL, 0);
        length = -1;
        outcome("negative-length", receive_from(stream[1], buf, 1, 0, &address, &length));
        printf("length=%d\n", length);
        outcome("no-length", receive_from(stream[1], buf, 1, 0, &address, NULL));
        outcome("drained", receive_from(stream[1], buf, sizeof buf, MSG_DONTWAIT, NULL, NULL));
        outcome("packet-address", send_to(packets[0], "gh", 2, 0, &address, sizeof address));
        send_to(packets[0], "ij", 2, 0, NULL, 0);
        outcome("packet-empty-buffer", receive_from(packets[1], buf, 0, 0, NULL, NULL));
        memset(buf, 0, sizeof buf);
        outcome("packet-next", receive_from(packets[1], buf, 1, 0, NULL, NULL));
        printf("data=%s\n", buf);
        outcome("packet-drained", receive_from(packets[1], buf, sizeof buf, MSG_DONTWAIT, NULL, NULL));
        outcome("family-only", send_to(datagram[0], "k", 1, 0, &address, 2));
        strcpy(address.sun_path, "/missing-socket");
        outcome("missing", send_to(datagram[0], "k", 1, 0, &address, sizeof address));
        /* Writable by everyone, so the write check passes without root. */
        strcpy(address.sun_path, "/tmp");
        outcome("not-a-socket", send_to(datagram[0], "k", 1, 0, &address, sizeof address));
        /* A descriptor that comes to recvfrom closes: the pipe loses its writer. */
        send_fds(datagram[0], "l", 1, &pipe_fds[1], 1);
        close(pipe_fds[1]);
        outcome("with-fds", receive_from(datagram[1], buf, sizeof buf, 0, NULL, NULL));
        outcome("pipe", read(pipe_fds[0], buf, 1));
        outcome("not-a-socket-fd", send_to(pipe_fds[0], "m", 1, 0, NULL, 0));
        outcome("recv-not-a-socket", receive_from(pipe_fds[0], buf, 1, 0, NULL, NULL));
        /* A buffer past the user half fails before the descriptor and the
           address are checked. */
        /* In the kernel half: past the user half with four-level page tables
           and with five-level ones, whose end the host decides. */
        char *high = (char *)0xffff800000000000;
        outcome("high-not-a-socket", send_to(pipe_fds[0], high, 1, 0, NULL, 0));
        outcome("high-bad-fd", receive_from(999, high, 2, 0, NULL, NULL));
        outcome("high-too-long", send_to(stream[0], high, 1, 0, &address, 129));
        outcome("unmapped-too-long", send_to(stream[0], (char *)8, 1, 0, &address, 129));
        /* A stream's address and a datagram's form and size are checked
           before the data is copied, and a datagram's peer is looked up
           after. */
        char *unmapped = (char *)8;
        outcome("unmapped-stream", send_to(stream[0], unmapped, 1, 0, &address, sizeof address));
        outcome("unmapped-family", send_to(datagram[0], unmapped, 1, 0, &address, 2));
        outcome("unmapped-huge", send_to(datagram[0], unmapped, 1 << 20, 0, &address, sizeof address));
        outcome("unmapped-datagram", send_to(datagram[0], unmapped, 1, 0, &address, sizeof address));
        struct iovec unmapped_iov = {unmapped, 1};
        struct msghdr unmapped_message = {
            .msg_name = &address, .msg_namelen = sizeof address,
            .msg_iov = &unmapped_iov, .msg_iovlen = 1,
        };
        errno = 0;
        outcome("unmapped-message", sendmsg(datagram[0], &unmapped_message, 0));
        errno = 0;
        outcome("unmapped-stream-message", sendmsg(stream[0], &unmapped_message, 0));
        return 0;
    }
    if (!strcmp(mode, "signal-io")) {
        /* The case names its own group, which the emulated first process,
           like a PID namespace's, is not in until it makes one. */
        if (setpgid(0, 0)) return 80;
        /* O_ASYNC: a pipe or socket signals its F_SETOWN owner as it
           changes, with SIGIO or F_SETSIG's signal (code, band and fd);
           F_SETOWN works on any file, O_ASYNC stays only on these. The
           signals stay blocked and are taken with sigtimedwait. */
        sigset_t set;
        sigemptyset(&set);
        sigaddset(&set, SIGIO);
        sigaddset(&set, SIGURG);
        sigaddset(&set, IO_RT);
        sigprocmask(SIG_BLOCK, &set, NULL);
        int p[2], sv[2], status;
        char buf[64];
        pid_t pid = getpid(), forked;
        puts("flags");
        if (pipe(p)) return 79;
        socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
        int file = open(self, O_RDONLY), event = eventfd(0, 0), null = open("/dev/null", O_RDWR);
        int fds[] = {p[0], sv[0], file, event, null};
        const char *names[] = {"pipe", "socket", "file", "eventfd", "null"};
        for (int k = 0; k < 5; k++) {
            struct f_owner_ex fresh;
            memset(&fresh, 0x55, sizeof fresh);
            fcntl(fds[k], F_GETOWN_EX, &fresh);
            int fresh_sig = fcntl(fds[k], F_GETSIG), fresh_own = fcntl(fds[k], F_GETOWN);
            long set_flags = fcntl(fds[k], F_SETFL, O_ASYNC | O_NONBLOCK);
            int flags = fcntl(fds[k], F_GETFL) & (O_ASYNC | O_NONBLOCK);
            long own = fcntl(fds[k], F_SETOWN, pid);
            printf("  %s fresh=%d/%d/%d/%d setfl=%ld flags=%#x setown=%ld getown=%d\n", names[k], fresh.type, fresh.pid,
                   fresh_sig, fresh_own, set_flags, flags, own, fcntl(fds[k], F_GETOWN) == pid);
            fcntl(fds[k], F_SETFL, 0);
        }
        puts("owner");
        struct f_owner_ex owner;
        pid_t tid = syscall(SYS_gettid), group = getpgrp();
#define IO_EX(name, kind, id) do { owner.type = (kind); owner.pid = (id); errno = 0; long r = fcntl(file, F_SETOWN_EX, &owner); \
        int e = r < 0 ? errno : 0; memset(&owner, 0x55, sizeof owner); fcntl(file, F_GETOWN_EX, &owner); \
        pid_t expected = owner.type == F_OWNER_PGRP ? group : pid; \
        printf("  %s=%ld errno=%d type=%d id=%s getown=%s\n", name, r, e, owner.type, \
               owner.pid == 0 ? "none" : owner.pid == expected ? "owner" : "other", io_owner(file)); } while (0)
        IO_EX("tid", F_OWNER_TID, tid);
        IO_EX("pid", F_OWNER_PID, pid);
        IO_EX("pgrp", F_OWNER_PGRP, group);
        IO_EX("type3", 3, pid);
        IO_EX("type-1", -1, pid);
        IO_EX("missing", F_OWNER_PID, 999999);
        IO_EX("negative", F_OWNER_PID, -pid);
        IO_EX("zero", F_OWNER_PID, 0);
        IO_EX("tid-zero", F_OWNER_TID, 0);
#undef IO_EX
        long r;
#define IO_OWN(name, value) do { errno = 0; r = fcntl(file, F_SETOWN, value); int e = r < 0 ? errno : 0; \
        memset(&owner, 0x55, sizeof owner); fcntl(file, F_GETOWN_EX, &owner); \
        printf("  setown-%s=%ld errno=%d type=%d getown=%s\n", name, r, e, owner.type, io_owner(file)); } while (0)
        IO_OWN("self", pid);
        IO_OWN("missing", 999999);
        IO_OWN("min", INT_MIN);
        IO_OWN("zero", 0);
#undef IO_OWN
        r = fcntl(file, F_SETOWN, -group);
        printf("  setown-group=%ld getown=%d\n", r, fcntl(file, F_GETOWN) == -group);
        errno = 0;
        r = fcntl(file, F_GETOWN_EX, (void *)8);
        printf("  getown-ex-fault=%ld errno=%d\n", r, errno);
        errno = 0;
        r = fcntl(file, F_SETOWN_EX, (void *)8);
        printf("  setown-ex-fault=%ld errno=%d\n", r, errno);
        puts("setsig");
        long numbers[] = {29, 64, 65, -1, 9, 0};
        for (int k = 0; k < 6; k++) {
            errno = 0;
            r = fcntl(file, F_SETSIG, numbers[k]);
            printf("  %ld=%ld errno=%d get=%d\n", numbers[k], r, r < 0 ? errno : 0, fcntl(file, F_GETSIG));
        }
        close(p[0]); close(p[1]); close(sv[0]); close(sv[1]);
        puts("pipe-reader");
        if (pipe(p)) return 79;
        io_async(p[0], 0);
        if (write(p[1], "a", 1) != 1) return 78;
        io_taken("write");
        if (write(p[1], "bc", 2) != 2) return 78;
        if (write(p[1], "d", 1) != 1) return 78;
        io_taken("two-writes");
        if (write(p[1], "", 0) != 0) return 78;
        io_taken("empty-write");
        if (read(p[0], buf, 1) != 1) return 77;
        io_taken("read");
        fcntl(p[0], F_SETSIG, IO_RT);
        if (write(p[1], "e", 1) != 1) return 78;
        if (write(p[1], "f", 1) != 1) return 78;
        io_taken("rt-writes");
        int copy = dup(p[0]);
        if (write(p[1], "g", 1) != 1) return 78;
        io_taken("dup");
        close(copy);
        close(p[1]);
        io_taken("close-writer");
        close(p[0]);
        puts("pipe-writer");
        if (pipe(p)) return 79;
        io_async(p[1], IO_RT);
        if (write(p[1], "a", 1) != 1) return 78;
        io_taken("write");
        if (read(p[0], buf, 1) != 1) return 77;
        io_taken("read");
        if (read(p[0], buf, 0) != 0) return 77;
        io_taken("empty-read");
        fcntl(p[0], F_SETFL, O_NONBLOCK);
        errno = 0;
        r = read(p[0], buf, 1);
        printf("  nothing=%ld errno=%d\n", r, errno);
        io_taken("nothing");
        close(p[0]);
        io_taken("close-reader");
        close(p[1]);
        puts("pipe-full");
        if (pipe(p)) return 79;
        io_async(p[0], IO_RT);
        fcntl(p[1], F_SETFL, O_NONBLOCK);
        static char chunk[4096];
        int writes = 0;
        while (write(p[1], chunk, sizeof chunk) > 0) writes++;
        errno = 0;
        r = write(p[1], "x", 1);
        printf("  full=%ld errno=%d in=%d\n", r, errno, io_count(POLL_IN) == writes + 2);
        close(p[0]); close(p[1]);
        puts("pipe-blocking");
        /* A blocking read signals the writer once, as it ends; a blocking
           write the reader once before it waits and once as it ends. A
           child moves the data, after a while for the read. */
        if (pipe(p)) return 79;
        io_async(p[1], IO_RT);
        forked = child();
        if (forked < 0) return 76;
        if (!forked) {
            usleep(200000);
            _exit(write(p[1], "x", 1) == 1 ? 0 : 1);
        }
        if (read(p[0], buf, 1) != 1) return 77;
        waitpid(forked, &status, 0);
        printf("  read out=%d\n", io_count(POLL_OUT));
        close(p[0]); close(p[1]);
        /* The write fills the pipe, waits, and ends, as the child reads
           only a full pipe, whichever process runs first. */
        if (pipe(p)) return 79;
        io_async(p[0], IO_RT);
        int size = fcntl(p[0], F_GETPIPE_SZ);
        char *big = calloc(1, size + sizeof chunk);
        if (size <= 0 || !big) return 75;
        forked = child();
        if (forked < 0) return 76;
        if (!forked) {
            struct pollfd full = {p[1], POLLOUT, 0};
            while (poll(&full, 1, 0) != 0)
                if (full.revents != POLLOUT) _exit(2);
            _exit(read(p[0], chunk, sizeof chunk) == sizeof chunk ? 0 : 1);
        }
        if (write(p[1], big, size + sizeof chunk) != size + (long)sizeof chunk) return 78;
        free(big);
        waitpid(forked, &status, 0);
        printf("  write in=%d\n", io_count(POLL_IN));
        close(p[0]); close(p[1]);
        puts("pipe-owners");
        if (pipe(p)) return 79;
        fcntl(p[0], F_SETFL, O_ASYNC);
        if (write(p[1], "a", 1) != 1) return 78;
        io_taken("none");
        fcntl(p[0], F_SETFL, 0);
        fcntl(p[0], F_SETOWN, pid);
        if (write(p[1], "a", 1) != 1) return 78;
        io_taken("no-async");
        fcntl(p[0], F_SETFL, O_ASYNC);
        io_taken("set");
        if (write(p[1], "a", 1) != 1) return 78;
        io_taken("async");
        fcntl(p[0], F_SETFL, 0);
        if (write(p[1], "a", 1) != 1) return 78;
        io_taken("cleared");
        fcntl(p[0], F_SETSIG, IO_RT);
        fcntl(p[0], F_SETFL, O_ASYNC);
        /* A group owner signals every process in the group, here only a
           child in a group of its own, whose mask keeps the signal. */
        fflush(stdout);
        forked = child();
        if (forked < 0) return 76;
        if (!forked) {
            setpgid(0, 0);
            fcntl(p[0], F_SETOWN, -getpid());
            if (write(p[1], "a", 1) != 1) _exit(1);
            io_taken("group");
            fflush(stdout);
            _exit(0);
        }
        waitpid(forked, &status, 0);
        printf("  group-child=%d\n", status);
        fcntl(p[0], F_SETOWN, pid);
        owner.type = F_OWNER_TID;
        owner.pid = tid;
        fcntl(p[0], F_SETOWN_EX, &owner);
        if (write(p[1], "a", 1) != 1) return 78;
        io_taken("thread");
        forked = child();
        if (forked < 0) return 76;
        if (!forked) _exit(fcntl(p[0], F_SETSIG, 0) ? 1 : 0);
        waitpid(forked, &status, 0);
        printf("  shared-setsig=%d\n", fcntl(p[0], F_GETSIG));
        close(p[0]); close(p[1]);
        puts("child");
        int ready[2];
        if (pipe(p) || pipe(ready)) return 79;
        forked = child();
        if (forked < 0) return 76;
        if (!forked) {
            sigset_t none;
            sigemptyset(&none);
            sigprocmask(SIG_SETMASK, &none, NULL);
            if (write(ready[1], "r", 1) != 1) _exit(4);
            for (;;) pause();
        }
        if (read(ready[0], buf, 1) != 1) return 77;
        fcntl(p[0], F_SETOWN, forked);
        fcntl(p[0], F_SETFL, O_ASYNC);
        if (write(p[1], "a", 1) != 1) return 78;
        waitpid(forked, &status, 0);
        printf("  killed=%d signal=%d\n", WIFSIGNALED(status), WIFSIGNALED(status) ? WTERMSIG(status) : -1);
        close(p[0]); close(p[1]); close(ready[0]); close(ready[1]);
        puts("stream");
        socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
        io_async(sv[0], IO_RT);
        io_async(sv[1], IO_RT);
        send(sv[0], "ab", 2, 0);
        io_taken("send");
        recv(sv[1], buf, 2, 0);
        io_taken("recv");
        send(sv[0], "", 0, 0);
        io_taken("empty-send");
        send(sv[0], "z", 1, MSG_OOB);
        io_taken("oob");
        recv(sv[1], buf, 1, MSG_OOB);
        io_taken("oob-recv");
        fcntl(sv[1], F_SETSIG, 0);
        send(sv[0], "cz", 2, MSG_OOB);
        io_taken("oob-sigio");
        fcntl(sv[1], F_SETSIG, IO_RT);
        recv(sv[1], buf, sizeof buf, MSG_DONTWAIT);
        io_taken("read-rest");
        send(sv[1], "r", 1, 0);
        io_taken("reverse");
        recv(sv[0], buf, 1, 0);
        fcntl(sv[0], F_SETFL, O_NONBLOCK | O_ASYNC);
        int sends = 0;
        while (send(sv[0], chunk, sizeof chunk, 0) > 0) sends++;
        while (send(sv[0], chunk, 1, 0) > 0) sends++;
        printf("  filled in=%d\n", io_count(POLL_IN) == sends);
        fcntl(sv[1], F_SETFL, O_NONBLOCK | O_ASYNC);
        while (recv(sv[1], chunk, sizeof chunk, 0) > 0) {}
        io_taken("drained");
        errno = 0;
        r = recv(sv[1], buf, 1, 0);
        printf("  nothing=%ld errno=%d\n", r, errno);
        io_taken("nothing");
        shutdown(sv[0], SHUT_WR);
        io_taken("shut-wr");
        shutdown(sv[0], SHUT_RD);
        io_taken("shut-rd");
        close(sv[0]);
        io_taken("close");
        close(sv[1]);
        socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
        io_async(sv[0], IO_RT);
        io_async(sv[1], IO_RT);
        shutdown(sv[0], SHUT_RDWR);
        io_taken("shut-rdwr");
        close(sv[1]);
        io_taken("close-after-shutdown");
        close(sv[0]);
        puts("datagram");
        socketpair(AF_UNIX, SOCK_DGRAM, 0, sv);
        io_async(sv[0], IO_RT);
        io_async(sv[1], IO_RT);
        send(sv[0], "a", 1, 0);
        io_taken("send");
        send(sv[0], "", 0, 0);
        io_taken("empty-send");
        recv(sv[1], buf, 1, 0);
        recv(sv[1], buf, 1, 0);
        io_taken("recv");
        shutdown(sv[0], SHUT_WR);
        io_taken("shut-wr");
        shutdown(sv[0], SHUT_RDWR);
        io_taken("shut-rdwr");
        close(sv[0]);
        io_taken("close");
        close(sv[1]);
        puts("seqpacket");
        socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv);
        io_async(sv[0], IO_RT);
        io_async(sv[1], IO_RT);
        send(sv[0], "a", 1, 0);
        io_taken("send");
        shutdown(sv[0], SHUT_WR);
        io_taken("shut-wr");
        shutdown(sv[0], SHUT_RD);
        io_taken("shut-rd");
        close(sv[0]);
        io_taken("close");
        close(sv[1]);
        puts("other-files");
        uint64_t one = 1;
        io_async(event, IO_RT);
        if (write(event, &one, sizeof one) != sizeof one) return 75;
        io_taken("eventfd");
        io_async(null, IO_RT);
        if (write(null, "a", 1) != 1) return 75;
        io_taken("null");
        return 0;
    }
    if (!strcmp(mode, "signal-io-wait")) {
        /* The O_ASYNC signals around waits. A stream whose reader waits
           gets none for the data, the peer's shutdown or its close that
           ends the wait (Linux's SOCKWQ_ASYNC_WAITDATA), where a datagram
           or packet socket still signals. Linux signals one whose reader
           ran before the sender looked, so an attempt whose reader was
           signalled is taken again, and the last of up to ten is printed
           as it is. A send that found the buffer full signals POLL_OUT
           only once three quarters of it is free. A pipe write signals
           its reader before each wait. A reader's child acts after a
           while (io_pause). */
        sigset_t set;
        sigemptyset(&set);
        sigaddset(&set, SIGIO);
        sigaddset(&set, SIGURG);
        sigaddset(&set, IO_RT);
        sigprocmask(SIG_BLOCK, &set, NULL);
        int sv[2], p[2], go[2], status;
        char buf[64];
        pid_t forked;
        struct timeval limit = {5, 0};
        puts("waiting-reader");
        int types[] = {SOCK_STREAM, SOCK_DGRAM, SOCK_SEQPACKET};
        const char *type_names[] = {"stream", "dgram", "seqpacket"};
        const char *actions[] = {"send", "shut-wr", "close"};
        for (int t = 0; t < 3; t++) {
            /* A datagram socket neither ends nor hangs up, so its reader
               would wait for good. */
            for (int a = 0, tries = 0; a < (types[t] == SOCK_DGRAM ? 1 : 3); a++) {
                /* The child keeps its end open until the signals are
                   taken, so that only the close case hangs up. A read
                   ends as soon as the data comes, before the send has
                   signalled, so the signals are taken only once the child
                   has acted (`acted`, or its exit for a close). */
                int acted[2];
                if (socketpair(AF_UNIX, types[t], 0, sv) || pipe(go) || pipe(acted)) return 74;
                setsockopt(sv[1], SOL_SOCKET, SO_RCVTIMEO, &limit, sizeof limit);
                io_async(sv[1], IO_RT);
                fflush(stdout);
                forked = child();
                if (forked < 0) return 76;
                if (!forked) {
                    io_pause();
                    int done = a == 0 ? send(sv[0], "a", 1, 0) != 1 : a == 1 ? shutdown(sv[0], SHUT_WR) : 0;
                    if (a != 2 && (write(acted[1], "a", 1) != 1 || read(go[0], buf, 1) != 1)) _exit(2);
                    _exit(done);
                }
                if (a == 2) close(sv[0]);
                /* A busy host can keep the reader from reaching recv
                   before the child acts. Then the reader does not wait
                   and the signal is due, so the attempt is taken again.
                   So it is when a stream's reader is signalled: Linux's
                   sock_def_readable (a send), unix_shutdown (a
                   shutdown) and unix_release_sock (a close) wake the
                   reader before they look at SOCKWQ_ASYNC_WAITDATA
                   (sk_wake_async), so what came before the reader slept,
                   or whose reader ran at once and cleared it, signals,
                   and what found the reader waiting and not yet run does
                   not. Up to ten
                   attempts give the second on Linux, so the emulator
                   must give it too. */
                struct pollfd ready = {sv[1], POLLIN | POLLRDHUP, 0};
                int early = poll(&ready, 1, 0) != 0;
                long r = recv(sv[1], buf, sizeof buf, 0);
                char name[32];
                snprintf(name, sizeof name, "%s-%s=%ld", type_names[t], actions[a], r);
                if (a == 2) waitpid(forked, &status, 0);
                else if (read(acted[0], buf, 1) != 1) return 72;
                sigset_t pending;
                sigpending(&pending);
                int again = (early || (types[t] == SOCK_STREAM && sigismember(&pending, IO_RT)))
                            && ++tries < 10;
                if (again) io_count(0);
                else io_taken(name);
                close(sv[1]);
                if (a != 2) {
                    if (write(go[1], "g", 1) != 1) return 78;
                    waitpid(forked, &status, 0);
                }
                if (status) return 73;
                if (a != 2) close(sv[0]);
                close(go[0]); close(go[1]); close(acted[0]); close(acted[1]);
                if (again) a--;
                else tries = 0;
            }
        }
        /* A reader that does not wait gets the signal. */
        socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
        io_async(sv[1], IO_RT);
        send(sv[0], "a", 1, 0);
        io_taken("not-waiting");
        close(sv[0]); close(sv[1]);
        puts("full");
        static char chunk[8192];
        socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
        io_async(sv[0], IO_RT);
        fcntl(sv[0], F_SETFL, O_NONBLOCK | O_ASYNC);
        long total = 0, r;
        while ((r = send(sv[0], chunk, 4096, 0)) > 0) total += r;
        while ((r = send(sv[0], chunk, 1, 0)) > 0) total += r;
        printf("  filled=%d\n", total > 0);
        if (recv(sv[1], chunk, 1, 0) != 1) return 77;
        printf("  one out=%d\n", io_count(POLL_OUT));
        long taken = 1;
        while (taken < total / 2 && (r = recv(sv[1], chunk, total / 2 - taken < 4096 ? total / 2 - taken : 4096, 0)) > 0)
            taken += r;
        printf("  half out=%d\n", io_count(POLL_OUT));
        while (taken < total && (r = recv(sv[1], chunk, 4096, 0)) > 0) taken += r;
        printf("  all=%d out=%d\n", taken == total, io_count(POLL_OUT));
        close(sv[0]); close(sv[1]);
        /* A full datagram or packet socket that a poll, select or
           epoll_ctl asks to write signals POLL_OUT once read, as one whose
           send failed does; filled with no failed send and no such
           question, or failed before O_ASYNC, it signals nothing. An
           epoll_wait asks only of what is on its ready list: a level-
           triggered interest it reported writable before the socket filled
           is, an edge-triggered one is not. */
        puts("polled-full");
        const char *ways[] = {"poll", "select", "epoll", "sent", "no-async", "epoll-wait", "epoll-wait-et"};
        for (int t = 1; t < 3; t++) {
            int fit = 0;
            if (socketpair(AF_UNIX, types[t], 0, sv)) return 74;
            fcntl(sv[0], F_SETFL, O_NONBLOCK);
            while (send(sv[0], chunk, 256, 0) == 256) fit++;
            close(sv[0]); close(sv[1]);
            for (int w = 0; w < 7; w++) {
                if (socketpair(AF_UNIX, types[t], 0, sv)) return 74;
                if (w != 4) io_async(sv[0], IO_RT);
                fcntl(sv[0], F_SETFL, fcntl(sv[0], F_GETFL) | O_NONBLOCK);
                struct epoll_event got;
                int waiting = -1;
                if (w >= 5 && (waiting = epoll_create1(0)) >= 0) {
                    struct epoll_event wanted = {.events = EPOLLOUT | (w == 6 ? EPOLLET : 0)};
                    epoll_ctl(waiting, EPOLL_CTL_ADD, sv[0], &wanted);
                    if (epoll_wait(waiting, &got, 1, 0) != 1) return 71;
                }
                int sent = 0;
                while (sent < fit && send(sv[0], chunk, 256, 0) == 256) sent++;
                struct pollfd out = {sv[0], POLLOUT, 0};
                fd_set writes;
                FD_ZERO(&writes);
                FD_SET(sv[0], &writes);
                struct timespec zero = {0, 0};
                struct epoll_event event = {.events = EPOLLOUT};
                int e;
                if (w == 0) poll(&out, 1, 0);
                if (w == 1) pselect(sv[0] + 1, NULL, &writes, NULL, &zero, NULL);
                if (w == 2 && (e = epoll_create1(0)) >= 0) {
                    epoll_ctl(e, EPOLL_CTL_ADD, sv[0], &event);
                    close(e);
                }
                if (w == 4) {
                    send(sv[0], chunk, 256, 0);
                    io_async(sv[0], IO_RT);
                }
                if (waiting >= 0 && epoll_wait(waiting, &got, 1, 0) != 0) return 70;
                io_count(POLL_OUT);
                while (recv(sv[1], chunk, 256, MSG_DONTWAIT) > 0) {}
                printf("  %s-%s filled=%d out=%d\n", type_names[t], ways[w], sent == fit,
                       io_count(POLL_OUT));
                if (waiting >= 0) close(waiting);
                close(sv[0]); close(sv[1]);
            }
        }
        puts("pipe");
        /* The write fills the pipe three times, as the child reads only
           a full pipe, so its count does not hang on which runs first. */
        if (pipe(p)) return 79;
        io_async(p[0], IO_RT);
        int size = fcntl(p[0], F_GETPIPE_SZ);
        char *big = calloc(1, size + 8192);
        if (size <= 0 || !big) return 75;
        fflush(stdout);
        forked = child();
        if (forked < 0) return 76;
        if (!forked) {
            for (int k = 0; k < 2; k++) {
                struct pollfd full = {p[1], POLLOUT, 0};
                while (poll(&full, 1, 0) != 0)
                    if (full.revents != POLLOUT) _exit(2);
                if (read(p[0], chunk, 4096) != 4096) _exit(1);
            }
            _exit(0);
        }
        r = write(p[1], big, size + 8192);
        free(big);
        waitpid(forked, &status, 0);
        printf("  write=%d in=%d child=%d\n", r == size + 8192, io_count(POLL_IN), status);
        close(p[0]); close(p[1]);
        return 0;
    }
    if (!strcmp(mode, "signal-restart")) {
        /* A handler with SA_RESTART runs a blocking read, recv or write it
           interrupted again (ERESTARTSYS); without it the call is EINTR.
           poll, select and pause are EINTR either way (ERESTARTNOHAND), as
           is a wait that SO_SNDTIMEO limits. */
        char buf[8];
        int p[2], sv[2];
#define RESTART_CASE(name, fd, drain, call) do { \
        restart_fd = (fd); restart_drain = (drain); received = 0; \
        struct itimerval it = {{0, 0}, {0, 100000}}; setitimer(ITIMER_REAL, &it, NULL); \
        errno = 0; long r = (call); int e = r < 0 ? errno : 0; \
        printf("  %s=%ld errno=%d signal=%d\n", name, r, e, (int)received); } while (0)
        for (int restart = 0; restart < 2; restart++) {
            puts(restart ? "restart" : "no-restart");
            struct sigaction sa = {0};
            sa.sa_handler = restart_feed;
            sa.sa_flags = restart ? SA_RESTART : 0;
            sigaction(SIGALRM, &sa, NULL);
            if (pipe(p)) return 79;
            RESTART_CASE("read", p[1], 0, read(p[0], buf, sizeof buf));
            close(p[0]); close(p[1]);
            if (pipe(p)) return 79;
            struct iovec iov = {buf, sizeof buf};
            RESTART_CASE("readv", p[1], 0, readv(p[0], &iov, 1));
            close(p[0]); close(p[1]);
            socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
            RESTART_CASE("socket-read", sv[0], 0, read(sv[1], buf, sizeof buf));
            close(sv[0]); close(sv[1]);
            socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
            RESTART_CASE("recv", sv[0], 0, recv(sv[1], buf, sizeof buf, 0));
            close(sv[0]); close(sv[1]);
            socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
            RESTART_CASE("recvfrom", sv[0], 0, recvfrom(sv[1], buf, sizeof buf, 0, NULL, NULL));
            close(sv[0]); close(sv[1]);
            socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
            struct msghdr message = {.msg_iov = &iov, .msg_iovlen = 1};
            RESTART_CASE("recvmsg", sv[0], 0, recvmsg(sv[1], &message, 0));
            close(sv[0]); close(sv[1]);
            socketpair(AF_UNIX, SOCK_DGRAM, 0, sv);
            RESTART_CASE("datagram-recv", sv[0], 0, recv(sv[1], buf, sizeof buf, 0));
            close(sv[0]); close(sv[1]);
            if (pipe(p)) return 79;
            struct pollfd pfd = {p[0], POLLIN, 0};
            RESTART_CASE("poll", p[1], 0, poll(&pfd, 1, -1));
            close(p[0]); close(p[1]);
            if (pipe(p)) return 79;
            fd_set set;
            FD_ZERO(&set);
            FD_SET(p[0], &set);
            RESTART_CASE("select", p[1], 0, select(p[0] + 1, &set, NULL, NULL, NULL));
            close(p[0]); close(p[1]);
            RESTART_CASE("pause", -1, 0, pause());
            if (pipe(p)) return 79;
            restart_fill(p[1]);
            fcntl(p[0], F_SETFL, O_NONBLOCK);
            RESTART_CASE("write", p[0], 1, write(p[1], "y", 1));
            close(p[0]); close(p[1]);
            socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
            restart_fill(sv[0]);
            fcntl(sv[1], F_SETFL, O_NONBLOCK);
            RESTART_CASE("send", sv[1], 1, send(sv[0], "y", 1, 0));
            close(sv[0]); close(sv[1]);
            /* SO_SNDTIMEO limits the wait, so the signal is EINTR. */
            struct timeval tv = {2, 0};
            socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
            setsockopt(sv[0], SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
            restart_fill(sv[0]);
            fcntl(sv[1], F_SETFL, O_NONBLOCK);
            RESTART_CASE("timed-write", sv[1], 1, write(sv[0], "y", 1));
            close(sv[0]); close(sv[1]);
            socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
            setsockopt(sv[0], SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
            restart_fill(sv[0]);
            fcntl(sv[1], F_SETFL, O_NONBLOCK);
            RESTART_CASE("timed-send", sv[1], 1, send(sv[0], "y", 1, 0));
            close(sv[0]); close(sv[1]);
        }
#undef RESTART_CASE
        return 0;
    }
    if (!strcmp(mode, "socket-timeouts")) {
        /* SO_RCVTIMEO and SO_SNDTIMEO: kept in ticks, a zero timeval waits
           for ever and a negative one not at all; a blocking call that
           waits past one gives EAGAIN, or what it moved, and a signal that
           ends such a wait is EINTR even with SA_RESTART. Only values that
           every tick rate keeps exactly are used, and times are checked
           against the timeout rather than printed. */
        int sv[2];
        char buf[16];
        long n;
        socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
#define TIMEO_SET(fd, opt, sec, usec, size) do { struct timeval tv = {sec, usec}; errno = 0; \
        n = setsockopt(fd, SOL_SOCKET, opt, &tv, size); int e = n < 0 ? errno : 0; \
        struct timeval got = {-7, -7}; socklen_t len = sizeof got; getsockopt(fd, SOL_SOCKET, opt, &got, &len); \
        printf("  set %ld.%06ld=%ld errno=%d got=%ld.%06ld len=%u\n", (long)(sec), (long)(usec), n, e, (long)got.tv_sec, (long)got.tv_usec, len); } while (0)
#define TIMEO_SINCE(t0) ({ struct timespec t1; clock_gettime(CLOCK_MONOTONIC, &t1); \
        (t1.tv_sec - (t0).tv_sec) * 1000 + (t1.tv_nsec - (t0).tv_nsec) / 1000000; })
        struct timespec t0;
        long ms;
        puts("values");
        TIMEO_SET(sv[0], SO_RCVTIMEO, 0, 250000, 16);
        TIMEO_SET(sv[0], SO_RCVTIMEO, 2, 500000, 16);
        TIMEO_SET(sv[0], SO_RCVTIMEO, 0, 1000000, 16);
        TIMEO_SET(sv[0], SO_RCVTIMEO, 0, -1, 16);
        TIMEO_SET(sv[0], SO_RCVTIMEO, -1, 0, 16);
        TIMEO_SET(sv[0], SO_RCVTIMEO, 0, 0, 16);
        TIMEO_SET(sv[0], SO_RCVTIMEO, 1, 0, 8);
        TIMEO_SET(sv[0], SO_RCVTIMEO, 1, 0, 24);
        TIMEO_SET(sv[0], SO_SNDTIMEO, 3, 0, 16);
        TIMEO_SET(sv[0], 66, 0, 500000, 16);
        TIMEO_SET(sv[0], 67, 4, 0, 16);
        puts("receive");
        TIMEO_SET(sv[1], SO_RCVTIMEO, 0, 200000, 16);
        clock_gettime(CLOCK_MONOTONIC, &t0);
        errno = 0;
        n = recv(sv[1], buf, 8, 0);
        ms = TIMEO_SINCE(t0);
        printf("  recv=%ld errno=%d waited=%d\n", n, n < 0 ? errno : 0, ms >= 200 && ms < 5000);
        clock_gettime(CLOCK_MONOTONIC, &t0);
        errno = 0;
        n = read(sv[1], buf, 8);
        ms = TIMEO_SINCE(t0);
        printf("  read=%ld errno=%d waited=%d\n", n, n < 0 ? errno : 0, ms >= 200 && ms < 5000);
        send(sv[0], "ab", 2, 0);
        clock_gettime(CLOCK_MONOTONIC, &t0);
        n = recv(sv[1], buf, 8, MSG_WAITALL);
        ms = TIMEO_SINCE(t0);
        printf("  waitall=%ld waited=%d\n", n, ms >= 200 && ms < 5000);
        TIMEO_SET(sv[1], SO_RCVTIMEO, -1, 0, 16);
        errno = 0;
        n = recv(sv[1], buf, 8, 0);
        printf("  no-wait=%ld errno=%d\n", n, n < 0 ? errno : 0);
        puts("signal");
        struct sigaction sa = {0};
        sa.sa_handler = interrupted;
        sa.sa_flags = SA_RESTART;
        sigaction(SIGALRM, &sa, NULL);
        TIMEO_SET(sv[1], SO_RCVTIMEO, 2, 0, 16);
        struct itimerval it = {{0, 0}, {0, 100000}};
        setitimer(ITIMER_REAL, &it, NULL);
        errno = 0;
        n = recv(sv[1], buf, 8, 0);
        printf("  recv=%ld errno=%d\n", n, n < 0 ? errno : 0);
        signal(SIGALRM, SIG_DFL);
        puts("send");
        TIMEO_SET(sv[0], SO_SNDTIMEO, 0, 200000, 16);
        static char big[1 << 20];
        clock_gettime(CLOCK_MONOTONIC, &t0);
        n = send(sv[0], big, sizeof big, 0);
        ms = TIMEO_SINCE(t0);
        printf("  send=%d waited=%d\n", n > 0 && n < (long)sizeof big, ms >= 200 && ms < 5000);
        clock_gettime(CLOCK_MONOTONIC, &t0);
        errno = 0;
        n = write(sv[0], big, sizeof big);
        ms = TIMEO_SINCE(t0);
        printf("  write=%ld errno=%d waited=%d\n", n, n < 0 ? errno : 0, ms >= 200 && ms < 5000);
        TIMEO_SET(sv[0], SO_SNDTIMEO, -1, 0, 16);
        errno = 0;
        n = send(sv[0], big, sizeof big, 0);
        printf("  no-wait=%ld errno=%d\n", n, n < 0 ? errno : 0);
        close(sv[0]);
        close(sv[1]);
        puts("datagram");
        socketpair(AF_UNIX, SOCK_DGRAM, 0, sv);
        TIMEO_SET(sv[1], SO_RCVTIMEO, 0, 200000, 16);
        clock_gettime(CLOCK_MONOTONIC, &t0);
        errno = 0;
        n = recv(sv[1], buf, 8, 0);
        ms = TIMEO_SINCE(t0);
        printf("  recv=%ld errno=%d waited=%d\n", n, n < 0 ? errno : 0, ms >= 200 && ms < 5000);
        close(sv[0]);
        close(sv[1]);
#undef TIMEO_SET
#undef TIMEO_SINCE
        return 0;
    }
    if (!strcmp(mode, "socket-options")) {
        /* The case names its own group, which the emulated first process,
           like a PID namespace's, is not in until it makes one. */
        if (setpgid(0, 0)) return 80;
        /* SOL_SOCKET options on socket pairs, as Linux's sk_setsockopt and
           sk_getsockopt keep them, SO_OOBINLINE's out-of-band byte read with
           the data, and the SIGURG that F_SETOWN's owner gets for one. Only
           options an unprivileged process sets the same way are tried. */
        int sv[2];
        char buf[16];
        long n;
#define OPT_GET(name, opt, size) do { int v[4] = {-7, -7, -7, -7}; socklen_t len = size; errno = 0; \
        n = getsockopt(sv[0], SOL_SOCKET, opt, v, &len); \
        printf("  get %s=%ld errno=%d v=%d,%d len=%u\n", name, n, n < 0 ? errno : 0, v[0], v[1], len); } while (0)
#define OPT_SET(name, opt, value, size) do { int v[4] = {value, 0, 0, 0}; errno = 0; \
        n = setsockopt(sv[0], SOL_SOCKET, opt, v, size); \
        printf("  set %s=%ld errno=%d\n", name, n, n < 0 ? errno : 0); } while (0)
        const int kinds[] = {SOCK_STREAM, SOCK_DGRAM, SOCK_SEQPACKET};
        for (int k = 0; k < 3; k++) {
            socketpair(AF_UNIX, kinds[k], 0, sv);
            printf("kind %d\n", kinds[k]);
            OPT_GET("type", SO_TYPE, 4);
            OPT_GET("domain", SO_DOMAIN, 4);
            OPT_GET("protocol", SO_PROTOCOL, 4);
            OPT_GET("error", SO_ERROR, 4);
            OPT_GET("acceptconn", SO_ACCEPTCONN, 4);
            OPT_GET("rcvlowat", SO_RCVLOWAT, 4);
            OPT_GET("sndlowat", SO_SNDLOWAT, 4);
            OPT_GET("peek_off", SO_PEEK_OFF, 4);
            OPT_GET("rcvtimeo", SO_RCVTIMEO, 16);
            OPT_GET("unknown", 999, 4);
            const struct { const char *name; int opt; } flags[] = {
                {"reuseaddr", SO_REUSEADDR}, {"dontroute", SO_DONTROUTE}, {"broadcast", SO_BROADCAST},
                {"keepalive", SO_KEEPALIVE}, {"oobinline", SO_OOBINLINE}, {"no_check", SO_NO_CHECK},
            };
            for (unsigned i = 0; i < sizeof flags / sizeof *flags; i++) {
                OPT_GET(flags[i].name, flags[i].opt, 4);
                OPT_SET(flags[i].name, flags[i].opt, 5, 4);
                OPT_GET(flags[i].name, flags[i].opt, 4);
            }
            OPT_SET("priority", SO_PRIORITY, 3, 4);
            OPT_GET("priority", SO_PRIORITY, 4);
            OPT_SET("sndbuf", SO_SNDBUF, 1, 4);
            OPT_GET("sndbuf", SO_SNDBUF, 4);
            OPT_SET("sndbuf", SO_SNDBUF, 50000, 4);
            OPT_GET("sndbuf", SO_SNDBUF, 4);
            OPT_SET("rcvbuf", SO_RCVBUF, 1, 4);
            OPT_GET("rcvbuf", SO_RCVBUF, 4);
            OPT_SET("rcvbuf", SO_RCVBUF, 50000, 4);
            OPT_GET("rcvbuf", SO_RCVBUF, 4);
            OPT_SET("bsdcompat", SO_BSDCOMPAT, 1, 4);
            OPT_GET("bsdcompat", SO_BSDCOMPAT, 4);
            OPT_GET("linger", SO_LINGER, 8);
            OPT_SET("linger-short", SO_LINGER, 1, 4);
            {
                struct linger l = {1, 3};
                errno = 0;
                n = setsockopt(sv[0], SOL_SOCKET, SO_LINGER, &l, sizeof l);
                printf("  set linger=%ld errno=%d\n", n, n < 0 ? errno : 0);
            }
            OPT_GET("linger", SO_LINGER, 8);
            OPT_SET("reuseport", SO_REUSEPORT, 1, 4);
            OPT_SET("type", SO_TYPE, 1, 4);
            OPT_SET("peercred", SO_PEERCRED, 1, 4);
            OPT_SET("sndlowat", SO_SNDLOWAT, 1, 4);
            OPT_SET("rcvtimeo-short", SO_RCVTIMEO, 1, 4);
            OPT_SET("unknown", 999, 1, 4);
            OPT_SET("short", SO_KEEPALIVE, 1, 2);
            close(sv[0]);
            close(sv[1]);
        }
        puts("errors");
        socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
        OPT_GET("cut", SO_TYPE, 2);
        OPT_GET("none", SO_TYPE, 0);
        OPT_GET("negative", SO_TYPE, -1);
        {
            int v = 1;
            errno = 0;
            n = setsockopt(sv[0], 6, 1, &v, 4);
            printf("  other-level=%ld errno=%d\n", n, n < 0 ? errno : 0);
            socklen_t len = 4;
            errno = 0;
            n = getsockopt(sv[0], 6, 1, &v, &len);
            printf("  get-other-level=%ld errno=%d\n", n, n < 0 ? errno : 0);
            errno = 0;
            n = setsockopt(sv[0], SOL_SOCKET, SO_KEEPALIVE, (void *)8, 4);
            printf("  bad-value=%ld errno=%d\n", n, n < 0 ? errno : 0);
            errno = 0;
            n = getsockopt(sv[0], SOL_SOCKET, SO_TYPE, (void *)8, &len);
            printf("  bad-get=%ld errno=%d\n", n, n < 0 ? errno : 0);
            errno = 0;
            n = getsockopt(sv[0], SOL_SOCKET, SO_TYPE, &v, (void *)8);
            printf("  bad-len=%ld errno=%d\n", n, n < 0 ? errno : 0);
            int p[2];
            pipe(p);
            errno = 0;
            n = setsockopt(p[0], SOL_SOCKET, SO_KEEPALIVE, &v, 4);
            printf("  not-socket=%ld errno=%d\n", n, n < 0 ? errno : 0);
            close(p[0]);
            close(p[1]);
            struct ucred peer;
            len = sizeof peer;
            n = getsockopt(sv[0], SOL_SOCKET, SO_PEERCRED, &peer, &len);
            printf("  peercred=%ld pid=%d uid=%d gid=%d len=%u\n", n, peer.pid == getpid(), peer.uid == 0 || peer.uid == getuid(), peer.gid == 0 || peer.gid == getgid(), len);
        }
        puts("oobinline");
        int one = 1;
        setsockopt(sv[1], SOL_SOCKET, SO_OOBINLINE, &one, sizeof one);
        send(sv[0], "abc", 3, MSG_OOB);
        send(sv[0], "de", 2, 0);
        memset(buf, 0, sizeof buf);
        errno = 0;
        n = recv(sv[1], buf, 8, MSG_OOB | MSG_DONTWAIT);
        printf("  oob=%ld errno=%d\n", n, n < 0 ? errno : 0);
        memset(buf, 0, sizeof buf);
        n = recv(sv[1], buf, 8, MSG_PEEK | MSG_DONTWAIT);
        printf("  peek=%ld data=%s\n", n, buf);
        memset(buf, 0, sizeof buf);
        n = recv(sv[1], buf, 8, MSG_DONTWAIT);
        printf("  read=%ld data=%s\n", n, buf);
        int at = -1;
        ioctl(sv[1], SIOCATMARK, &at);
        printf("  atmark=%d\n", at);
        memset(buf, 0, sizeof buf);
        n = recv(sv[1], buf, 8, MSG_PEEK | MSG_DONTWAIT);
        printf("  peek-at-mark=%ld data=%s\n", n, buf);
        memset(buf, 0, sizeof buf);
        n = recv(sv[1], buf, 8, MSG_DONTWAIT);
        printf("  read-at-mark=%ld data=%s\n", n, buf);
        puts("owner");
        signal(SIGURG, interrupted);
        received = 0;
        printf("  getown=%d\n", fcntl(sv[1], F_GETOWN));
        errno = 0;
        n = fcntl(sv[1], F_SETOWN, getpid());
        printf("  setown=%ld errno=%d getown=%d\n", n, n < 0 ? errno : 0, fcntl(sv[1], F_GETOWN) == getpid());
        send(sv[0], "x", 1, MSG_OOB);
        printf("  sigurg=%d\n", received);
        send(sv[0], "y", 1, 0);
        printf("  data-only=%d\n", received);
        n = fcntl(sv[1], F_SETOWN, -getpgrp());
        printf("  setown-group=%ld getown=%d\n", n, fcntl(sv[1], F_GETOWN) == -getpgrp());
        send(sv[0], "z", 1, MSG_OOB);
        printf("  sigurg-group=%d\n", received);
        errno = 0;
        n = fcntl(sv[1], F_SETOWN, 999999);
        printf("  setown-none=%ld errno=%d\n", n, n < 0 ? errno : 0);
        fcntl(sv[1], F_SETOWN, 0);
        send(sv[0], "w", 1, MSG_OOB);
        printf("  no-owner=%d\n", received);
        fcntl(sv[0], F_SETOWN, getpid());
        send(sv[1], "v", 1, MSG_OOB);
        printf("  other-way=%d\n", received);
        signal(SIGURG, SIG_DFL);
        close(sv[0]);
        close(sv[1]);
#undef OPT_GET
#undef OPT_SET
        return 0;
    }
    if (!strcmp(mode, "socket-pidfd")) {
        /* SO_PASSPIDFD, SCM_PIDFD and SO_PEERPIDFD on socket pairs, as
           Linux's af_unix and scm_pidfd_recv: a message to an end that
           passes pidfds carries a close-on-exec pidfd of its sender, after
           its credentials and before its descriptors. */
        int types[] = {SOCK_STREAM, SOCK_DGRAM, SOCK_SEQPACKET};
        const char *names[] = {"stream", "dgram", "seqpacket"};
        int sv[2], on = 1, value = -7;
        socklen_t len = sizeof value;
        for (int t = 0; t < 3; t++) {
            if (socketpair(AF_UNIX, types[t], 0, sv)) return 74;
            printf("%s\n", names[t]);
            getsockopt(sv[1], SOL_SOCKET, SO_PASSPIDFD, &value, &len);
            printf("  passpidfd=%d", value);
            setsockopt(sv[1], SOL_SOCKET, SO_PASSPIDFD, &on, sizeof on);
            len = sizeof value;
            getsockopt(sv[1], SOL_SOCKET, SO_PASSPIDFD, &value, &len);
            printf(" then=%d\n", value);
            send(sv[0], "a", 1, 0);
            pidfd_received("self", sv[1], 256);
            send(sv[0], "b", 1, 0);
            pidfd_received("no-control", sv[1], 0);
            send(sv[0], "c", 1, 0);
            pidfd_received("header-only", sv[1], CMSG_LEN(0));
            send(sv[0], "x", 1, 0);
            pidfd_received("exact", sv[1], CMSG_LEN(sizeof(int)));
            send(sv[0], "y", 1, 0);
            pidfd_received("one-short", sv[1], CMSG_LEN(sizeof(int)) - 1);
            /* With credentials and a descriptor: credentials, pidfd, rights. */
            setsockopt(sv[1], SOL_SOCKET, SO_PASSCRED, &on, sizeof on);
            {
                union { struct cmsghdr align; char bytes[CMSG_SPACE(sizeof(int))]; } out;
                struct iovec iov = {"d", 1};
                struct msghdr m = {.msg_iov = &iov, .msg_iovlen = 1, .msg_control = out.bytes,
                                   .msg_controllen = sizeof out.bytes};
                struct cmsghdr *c = CMSG_FIRSTHDR(&m);
                c->cmsg_level = SOL_SOCKET;
                c->cmsg_type = SCM_RIGHTS;
                c->cmsg_len = CMSG_LEN(sizeof(int));
                int passed = 0;
                memcpy(CMSG_DATA(c), &passed, sizeof passed);
                sendmsg(sv[0], &m, 0);
            }
            pidfd_received("all", sv[1], 256);
            close(sv[0]); close(sv[1]);
        }
        /* A message sent before the receiver passed pidfds carries none. */
        socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
        send(sv[0], "e", 1, 0);
        setsockopt(sv[1], SOL_SOCKET, SO_PASSPIDFD, &on, sizeof on);
        pidfd_received("sent-before", sv[1], 256);
        close(sv[0]); close(sv[1]);
        /* A child's message carries the child's pidfd, which its exit
           makes readable. */
        socketpair(AF_UNIX, SOCK_DGRAM, 0, sv);
        setsockopt(sv[1], SOL_SOCKET, SO_PASSPIDFD, &on, sizeof on);
        int go[2];
        if (pipe(go)) return 79;
        fflush(stdout);
        pid_t forked = child();
        if (forked < 0) return 76;
        if (!forked) {
            char b;
            send(sv[0], "f", 1, 0);
            _exit(read(go[0], &b, 1) == 1 ? 0 : 2);
        }
        {
            struct pollfd ready = {sv[1], POLLIN, 0};
            poll(&ready, 1, 5000);
            char data[8];
            union { struct cmsghdr align; char bytes[64]; } control;
            struct iovec iov = {data, sizeof data};
            struct msghdr m = {.msg_iov = &iov, .msg_iovlen = 1, .msg_control = control.bytes,
                               .msg_controllen = sizeof control.bytes};
            int pidfd = -1;
            if (recvmsg(sv[1], &m, 0) == 1 && CMSG_FIRSTHDR(&m) && CMSG_FIRSTHDR(&m)->cmsg_type == SCM_PIDFD)
                memcpy(&pidfd, CMSG_DATA(CMSG_FIRSTHDR(&m)), sizeof pidfd);
            printf("child pidfd=%d:", pidfd >= 0);
            if (pidfd >= 0) pidfd_kind(pidfd);
            if (write(go[1], "g", 1) != 1) return 78;
            int status;
            siginfo_t info;
            info.si_pid = 0;
            waitid(P_PIDFD, pidfd, &info, WEXITED | WNOWAIT);
            printf(" waited-child=%d", info.si_pid == forked);
            if (pidfd >= 0) pidfd_kind(pidfd);
            putchar('\n');
            waitpid(forked, &status, 0);
            close(pidfd);
        }
        close(go[0]); close(go[1]); close(sv[0]); close(sv[1]);
        /* SO_PEERPIDFD: a pidfd of the process that made the pair. */
        socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
        int peer = -7;
        len = sizeof peer;
        errno = 0;
        int r = getsockopt(sv[0], SOL_SOCKET, SO_PEERPIDFD, &peer, &len);
        printf("peerpidfd=%d errno=%d len=%u valid=%d:", r, errno, (unsigned)len, peer >= 0);
        if (peer >= 0) pidfd_kind(peer);
        putchar('\n');
        close(peer);
        /* A short buffer takes part of the number; the pidfd is still
           installed. */
        char small = 0;
        len = 1;
        int before = lowest_free();
        errno = 0;
        r = getsockopt(sv[0], SOL_SOCKET, SO_PEERPIDFD, &small, &len);
        int installed = lowest_free() != before;
        printf("peerpidfd-short=%d errno=%d len=%u installed=%d\n", r, errno, (unsigned)len, installed);
        if (installed) close(before);
        errno = 0;
        r = setsockopt(sv[0], SOL_SOCKET, SO_PEERPIDFD, &on, sizeof on);
        printf("set-peerpidfd=%d errno=%d\n", r, errno);
        close(sv[0]); close(sv[1]);
        return 0;
    }
    if (!strcmp(mode, "socket-credentials")) {
        /* SO_PASSCRED and SCM_CREDENTIALS on socket pairs, as Linux's
           af_unix and scm.c have them: a message carries its sender's
           credentials when either end passes them, or those SCM_CREDENTIALS
           gives, and a receiver that passes them gets them before its
           descriptors. Only credentials an unprivileged process may send are
           tried. */
        int sv[2], p[2];
        long n;
        char buf[8];
        pipe(p);
#define CRED_SET(fd, on) do { int v = on; errno = 0; n = setsockopt(fd, SOL_SOCKET, SO_PASSCRED, &v, sizeof v); \
        printf("  set passcred=%ld errno=%d\n", n, n < 0 ? errno : 0); } while (0)
#define CRED_GET(fd) do { int v = -7; socklen_t len = sizeof v; errno = 0; \
        n = getsockopt(fd, SOL_SOCKET, SO_PASSCRED, &v, &len); \
        printf("  get passcred=%ld errno=%d v=%d len=%u\n", n, n < 0 ? errno : 0, v, len); } while (0)
        const int kinds[] = {SOCK_STREAM, SOCK_DGRAM, SOCK_SEQPACKET};
        for (int k = 0; k < 3; k++) {
            socketpair(AF_UNIX, kinds[k], 0, sv);
            printf("kind %d\n", kinds[k]);
            CRED_GET(sv[1]);
            puts(" none");
            send(sv[0], "a", 1, 0);
            CRED_SET(sv[1], 5);
            CRED_GET(sv[1]);
            receive_credentials(sv[1], 64, 0);
            puts(" receiver");
            send(sv[0], "b", 1, 0);
            receive_credentials(sv[1], 64, MSG_PEEK);
            receive_credentials(sv[1], 64, 0);
            puts(" sender");
            CRED_SET(sv[1], 0);
            CRED_SET(sv[0], 1);
            send(sv[0], "c", 1, 0);
            CRED_SET(sv[1], 1);
            receive_credentials(sv[1], 64, 0);
            CRED_SET(sv[0], 0);
            puts(" explicit");
            n = send_credentials(sv[0], "d", getpid(), getuid(), getgid(), CMSG_LEN(sizeof(struct ucred)));
            printf("  send=%ld errno=%d\n", n, n < 0 ? errno : 0);
            receive_credentials(sv[1], 64, 0);
            CRED_SET(sv[1], 0);
            n = send_credentials(sv[0], "e", getpid(), getuid(), getgid(), CMSG_LEN(sizeof(struct ucred)));
            printf("  send=%ld errno=%d\n", n, n < 0 ? errno : 0);
            CRED_SET(sv[1], 1);
            receive_credentials(sv[1], 64, 0);
            n = send_credentials(sv[0], "f", getpid(), getuid(), getgid(), CMSG_LEN(8));
            printf("  short=%ld errno=%d\n", n, n < 0 ? errno : 0);
            n = send_credentials(sv[0], "f", getpid(), getuid(), getgid(), CMSG_LEN(sizeof(struct ucred)) + 4);
            printf("  long=%ld errno=%d\n", n, n < 0 ? errno : 0);
            /* An ID of -1 is EINVAL before the process is looked up. */
            n = send_credentials(sv[0], "f", getpid(), -1, getgid(), CMSG_LEN(sizeof(struct ucred)));
            printf("  no-uid=%ld errno=%d\n", n, n < 0 ? errno : 0);
            n = send_credentials(sv[0], "f", getpid(), getuid(), -1, CMSG_LEN(sizeof(struct ucred)));
            printf("  no-gid=%ld errno=%d\n", n, n < 0 ? errno : 0);
            n = send_credentials(sv[0], "f", 0, -1, getgid(), CMSG_LEN(sizeof(struct ucred)));
            printf("  no-pid-no-uid=%ld errno=%d\n", n, n < 0 ? errno : 0);
            puts(" writers");
            send_from_child(sv[0], "g");
            send(sv[0], "h", 1, 0);
            memset(buf, 0, sizeof buf);
            n = read(sv[1], buf, sizeof buf);
            printf("  read=%ld data=%.*s\n", n, n > 0 ? (int)n : 0, buf);
            receive_credentials(sv[1], 64, 0);
            send_from_child(sv[0], "i");
            send(sv[0], "j", 1, 0);
            receive_credentials(sv[1], 64, 0);
            receive_credentials(sv[1], 64, 0);
            send_from_child(sv[0], "k");
            send(sv[0], "l", 1, 0);
            memset(buf, 0, sizeof buf);
            n = recv(sv[1], buf, 2, MSG_WAITALL | MSG_DONTWAIT);
            printf("  waitall=%ld data=%.*s\n", n, n > 0 ? (int)n : 0, buf);
            receive_credentials(sv[1], 64, 0);
            CRED_SET(sv[1], 0);
            send_from_child(sv[0], "m");
            send(sv[0], "n", 1, 0);
            receive_credentials(sv[1], 64, 0);
            receive_credentials(sv[1], 64, 0);
            CRED_SET(sv[0], 1);
            send_from_child(sv[0], "o");
            send(sv[0], "p", 1, 0);
            receive_credentials(sv[1], 64, 0);
            receive_credentials(sv[1], 64, 0);
            CRED_SET(sv[0], 0);
            puts(" room");
            CRED_SET(sv[1], 1);
            const size_t rooms[] = {0, 8, 16, 20, 24, 28, 32};
            for (unsigned i = 0; i < sizeof rooms / sizeof *rooms; i++) {
                send(sv[0], "q", 1, 0);
                receive_credentials(sv[1], rooms[i], 0);
            }
            puts(" descriptors");
            const size_t fd_rooms[] = {64, 32, 40, 48, 52, 56};
            for (unsigned i = 0; i < sizeof fd_rooms / sizeof *fd_rooms; i++) {
                send_fds(sv[0], "r", 1, p, 2);
                receive_credentials(sv[1], fd_rooms[i], 0);
            }
            CRED_SET(sv[1], 0);
            send_fds(sv[0], "s", 1, p, 1);
            receive_credentials(sv[1], 64, 0);
            close(sv[0]);
            close(sv[1]);
        }
        puts("errors");
        socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
        CRED_SET(p[0], 1);
        {
            int v = 1;
            errno = 0;
            n = setsockopt(sv[0], SOL_SOCKET, SO_PASSCRED, &v, 2);
            printf("  short-set=%ld errno=%d\n", n, n < 0 ? errno : 0);
            socklen_t len = 2;
            v = -7;
            errno = 0;
            n = getsockopt(sv[0], SOL_SOCKET, SO_PASSCRED, &v, &len);
            printf("  short-get=%ld errno=%d v=%d len=%u\n", n, n < 0 ? errno : 0, v, len);
        }
        close(sv[0]);
        close(sv[1]);
        close(p[0]);
        close(p[1]);
#undef CRED_SET
#undef CRED_GET
        return 0;
    }
    if (!strcmp(mode, "fionread")) {
        /* FIONREAD (SIOCINQ) and SIOCOUTQ. A pipe counts its unread bytes
           at either end; a stream socket its unread bytes, a packet socket
           those of every packet, a datagram socket its first datagram's; a
           regular file its size past the offset. SIOCOUTQ counts what the
           peer has not read, which Linux counts with each message's
           overhead, so only whether it is 0 is printed. Other files are
           ENOTTY. */
        int p[2], sv[2], n;
        char buf[16];
        if (pipe(p)) return 79;
        write(p[1], "abcde", 5);
        ioctl_int("pipe-read", p[0], FIONREAD);
        ioctl_int("pipe-write", p[1], FIONREAD);
        read(p[0], buf, 2);
        ioctl_int("pipe-read", p[0], FIONREAD);
        ioctl_int("pipe-outq", p[0], SIOCOUTQ);
        errno = 0;
        n = ioctl(p[0], FIONREAD, (int *)8);
        printf("  pipe-fault=%d errno=%d\n", n, errno);
        close(p[0]); close(p[1]);
        const int kinds[] = {SOCK_STREAM, SOCK_DGRAM, SOCK_SEQPACKET};
        for (int k = 0; k < 3; k++) {
            socketpair(AF_UNIX, kinds[k], 0, sv);
            printf("kind %d\n", kinds[k]);
            ioctl_int("empty", sv[1], SIOCINQ);
            send(sv[0], "abc", 3, 0);
            send(sv[0], "de", 2, 0);
            ioctl_int("two", sv[1], SIOCINQ);
            ioctl_int("own", sv[0], SIOCINQ);
            n = ioctl(sv[0], SIOCOUTQ, &(int){0}) == 0;
            int queued = -1;
            ioctl(sv[0], SIOCOUTQ, &queued);
            printf("  outq ok=%d sent=%d\n", n, queued > 0);
            recv(sv[1], buf, 1, MSG_PEEK);
            ioctl_int("peeked", sv[1], SIOCINQ);
            /* A stream reads its first write whole: what a part read
               leaves of one depends on the kernel, as some count only the
               rest and others the whole write. A message's part read drops
               the rest. */
            recv(sv[1], buf, kinds[k] == SOCK_STREAM ? 3 : 2, 0);
            ioctl_int("read", sv[1], SIOCINQ);
            while (recv(sv[1], buf, sizeof buf, MSG_DONTWAIT) > 0) {}
            ioctl_int("drained", sv[1], SIOCINQ);
            queued = -1;
            ioctl(sv[0], SIOCOUTQ, &queued);
            printf("  outq drained=%d\n", queued);
            if (kinds[k] == SOCK_STREAM) {
                /* An out-of-band byte is counted until it is taken. */
                send(sv[0], "fg", 2, 0);
                send(sv[0], "h", 1, MSG_OOB);
                ioctl_int("oob", sv[1], SIOCINQ);
                recv(sv[1], buf, 1, MSG_OOB);
                ioctl_int("oob-taken", sv[1], SIOCINQ);
                recv(sv[1], buf, sizeof buf, 0);
                ioctl_int("oob-read", sv[1], SIOCINQ);
            }
            send(sv[0], "ij", 2, 0);
            shutdown(sv[0], SHUT_WR);
            ioctl_int("shut", sv[1], SIOCINQ);
            close(sv[0]);
            ioctl_int("closed", sv[1], SIOCINQ);
            close(sv[1]);
        }
        puts("files");
        int m = memfd_create("fionread", 0);
        if (m < 0) return 78;
        write(m, "0123456789", 10);
        ioctl_int("memfd-end", m, FIONREAD);
        lseek(m, 3, SEEK_SET);
        ioctl_int("memfd-at-3", m, FIONREAD);
        lseek(m, 20, SEEK_SET);
        ioctl_int("memfd-past", m, FIONREAD);
        ioctl_int("memfd-outq", m, SIOCOUTQ);
        close(m);
        int f = open("/tmp/paludarium-fionread", O_RDWR | O_CREAT | O_TRUNC, 0600);
        if (f < 0) return 77;
        write(f, "abcdef", 6);
        lseek(f, 1, SEEK_SET);
        ioctl_int("file", f, FIONREAD);
        close(f);
        unlink("/tmp/paludarium-fionread");
        f = open("/tmp", O_RDONLY | O_DIRECTORY);
        ioctl_int("directory", f, FIONREAD);
        close(f);
        f = open("/dev/null", O_RDWR);
        ioctl_int("null", f, FIONREAD);
        close(f);
        f = eventfd(1, 0);
        ioctl_int("eventfd", f, FIONREAD);
        close(f);
        return 0;
    }
    if (!strcmp(mode, "generic-ioctl")) {
        /* The ioctls Linux's do_vfs_ioctl answers for every file: FIOCLEX
           and FIONCLEX, FIONBIO, FIOASYNC, which a file without fasync
           refuses with ENOTTY only for a change, FIOQSIZE, the size of a
           regular file or directory, and FIGETBSZ, the block size of the
           file's filesystem. An O_PATH descriptor answers none. */
        int p[2], sv[2];
        if (pipe(p) || socketpair(AF_UNIX, SOCK_STREAM, 0, sv)) return 79;
        write(p[1], "abc", 3);
        int m = memfd_create("generic-ioctl", 0);
        if (m < 0) return 78;
        write(m, "0123456789", 10);
        int f = open("/tmp/paludarium-generic-ioctl", O_RDWR | O_CREAT | O_TRUNC, 0600);
        if (f < 0) return 77;
        write(f, "abcdef", 6);
        const struct {
            const char *name;
            int fd;
        } files[] = {
            {"pipe", p[0]},
            {"socket", sv[0]},
            {"memfd", m},
            {"file", f},
            {"null", open("/dev/null", O_RDWR)},
            {"eventfd", eventfd(0, 0)},
        };
        for (unsigned i = 0; i < sizeof files / sizeof *files; i++) {
            int fd = files[i].fd;
            printf("%s\n", files[i].name);
            ioctl_flags("clex", fd, FIOCLEX, 0);
            ioctl_flags("nclex", fd, FIONCLEX, 0);
            ioctl_flags("nbio-on", fd, FIONBIO, 1);
            ioctl_flags("nbio-off", fd, FIONBIO, 0);
            ioctl_flags("async-off", fd, FIOASYNC, 0);
            ioctl_flags("async-on", fd, FIOASYNC, 3);
            ioctl_flags("async-again", fd, FIOASYNC, 1);
            ioctl_flags("async-off", fd, FIOASYNC, 0);
            errno = 0;
            int n = ioctl(fd, FIOASYNC, (int *)8);
            printf("  async-fault=%d errno=%d\n", n, errno);
            /* What a file takes is its filesystem's: stat's st_blocks
               counts it, though for a file some (overlayfs, ext4 with
               delayed allocation) count blocks FIOQSIZE does not yet see,
               so only a memfd's is compared. */
            long long size = -7;
            errno = 0;
            n = ioctl(fd, FIOQSIZE, &size);
            struct stat st;
            fstat(fd, &st);
            printf("  qsize=%d errno=%d", n, errno);
            if (fd == m) printf(" blocks=%d", size == (long long)st.st_blocks * 512);
            putchar('\n');
            /* The pseudo filesystems' block size is the page's; a file's and
               /dev/null's are their filesystem's, which st_blksize gives
               (/tmp is ext4 on the CI runner; overlayfs, as in a container,
               has none and answers EINVAL). */
            int block = -7;
            errno = 0;
            n = ioctl(fd, FIGETBSZ, &block);
            printf("  bsize=%d errno=%d stat=%d", n, errno, block == (int)st.st_blksize);
            if (strcmp(files[i].name, "file") && strcmp(files[i].name, "null")) printf(" block=%d", block);
            putchar('\n');
        }
        int d = open("/tmp", O_RDONLY | O_DIRECTORY);
        errno = 0;
        int n = ioctl(d, FIOQSIZE, &(long long){0});
        printf("directory qsize=%d errno=%d\n", n, errno);
        errno = 0;
        n = ioctl(f, FIOQSIZE, (long long *)8);
        printf("qsize-fault=%d errno=%d\n", n, errno);
        errno = 0;
        n = ioctl(d, FIGETBSZ, &(int){0});
        printf("directory bsize=%d errno=%d\n", n, errno);
        errno = 0;
        n = ioctl(f, FIGETBSZ, (int *)8);
        printf("bsize-fault=%d errno=%d\n", n, errno);
        int path = open("/tmp", O_PATH);
        errno = 0;
        n = ioctl(path, FIOCLEX);
        printf("path clex=%d errno=%d\n", n, errno);
        errno = 0;
        n = ioctl(path, FIONREAD, &(int){0});
        printf("path fionread=%d errno=%d\n", n, errno);
        errno = 0;
        n = ioctl(path, FIGETBSZ, &(int){0});
        printf("path bsize=%d errno=%d\n", n, errno);
        errno = 0;
        n = ioctl(1000, FIOCLEX);
        printf("bad clex=%d errno=%d\n", n, errno);
        unlink("/tmp/paludarium-generic-ioctl");
        return 0;
    }
    if (!strcmp(mode, "socket-rcvlowat")) {
        /* SO_RCVLOWAT on socket pairs, as Linux's af_unix has it: a blocking
           stream read waits until it has that many bytes, or the buffer is
           full, and returns what it has once a wait ends; it does not hold
           back poll, a peek or a nonblocking read, nor datagrams and
           packets. A child sends the later bytes, only where the read is
           to wait; SO_RCVTIMEO bounds every wait. */
        int sv[2];
        const int kinds[] = {SOCK_STREAM, SOCK_DGRAM, SOCK_SEQPACKET};
        for (int k = 0; k < 3; k++) {
            socketpair(AF_UNIX, kinds[k], 0, sv);
            printf("kind %d\n", kinds[k]);
            int_option("rcvlowat", sv[1], SO_RCVLOWAT, 5, 4);
            int_option("rcvlowat", sv[1], SO_RCVLOWAT, 0, 4);
            int_option("rcvlowat", sv[1], SO_RCVLOWAT, -1, 4);
            int_option("rcvlowat", sv[1], SO_RCVLOWAT, -9, 4);
            int_option("rcvlowat", sv[1], SO_RCVLOWAT, 3, 2);
            int_option("rcvlowat", sv[1], SO_RCVLOWAT, 4, 4);
            struct timeval tv = {3, 0};
            setsockopt(sv[1], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
            send(sv[0], "ab", 2, 0);
            struct pollfd p = {sv[1], POLLIN, 0};
            int ready = poll(&p, 1, 0);
            printf("  poll=%d revents=%#x\n", ready, p.revents);
            receive_waited("peek", sv[1], 8, MSG_PEEK);
            receive_waited("peek-all", sv[1], 8, MSG_PEEK | MSG_WAITALL);
            receive_waited("dontwait", sv[1], 1, MSG_DONTWAIT);
            /* The child sends after what this process sent. */
            struct timespec before_fork;
            clock_gettime(CLOCK_MONOTONIC, &before_fork);
            pid_t pid = send_later(sv[0], "cd", 1000);
            receive_waited_from("recv", sv[1], 8, 0, &before_fork);
            waitpid(pid, NULL, 0);
            receive_waited("rest", sv[1], 8, MSG_DONTWAIT);
            /* A buffer smaller than the mark ends the read when full; were
               it to wait, SO_RCVTIMEO would end it, long after. No child
               runs here: an emulated parent's first steps after a fork
               copy its pages, which can take as long as a wait. */
            send(sv[0], "ef", 2, 0);
            receive_waited("small", sv[1], 2, 0);
            /* read takes it too. */
            send(sv[0], "ij", 2, 0);
            pid = send_later(sv[0], "kl", 1000);
            char buf[8] = {0};
            long n = read(sv[1], buf, sizeof buf);
            printf("  read=%ld data=%.*s\n", n, n > 0 ? (int)n : 0, buf);
            waitpid(pid, NULL, 0);
            receive_waited("rest", sv[1], 8, MSG_DONTWAIT);
            /* A wait that times out returns what came. */
            tv.tv_sec = 1;
            setsockopt(sv[1], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
            send(sv[0], "mn", 2, 0);
            receive_waited("timeout", sv[1], 8, 0);
            receive_waited("empty", sv[1], 8, 0);
            /* The end of the stream ends it as well. */
            send(sv[0], "op", 2, 0);
            shutdown(sv[0], SHUT_WR);
            receive_waited("shut", sv[1], 8, 0);
            close(sv[0]);
            close(sv[1]);
        }
        return 0;
    }
    if (!strcmp(mode, "socket-peek-off")) {
        /* SO_PEEK_OFF on socket pairs, as Linux's af_unix has it: a peek
           starts that far in and moves it on, a read moves it back, and on
           datagrams and packets it skips whole messages. */
        int sv[2];
        const int kinds[] = {SOCK_STREAM, SOCK_DGRAM, SOCK_SEQPACKET};
        for (int k = 0; k < 3; k++) {
            socketpair(AF_UNIX, kinds[k], 0, sv);
            printf("kind %d\n", kinds[k]);
            int_option("peek_off", sv[1], SO_PEEK_OFF, 5, 4);
            int_option("peek_off", sv[1], SO_PEEK_OFF, -1, 4);
            int_option("peek_off", sv[1], SO_PEEK_OFF, -2, 4);
            int_option("peek_off", sv[1], SO_PEEK_OFF, 3, 2);
            int_option("peek_off", sv[1], SO_PEEK_OFF, -1, 4);
            send(sv[0], "abc", 3, 0);
            send(sv[0], "de", 2, 0);
            receive_waited("off", sv[1], 2, MSG_PEEK | MSG_DONTWAIT);
            int_option("peek_off", sv[1], SO_PEEK_OFF, 0, 4);
            receive_waited("peek", sv[1], 2, MSG_PEEK | MSG_DONTWAIT);
            receive_waited("peek", sv[1], 8, MSG_PEEK | MSG_DONTWAIT);
            receive_waited("peek", sv[1], 1, MSG_PEEK | MSG_TRUNC | MSG_DONTWAIT);
            receive_waited("peek", sv[1], 8, MSG_PEEK | MSG_DONTWAIT);
            receive_waited("peek", sv[1], 8, MSG_PEEK | MSG_DONTWAIT);
            receive_waited("recv", sv[1], 2, MSG_DONTWAIT);
            receive_waited("peek", sv[1], 8, MSG_PEEK | MSG_DONTWAIT);
            receive_waited("recv", sv[1], 8, MSG_DONTWAIT);
            receive_waited("recv", sv[1], 8, MSG_DONTWAIT);
            /* An empty message at the offset is peeked, past it skipped. */
            send(sv[0], "", 0, 0);
            send(sv[0], "f", 1, 0);
            int_option("peek_off", sv[1], SO_PEEK_OFF, 0, 4);
            receive_waited("empty", sv[1], 8, MSG_PEEK | MSG_DONTWAIT);
            receive_waited("empty", sv[1], 8, MSG_PEEK | MSG_DONTWAIT);
            int_option("peek_off", sv[1], SO_PEEK_OFF, 9, 4);
            receive_waited("past", sv[1], 8, MSG_PEEK | MSG_DONTWAIT);
            receive_waited("recv", sv[1], 8, MSG_DONTWAIT);
            receive_waited("recv", sv[1], 8, MSG_DONTWAIT);
            /* A large offset comes down by what a read takes. */
            int_option("peek_off", sv[1], SO_PEEK_OFF, 9, 4);
            send(sv[0], "ghij", 4, 0);
            receive_waited("recv", sv[1], 8, MSG_DONTWAIT);
            close(sv[0]);
            close(sv[1]);
        }
        return 0;
    }
    if (!strcmp(mode, "socket-parts")) {
        /* A stream write goes in parts, as Linux's unix_stream_sendmsg
           sends it: at most a page's head and 32 KiB of pages, or half the
           send buffer less 64 bytes, each, with the descriptors in the
           first, where a read of them ends. Each part signals O_ASYNC's
           owner. Messages go whole. */
        static char data[100000], got[sizeof data + 1];
        int sv[2], fd, flags, value;
        long n;
        sigset_t set;
        sigemptyset(&set);
        sigaddset(&set, IO_RT);
        sigprocmask(SIG_BLOCK, &set, NULL);
        const int kinds[] = {SOCK_STREAM, SOCK_SEQPACKET};
        for (int k = 0; k < 2; k++) {
            socketpair(AF_UNIX, kinds[k], 0, sv);
            printf("kind %d\n", kinds[k]);
            io_async(sv[1], IO_RT);
            n = send_fds(sv[0], data, sizeof data, &sv[0], 1);
            printf("  send=%ld errno=%d in=%d\n", n, n < 0 ? errno : 0, io_count(POLL_IN));
            n = receive_fd(sv[1], got, sizeof got, MSG_PEEK | MSG_DONTWAIT, &fd, &flags);
            printf("  peek=%ld fd=%d\n", n, fd >= 0);
            if (fd >= 0) close(fd);
            n = receive_fd(sv[1], got, sizeof got, MSG_WAITALL, &fd, &flags);
            printf("  waitall=%ld fd=%d\n", n, fd >= 0);
            if (fd >= 0) close(fd);
            n = receive_fd(sv[1], got, sizeof got, MSG_DONTWAIT, &fd, &flags);
            printf("  rest=%ld errno=%d fd=%d\n", n, n < 0 ? errno : 0, fd >= 0);
            if (fd >= 0) close(fd);
            /* SO_SNDBUF 10000 is a send buffer of 20000: parts of 9936. */
            value = 10000;
            setsockopt(sv[0], SOL_SOCKET, SO_SNDBUF, &value, sizeof value);
            n = send_fds(sv[0], data, 2 * 9936, &sv[0], 1);
            printf("  small-send=%ld errno=%d in=%d\n", n, n < 0 ? errno : 0, io_count(POLL_IN));
            n = receive_fd(sv[1], got, sizeof got, MSG_DONTWAIT, &fd, &flags);
            printf("  small=%ld fd=%d\n", n, fd >= 0);
            if (fd >= 0) close(fd);
            n = receive_fd(sv[1], got, sizeof got, MSG_DONTWAIT, &fd, &flags);
            printf("  small-rest=%ld errno=%d fd=%d\n", n, n < 0 ? errno : 0, fd >= 0);
            if (fd >= 0) close(fd);
            close(sv[0]);
            close(sv[1]);
        }
        return 0;
    }
    if (!strcmp(mode, "socket-timestamp")) {
        /* SO_TIMESTAMP, SO_TIMESTAMPNS and their _NEW forms on socket pairs,
           as Linux's sock.c and af_unix have them: a datagram or packet
           receiver that takes them gets the time a message was sent, if it
           took them then, or else the time it is first read, before its
           credentials and descriptors. A stream gets none. */
        int sv[2], p[2];
        long long sent, first = 0, again = 1;
        pipe(p);
        const int kinds[] = {SOCK_STREAM, SOCK_DGRAM, SOCK_SEQPACKET};
        for (int k = 0; k < 3; k++) {
            socketpair(AF_UNIX, kinds[k], 0, sv);
            printf("kind %d\n", kinds[k]);
            timestamp_options("none", sv[1]);
            int_option("new", sv[1], TS_NEW, 1, 4);
            timestamp_options("new", sv[1]);
            /* Turning one off keeps _NEW, which the next on form sets. */
            int_option("old-off", sv[1], TS_OLD, 0, 4);
            timestamp_options("off", sv[1]);
            int_option("ns-old", sv[1], TS_NS_OLD, 1, 4);
            timestamp_options("ns-old", sv[1]);
            int_option("ns-new", sv[1], TS_NS_NEW, 5, 4);
            timestamp_options("ns-new", sv[1]);
            int_option("short", sv[1], TS_OLD, 1, 2);
            int_option("old", sv[1], TS_OLD, 1, 4);
            timestamp_options("old", sv[1]);
            /* Stamped as sent. */
            send(sv[0], "a", 1, 0);
            sent = real_ns();
            receive_stamped("old", sv[1], 256, 0, sent, NULL);
            /* Stamped as first read, by a peek, which the read keeps. The
               sleeps part the times, which a test host's clock moves only
               by. */
            int_option("off", sv[1], TS_OLD, 0, 4);
            send(sv[0], "b", 1, 0);
            sent = real_ns();
            int_option("ns-old", sv[1], TS_NS_OLD, 1, 4);
            usleep(2000);
            receive_stamped("peek", sv[1], 256, MSG_PEEK, sent, &first);
            usleep(2000);
            receive_stamped("read", sv[1], 256, 0, sent, &again);
            printf("  kept=%d\n", first == again);
            int_option("new", sv[1], TS_NEW, 1, 4);
            send(sv[0], "c", 1, 0);
            sent = real_ns();
            receive_stamped("new", sv[1], 256, 0, sent, NULL);
            int_option("ns-new", sv[1], TS_NS_NEW, 1, 4);
            send(sv[0], "d", 1, 0);
            sent = real_ns();
            receive_stamped("ns-new", sv[1], 256, 0, sent, NULL);
            /* Before the credentials and descriptors. */
            int_option("passcred", sv[1], SO_PASSCRED, 1, 4);
            send_fds(sv[0], "e", 1, &p[0], 1);
            sent = real_ns();
            receive_stamped("all", sv[1], 256, 0, sent, NULL);
            int_option("passcred", sv[1], SO_PASSCRED, 0, 4);
            /* A control buffer that holds less cuts it. */
            const size_t rooms[] = {0, 8, 16, 24, 40};
            for (int r = 0; r < 5; r++) {
                send_fds(sv[0], "f", 1, &p[0], 1);
                sent = real_ns();
                char label[16];
                snprintf(label, sizeof label, "room%zu", rooms[r]);
                receive_stamped(label, sv[1], rooms[r], 0, sent, NULL);
            }
            /* A plain read takes the message all the same. */
            send(sv[0], "g", 1, 0);
            char byte;
            printf("  read=%ld\n", (long)read(sv[1], &byte, 1));
            close(sv[0]);
            close(sv[1]);
        }
        close(p[0]);
        close(p[1]);
        return 0;
    }
    if (!strcmp(mode, "anon-reopen")) {
        /* Opening the /proc/self/fd link of a file of no type. Linux first
           checks the inode's permission, root's with mode 0600 (a pidfd's
           0700), so another user gets EACCES. Root then reaches the
           anonymous inodes' no_open (ENXIO), while pidfs has no open of its
           own, so a pidfd opens as another description of its process: the
           access it is opened with and its own O_NONBLOCK, polled as the
           process exits and is reaped. Each line is whether the outcome is
           the one for this process's user. */
        int root = geteuid() == 0;
        char link[64];
        int anon[3] = {eventfd(0, 0), epoll_create1(0), timerfd_create(CLOCK_MONOTONIC, 0)};
        const char *names[3] = {"eventfd", "epoll", "timerfd"};
        for (int i = 0; i < 3; i++) {
            snprintf(link, sizeof link, "/proc/self/fd/%d", anon[i]);
            errno = 0;
            int n = open(link, O_RDWR);
            int refused = n < 0 && errno == (root ? ENXIO : EACCES);
            struct stat st = {0};
            fstat(anon[i], &st);
            printf("%s=%d mode=%#o\n", names[i], refused, st.st_mode);
            close(anon[i]);
        }
        int gate[2];
        if (pipe(gate) < 0)
            return 1;
        pid_t pid = child();
        if (pid == 0) {
            char byte;
            read(gate[0], &byte, 1);
            _exit(0);
        }
        int pidfd = (int)syscall(SYS_pidfd_open, pid, 0);
        struct stat st = {0};
        fstat(pidfd, &st);
        printf("pidfd-mode=%#o\n", st.st_mode);
        snprintf(link, sizeof link, "/proc/self/fd/%d", pidfd);
        errno = 0;
        int again = open(link, O_RDONLY | O_NONBLOCK);
        int refused = again < 0 && errno == EACCES;
        struct pollfd q = {again, POLLIN, 0};
        int running = poll(&q, 1, 0) == 0;
        result("open", root ? again >= 0 : refused);
        result("flags", root ? fcntl(again, F_GETFL) == (O_RDONLY | O_NONBLOCK | O_LARGEFILE) : refused);
        result("signal", root ? syscall(SYS_pidfd_send_signal, again, 0, NULL, 0) == 0 : refused);
        result("running", root ? running : refused);
        fcntl(again, F_SETFL, 0);
        result("set-flags", root ? fcntl(again, F_GETFL) == (O_RDONLY | O_LARGEFILE) : refused);
        result("first-flags", fcntl(pidfd, F_GETFL) == O_RDWR);
        close(again);
        write(gate[1], "x", 1);
        siginfo_t info;
        waitid(P_PID, pid, &info, WEXITED | WNOWAIT);
        again = open(link, O_WRONLY);
        q = (struct pollfd){again, POLLIN, 0};
        result("exited", root ? poll(&q, 1, 0) == 1 && q.revents == POLLIN : again < 0 && errno == EACCES);
        close(again);
        waitpid(pid, NULL, 0);
        again = open(link, O_RDWR);
        q = (struct pollfd){again, POLLIN, 0};
        result("reaped", root ? poll(&q, 1, 0) == 1 && q.revents == (POLLIN | POLLHUP) : again < 0 && errno == EACCES);
        close(again);
        close(pidfd);
        return 0;
    }
    if (!strcmp(mode, "proc-self-link")) {
        /* /proc/self is a symbolic link to this process's /proc directory,
           as Linux's proc_self_get_link makes it: lstat (fstatat and statx
           with AT_SYMLINK_NOFOLLOW too) gives the link, stat and a
           trailing slash follow it, O_NOFOLLOW does not (ELOOP), and
           O_PATH | O_NOFOLLOW opens the link itself, which reads as the
           pid and names itself /proc/self. */
        struct stat st = {0}, dir = {0};
        char own_dir[32];
        snprintf(own_dir, sizeof own_dir, "/proc/%d", getpid());
        stat(own_dir, &dir);
#define SELF_STAT(name, call) do { memset(&st, 0, sizeof st); errno = 0; int r = (call); \
        printf("%s: r=%d errno=%d mode=%#o size=%ld blksize=%ld%s\n", name, r, r < 0 ? errno : 0, st.st_mode, \
               (long)st.st_size, (long)st.st_blksize, S_ISDIR(st.st_mode) ? (st.st_ino == dir.st_ino ? " own-dir" : " other-dir") : \
               S_ISLNK(st.st_mode) ? (st.st_nlink == 1 ? " one-link" : " links") : ""); } while (0)
        SELF_STAT("lstat", lstat("/proc/self", &st));
        SELF_STAT("lstat-slash", lstat("/proc/self/", &st));
        SELF_STAT("stat", stat("/proc/self", &st));
        SELF_STAT("fstatat-nofollow", fstatat(AT_FDCWD, "/proc/self", &st, AT_SYMLINK_NOFOLLOW));
        unsigned char sx[256] = {0};
        errno = 0;
        int r = (int)syscall(SYS_statx, AT_FDCWD, "/proc/self", AT_SYMLINK_NOFOLLOW, 0x7ff, sx);
        unsigned short statx_mode;
        memcpy(&statx_mode, sx + 28, sizeof statx_mode);
        printf("statx: r=%d errno=%d mode=%#o\n", r, r < 0 ? errno : 0, statx_mode);
        char to[64] = {0};
        long n = readlink("/proc/self", to, sizeof to - 1);
        printf("readlink=%ld pid=%d\n", n > 0 ? 1L : n, atoi(to) == getpid());
        errno = 0;
        int fd = open("/proc/self", O_RDONLY | O_NOFOLLOW);
        printf("nofollow: open=%d errno=%d\n", fd >= 0, fd < 0 ? errno : 0);
        errno = 0;
        fd = open("/proc/self", O_RDONLY | O_DIRECTORY);
        printf("directory: open=%d errno=%d\n", fd >= 0, fd < 0 ? errno : 0);
        close(fd);
        int link = open("/proc/self", O_PATH | O_NOFOLLOW);
        SELF_STAT("path-nofollow", fstat(link, &st));
        memset(to, 0, sizeof to);
        n = readlinkat(link, "", to, sizeof to - 1);
        printf("readlinkat=%ld pid=%d\n", n > 0 ? 1L : n, atoi(to) == getpid());
        char own[64], named[64] = {0};
        snprintf(own, sizeof own, "/proc/self/fd/%d", link);
        readlink(own, named, sizeof named - 1);
        printf("own-link=%s\n", named);
        close(link);
#undef SELF_STAT
        return 0;
    }
    if (!strcmp(mode, "link-path")) {
        /* O_PATH | O_NOFOLLOW on a symbolic link opens the link itself, as
           Linux does: its own fstat (fstatat with AT_EMPTY_PATH too) and
           fstatfs, readlinkat(fd, "") reads where it points, its own link
           in /proc/self/fd names the link, nothing reads through it, and
           an open that follows that link reaches the link (ELOOP). Shown
           for a link in /proc/self/fd, a symbolic link of a filesystem and
           /dev/stdin. */
        char tmp[] = "/tmp/paludarium-linkpathXXXXXX";
        int file = mkstemp(tmp);
        struct stat target;
        fstat(file, &target);
        char fd_link[64];
        snprintf(fd_link, sizeof fd_link, "/proc/self/fd/%d", file);
        char symbolic[] = "/tmp/paludarium-linkpath-link";
        unlink(symbolic);
        symlink(tmp, symbolic);
        const char *links[] = {fd_link, symbolic, "/dev/stdin"};
        const char *names[] = {"fd-link", "symlink", "dev-stdin"};
        for (int i = 0; i < 3; i++) {
            errno = 0;
            int fd = open(links[i], O_PATH | O_NOFOLLOW);
            printf("%s: open=%d errno=%d flags=%#o\n", names[i], fd >= 0, fd < 0 ? errno : 0, fcntl(fd, F_GETFL));
            if (fd < 0) continue;
            struct stat st = {0}, at = {0};
            fstat(fd, &st);
            fstatat(fd, "", &at, AT_EMPTY_PATH);
            printf("  fstat mode=%#o size=%s blksize=%ld not-target=%d fstatat-same=%d\n", st.st_mode,
                   i == 1 ? (st.st_size == (off_t)strlen(tmp) ? "target-length" : "other") : st.st_size == 64 ? "64" : "other",
                   (long)st.st_blksize, st.st_ino != target.st_ino || st.st_dev != target.st_dev,
                   at.st_mode == st.st_mode && at.st_ino == st.st_ino);
            char to[256] = {0};
            errno = 0;
            long n = readlinkat(fd, "", to, sizeof to - 1);
            printf("  readlinkat=%ld errno=%d target=%s\n", n > 0 ? 1L : n, n < 0 ? errno : 0,
                   n <= 0 ? "-" : !strcmp(to, tmp) ? "file" : to);
            char own[64], named[256] = {0};
            snprintf(own, sizeof own, "/proc/self/fd/%d", fd);
            readlink(own, named, sizeof named - 1);
            char expected[64];
            snprintf(expected, sizeof expected, "/proc/%d/fd/%d", getpid(), file);
            printf("  own-link=%s\n", !strcmp(named, expected) ? "proc-link" : !strcmp(named, symbolic) ? "symlink" : named);
            struct statfs fs = {0};
            errno = 0;
            int r = fstatfs(fd, &fs);
            printf("  fstatfs=%d errno=%d proc=%d\n", r, r < 0 ? errno : 0, fs.f_type == 0x9fa0);
            char byte;
            errno = 0;
            n = read(fd, &byte, 1);
            printf("  read=%ld errno=%d", n, n < 0 ? errno : 0);
            errno = 0;
            r = open(own, O_RDONLY);
            printf(" follow-again=%d errno=%d\n", r >= 0, r < 0 ? errno : 0);
            close(fd);
        }
        /* A file is no link: readlinkat(fd, "") of its O_PATH descriptor is
           ENOENT; a closed descriptor's link is not there. */
        int path = open(tmp, O_PATH);
        char to[64];
        errno = 0;
        long n = readlinkat(path, "", to, sizeof to);
        printf("file: readlinkat=%ld errno=%d", n, n < 0 ? errno : 0);
        errno = 0;
        n = readlinkat(AT_FDCWD, "", to, sizeof to);
        printf(" cwd=%ld errno=%d\n", n, n < 0 ? errno : 0);
        close(path);
        errno = 0;
        int r = open("/proc/self/fd/900", O_PATH | O_NOFOLLOW);
        printf("closed: open=%d errno=%d\n", r >= 0, r < 0 ? errno : 0);
        unlink(symbolic);
        unlink(tmp);
        close(file);
        return 0;
    }
    if (!strcmp(mode, "pipe-async")) {
        /* Each open file description of a pipe has its own owner and
           O_ASYNC, as Linux keeps f_owner and the fasync entry for each
           file: a write signals every reader description open with it
           (fasync_readers), a read every writer one (fasync_writers), and
           an O_RDWR description is both. */
        sigset_t set;
        sigemptyset(&set);
        sigaddset(&set, SIGIO);
        sigaddset(&set, SIGURG);
        sigaddset(&set, IO_RT);
        sigprocmask(SIG_BLOCK, &set, NULL);
        pid_t pid = getpid();
        int p[2];
        char sink[64];
        if (pipe(p)) return 79;
        char link[64];
        snprintf(link, sizeof link, "/proc/self/fd/%d", p[0]);
        int again = open(link, O_RDONLY | O_NONBLOCK);
        fcntl(p[0], F_SETOWN, pid);
        fcntl(p[0], F_SETSIG, IO_RT);
        fcntl(p[0], F_SETFL, O_ASYNC | O_NONBLOCK);
        printf("own: first=%d/%d/%d again=%d/%d/%d\n", fcntl(p[0], F_GETOWN) == pid, fcntl(p[0], F_GETSIG) == IO_RT,
               !!(fcntl(p[0], F_GETFL) & O_ASYNC), fcntl(again, F_GETOWN) == pid, fcntl(again, F_GETSIG) == IO_RT,
               !!(fcntl(again, F_GETFL) & O_ASYNC));
        write(p[1], "a", 1);
        io_taken("one-reader");
        fcntl(again, F_SETOWN, pid);
        fcntl(again, F_SETSIG, IO_RT);
        fcntl(again, F_SETFL, O_ASYNC | O_NONBLOCK);
        write(p[1], "b", 1);
        io_taken("two-readers");
        fcntl(p[0], F_SETFL, O_NONBLOCK);
        write(p[1], "c", 1);
        io_taken("second-reader");
        while (read(p[0], sink, sizeof sink) > 0) {}
        io_taken("drained");
        fcntl(again, F_SETFL, O_NONBLOCK);
        /* O_RDWR: a reader and a writer at once. */
        int both = open(link, O_RDWR | O_NONBLOCK);
        fcntl(both, F_SETOWN, pid);
        fcntl(both, F_SETSIG, IO_RT);
        fcntl(both, F_SETFL, O_ASYNC | O_NONBLOCK);
        write(p[1], "d", 1);
        io_taken("read-write-data");
        read(p[0], sink, 1);
        io_taken("read-write-room");
        close(both);
        write(p[1], "e", 1);
        io_taken("closed");
        close(again);
        close(p[0]);
        close(p[1]);
        return 0;
    }
    if (!strcmp(mode, "pipe-reopen")) {
        /* A pipe or standard output opened again through its link is a
           new open file description, as Linux's fifo_open makes: status
           flags of its own, the same pipe, and an end that closes when
           its last description does. */
        int p[2];
        pipe(p);
        char link[64];
        snprintf(link, sizeof link, "/proc/self/fd/%d", p[1]);
        int writer = open(link, O_WRONLY | O_NONBLOCK);
        printf("writer: %#o first: %#o\n", fcntl(writer, F_GETFL), fcntl(p[1], F_GETFL));
        fcntl(writer, F_SETFL, 0);
        fcntl(p[1], F_SETFL, O_NONBLOCK);
        printf("setfl: writer %#o first %#o\n", fcntl(writer, F_GETFL), fcntl(p[1], F_GETFL));
        /* The same pipe, which fills at its size through either. */
        long filled = 0;
        char block[4096] = {0};
        for (;;) {
            long n = write(p[1], block, sizeof block);
            if (n <= 0) break;
            filled += n;
        }
        printf("filled=%ld errno=%d\n", filled, errno);
        fcntl(writer, F_SETFL, O_NONBLOCK);
        errno = 0;
        long full = write(writer, block, 1);
        printf("writer-full=%ld errno=%d\n", full, full < 0 ? errno : 0);
        char sink[4096];
        while (filled > 0) filled -= read(p[0], sink, sizeof sink);
        printf("through=%ld\n", (long)write(writer, "x", 1));
        printf("read=%ld\n", (long)read(p[0], sink, sizeof sink));
        /* The write end stays open while a description of it does. */
        fcntl(p[0], F_SETFL, O_NONBLOCK);
        close(p[1]);
        errno = 0;
        long n = read(p[0], sink, 1);
        printf("one-writer: read=%ld errno=%d\n", n, n < 0 ? errno : 0);
        close(writer);
        printf("no-writer: read=%ld\n", (long)read(p[0], sink, 1));
        /* The read end, opened again without blocking. */
        int q[2];
        pipe(q);
        snprintf(link, sizeof link, "/proc/self/fd/%d", q[0]);
        int reader = open(link, O_RDONLY | O_NONBLOCK);
        errno = 0;
        n = read(reader, sink, 1);
        printf("reader: %#o first: %#o read=%ld errno=%d\n", fcntl(reader, F_GETFL), fcntl(q[0], F_GETFL), n,
               n < 0 ? errno : 0);
        write(q[1], "y", 1);
        printf("reader-read=%ld\n", (long)read(reader, sink, 1));
        close(reader);
        close(q[0]);
        close(q[1]);
        close(p[0]);
        /* Either end's link opens either end, as a pipe (unlike a FIFO)
           neither waits for the other end nor refuses a writer without a
           reader: a writer through the read end, a reader through the
           write end, and an end all of whose descriptions closed. */
        int e[2];
        pipe(e);
        snprintf(link, sizeof link, "/proc/self/fd/%d", e[0]);
        int other = open(link, O_WRONLY);
        long wrote = write(other, "a", 1);
        n = read(e[0], sink, 1);
        printf("writer-through-reader: %#o wrote=%ld read=%ld\n", fcntl(other, F_GETFL), wrote, n);
        close(other);
        snprintf(link, sizeof link, "/proc/self/fd/%d", e[1]);
        other = open(link, O_RDONLY);
        wrote = write(e[1], "b", 1);
        n = read(other, sink, 1);
        printf("reader-through-writer: %#o wrote=%ld read=%ld\n", fcntl(other, F_GETFL), wrote, n);
        close(other);
        close(e[1]);
        fcntl(e[0], F_SETFL, O_NONBLOCK);
        printf("writers-gone: read=%ld\n", (long)read(e[0], sink, 1));
        snprintf(link, sizeof link, "/proc/self/fd/%d", e[0]);
        other = open(link, O_WRONLY | O_NONBLOCK);
        errno = 0;
        n = read(e[0], sink, 1);
        printf("writer-again: open=%d read=%ld errno=%d", other >= 0, n, n < 0 ? errno : 0);
        wrote = write(other, "c", 1);
        n = read(e[0], sink, 1);
        printf(" wrote=%ld read=%ld", wrote, n);
        close(other);
        printf(" after=%ld\n", (long)read(e[0], sink, 1));
        close(e[0]);
        pipe(e);
        /* What the readers left unread stays for the next one. */
        write(e[1], "z", 1);
        close(e[0]);
        signal(SIGPIPE, SIG_IGN);
        errno = 0;
        n = write(e[1], "d", 1);
        printf("readers-gone: wrote=%ld errno=%d\n", n, n < 0 ? errno : 0);
        snprintf(link, sizeof link, "/proc/self/fd/%d", e[1]);
        other = open(link, O_RDONLY);
        wrote = write(e[1], "e", 1);
        n = read(other, sink, 2);
        printf("reader-again: open=%d wrote=%ld read=%ld %.*s\n", other >= 0, wrote, n, n > 0 ? (int)n : 0, sink);
        close(other);
        close(e[1]);
        /* O_RDWR opens both ends at once: it reads what it writes, is
           readable and writable, and with every other description gone
           sees neither the end of the pipe nor EPIPE. */
        pipe(e);
        snprintf(link, sizeof link, "/proc/self/fd/%d", e[0]);
        int both = open(link, O_RDWR | O_NONBLOCK);
        struct pollfd ready = {.fd = both, .events = POLLIN | POLLOUT};
        poll(&ready, 1, 0);
        printf("read-write: %#o revents=%#x", fcntl(both, F_GETFL), ready.revents);
        wrote = write(both, "fg", 2);
        n = read(both, sink, 1);
        printf(" wrote=%ld read=%ld", wrote, n);
        n = read(e[0], sink, 1);
        poll(&ready, 1, 0);
        printf(" other-read=%ld %c revents=%#x\n", n, sink[0], ready.revents);
        close(e[0]);
        close(e[1]);
        errno = 0;
        n = read(both, sink, 1);
        printf("read-write-alone: read=%ld errno=%d", n, n < 0 ? errno : 0);
        poll(&ready, 1, 0);
        wrote = write(both, "h", 1);
        n = read(both, sink, 1);
        printf(" revents=%#x wrote=%ld read=%ld\n", ready.revents, wrote, n);
        close(both);
        /* Standard output, opened again without blocking. */
        int out = open("/dev/stdout", O_WRONLY | O_NONBLOCK);
        printf("stdout: %#o first: %#o\n", fcntl(out, F_GETFL), fcntl(1, F_GETFL));
        close(out);
        return 0;
    }
    if (!strcmp(mode, "open-flags")) {
        /* What F_GETFL gives, as Linux keeps f_flags: the open flags less
           O_CLOEXEC (build_open_flags) and O_CREAT, O_EXCL, O_NOCTTY and
           O_TRUNC (do_dentry_open), with O_LARGEFILE for a file opened by
           path or a memfd (force_o_largefile), but only O_DIRECTORY,
           O_NOFOLLOW and O_PATH for an O_PATH one. Pipes, sockets and the
           kernel's own files have no O_LARGEFILE. */
        char tmp[] = "/tmp/paludarium-flagsXXXXXX";
        close(mkstemp(tmp));
        struct {
            const char *name;
            const char *path;
            int flags;
        } opens[] = {
            {"rdonly", tmp, O_RDONLY},
            {"creat-trunc", tmp, O_WRONLY | O_CREAT | O_TRUNC},
            {"append-cloexec-noctty", tmp, O_RDWR | O_APPEND | O_CLOEXEC | O_NOCTTY},
            {"nonblock-sync", tmp, O_RDONLY | O_NONBLOCK | O_SYNC},
            {"dsync-noatime-nofollow", tmp, O_WRONLY | O_DSYNC | O_NOATIME | O_NOFOLLOW},
            {"directory", "/tmp", O_RDONLY | O_DIRECTORY},
            {"path", tmp, O_PATH},
            {"path-all", "/tmp", O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK},
            {"null", "/dev/null", O_RDWR | O_CREAT},
            {"proc", "/proc/self/status", O_RDONLY | O_CLOEXEC},
        };
        for (size_t i = 0; i < sizeof opens / sizeof opens[0]; i++) {
            errno = 0;
            int fd = open(opens[i].path, opens[i].flags, 0600);
            printf("%s: fd=%d errno=%d", opens[i].name, fd >= 0, fd < 0 ? errno : 0);
            if (fd >= 0) {
                printf(" flags=%#o", fcntl(fd, F_GETFL));
                int dup = fcntl(fd, F_DUPFD_CLOEXEC, 0);
                printf(" dup=%#o", fcntl(dup, F_GETFL));
                close(dup);
                close(fd);
            }
            putchar('\n');
        }
        /* F_SETFL changes only what it may, and the rest stays. */
        int fd = open(tmp, O_RDWR | O_TRUNC | O_CLOEXEC);
        fcntl(fd, F_SETFL, O_APPEND | O_NONBLOCK | O_CREAT | O_TRUNC);
        printf("setfl: flags=%#o\n", fcntl(fd, F_GETFL));
        close(fd);
        int p[2];
        pipe2(p, O_CLOEXEC | O_NONBLOCK);
        printf("pipe: %#o %#o\n", fcntl(p[0], F_GETFL), fcntl(p[1], F_GETFL));
        /* A pipe or standard output opened by path, through a link to it,
           is an open by path all the same. */
        int q[2];
        pipe(q);
        char link[64];
        snprintf(link, sizeof link, "/proc/self/fd/%d", q[1]);
        int writer = open(link, O_WRONLY | O_CLOEXEC);
        printf("pipe-by-path: %#o first: %#o\n", fcntl(writer, F_GETFL), fcntl(q[1], F_GETFL));
        int out = open("/dev/stdout", O_WRONLY);
        printf("stdout-by-path: %#o\n", fcntl(out, F_GETFL));
        close(writer);
        close(out);
        close(q[0]);
        close(q[1]);
        int sv[2];
        socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv);
        printf("socketpair: %#o\n", fcntl(sv[0], F_GETFL));
        int memfd = memfd_create("flags", MFD_CLOEXEC);
        printf("memfd: %#o\n", fcntl(memfd, F_GETFL));
        int event = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
        printf("eventfd: %#o\n", fcntl(event, F_GETFL));
        int poll = epoll_create1(EPOLL_CLOEXEC);
        printf("epoll: %#o\n", fcntl(poll, F_GETFL));
        close(p[0]);
        close(p[1]);
        close(sv[0]);
        close(sv[1]);
        close(memfd);
        close(event);
        close(poll);
        unlink(tmp);
        return 0;
    }
    if (!strcmp(mode, "proc-block-size")) {
        /* /proc is procfs, whose superblock Linux gives a block size of
           1024 (proc_fill_super): stat, statx, FIGETBSZ and statfs all
           give it, with procfs's type. A link in /proc/self/fd is procfs's
           itself, but leads to its file, which is the file's own. */
        path_block_size("status", "/proc/self/status");
        path_block_size("mountinfo", "/proc/self/mountinfo");
        path_block_size("self", "/proc/self");
        path_block_size("fd", "/proc/self/fd");
        path_block_size("missing", "/proc/self/missing");
        int status = open("/proc/self/status", O_RDONLY);
        descriptor_block_size("status-fd", status);
        int dir = open("/proc/self/fd", O_RDONLY | O_DIRECTORY);
        descriptor_block_size("fd-dir", dir);
        char tmp[] = "/tmp/paludarium-blockXXXXXX";
        int file = mkstemp(tmp);
        char link[64];
        snprintf(link, sizeof link, "/proc/self/fd/%d", file);
        struct stat target = {0}, through = {0}, link_stat = {0};
        struct statfs target_fs = {0}, through_fs = {0};
        fstat(file, &target);
        fstatfs(file, &target_fs);
        stat(link, &through);
        lstat(link, &link_stat);
        statfs(link, &through_fs);
        printf("  link: lstat=%ld stat-same=%d statfs-same=%d\n", (long)link_stat.st_blksize,
               through.st_blksize == target.st_blksize,
               through_fs.f_type == target_fs.f_type && through_fs.f_bsize == target_fs.f_bsize);
        /* A link for a descriptor that is not open is not there. */
        char closed[64];
        snprintf(closed, sizeof closed, "/proc/self/fd/%d", 900);
        path_block_size("closed-link", closed);
        int opened = open(link, O_RDONLY);
        struct stat reopened = {0};
        fstat(opened, &reopened);
        printf("  reopened-same=%d\n", reopened.st_blksize == target.st_blksize);
        /* The pseudo filesystems', devtmpfs's and a pipe's are the page's. */
        int null = open("/dev/null", O_RDONLY);
        struct stat null_stat = {0};
        fstat(null, &null_stat);
        printf("  null=%ld\n", (long)null_stat.st_blksize);
        int p[2];
        pipe(p);
        descriptor_block_size("pipe", p[0]);
        close(p[0]);
        close(p[1]);
        close(null);
        close(opened);
        close(file);
        unlink(tmp);
        close(dir);
        close(status);
        return 0;
    }
    if (!strcmp(mode, "socket-passrights")) {
        /* SO_PASSRIGHTS on AF_UNIX sockets, as Linux's sock.c and af_unix
           have it: on for a new socket, and set to 0 a socket takes no
           descriptors, so a send that passes some to it is EPERM, past the
           receiver's shutdown (EPIPE) and before a full queue (EAGAIN),
           and a stream send of no bytes passes nothing to refuse. What
           waits is still read whole. A socket a listener accepts takes the
           listener's as it was when the client connected. */
        int p[2];
        if (pipe(p) != 0) {
            perror("pipe");
            return 1;
        }
        const int types[] = {SOCK_STREAM, SOCK_DGRAM, SOCK_SEQPACKET};
        for (int t = 0; t < 3; t++) {
            int sv[2];
            if (socketpair(AF_UNIX, types[t], 0, sv) != 0) {
                perror("socketpair");
                return 1;
            }
            printf("type %d\n", types[t]);
            int got = -7;
            socklen_t len = sizeof got;
            getsockopt(sv[1], SOL_SOCKET, SO_PASSRIGHTS, &got, &len);
            printf("  default=%d\n", got);
            int_option("short", sv[1], SO_PASSRIGHTS, 0, 2);
            /* Sent while it took them, and read after. */
            rights_send("before", sv[0], "a", 1, 0, p[0]);
            int_option("off", sv[1], SO_PASSRIGHTS, 0, 4);
            rights_receive("waiting", sv[1], 0);
            rights_send("refused", sv[0], "b", 1, 0, p[0]);
            rights_send("plain", sv[0], "c", 1, 0, -1);
            rights_receive("plain", sv[1], 0);
            rights_send("empty", sv[0], "", 0, 0, p[0]);
            if (types[t] == SOCK_STREAM) {
                rights_send("oob", sv[0], "de", 2, MSG_OOB, p[0]);
                rights_send("oob-alone", sv[0], "f", 1, MSG_OOB, p[0]);
            }
            /* The other way it still takes them. */
            rights_send("back", sv[1], "g", 1, 0, p[0]);
            rights_receive("back", sv[0], 0);
            int_option("on", sv[1], SO_PASSRIGHTS, 7, 4);
            rights_send("again", sv[0], "h", 1, 0, p[0]);
            rights_receive("again", sv[1], 0);
            /* Shut down for reading: EPIPE comes first. */
            int_option("off", sv[1], SO_PASSRIGHTS, 0, 4);
            shutdown(sv[1], SHUT_RD);
            rights_send("shut", sv[0], "i", 1, 0, p[0]);
            close(sv[0]);
            close(sv[1]);
        }
        /* A datagram to a socket's name, which refuses them. */
        {
            struct sockaddr_un a;
            socklen_t alen = unix_abstract(&a, "passrights-dgram");
            int r = socket(AF_UNIX, SOCK_DGRAM, 0), w = socket(AF_UNIX, SOCK_DGRAM, 0);
            if (r < 0 || w < 0 || bind(r, (struct sockaddr *)&a, alen) != 0) {
                perror("dgram");
                return 1;
            }
            printf("named\n");
            int_option("off", r, SO_PASSRIGHTS, 0, 4);
            struct iovec iov = {"j", 1};
            union { char bytes[CMSG_SPACE(sizeof(int))]; struct cmsghdr align; } control;
            struct msghdr message = {.msg_name = &a, .msg_namelen = alen, .msg_iov = &iov, .msg_iovlen = 1,
                                     .msg_control = control.bytes, .msg_controllen = sizeof control.bytes};
            struct cmsghdr *header = CMSG_FIRSTHDR(&message);
            header->cmsg_level = SOL_SOCKET;
            header->cmsg_type = SCM_RIGHTS;
            header->cmsg_len = CMSG_LEN(sizeof(int));
            memcpy(CMSG_DATA(header), &p[0], sizeof p[0]);
            errno = 0;
            long n = sendmsg(w, &message, MSG_DONTWAIT);
            printf("  sendto: sent=%ld errno=%d\n", n, n < 0 ? errno : 0);
            message.msg_control = NULL;
            message.msg_controllen = 0;
            errno = 0;
            n = sendmsg(w, &message, MSG_DONTWAIT);
            printf("  sendto-plain: sent=%ld errno=%d\n", n, n < 0 ? errno : 0);
            rights_receive("named", r, 0);
            close(r);
            close(w);
        }
        const int listening[] = {SOCK_STREAM, SOCK_SEQPACKET};
        for (int t = 0; t < 2; t++) {
            struct sockaddr_un a;
            socklen_t alen = unix_abstract(&a, "passrights");
            int l = socket(AF_UNIX, listening[t], 0);
            if (l < 0 || bind(l, (struct sockaddr *)&a, alen) != 0 || listen(l, 4) != 0) {
                perror("listener");
                return 1;
            }
            printf("listener %d\n", listening[t]);
            int_option("listener", l, SO_PASSRIGHTS, 0, 4);
            int first = socket(AF_UNIX, listening[t], 0);
            if (connect(first, (struct sockaddr *)&a, alen) != 0) {
                perror("connect");
                return 1;
            }
            int_option("listener", l, SO_PASSRIGHTS, 1, 4);
            int second = socket(AF_UNIX, listening[t], 0);
            if (connect(second, (struct sockaddr *)&a, alen) != 0) {
                perror("connect");
                return 1;
            }
            int got = accept(l, NULL, NULL), value = -7;
            socklen_t len = sizeof value;
            getsockopt(got, SOL_SOCKET, SO_PASSRIGHTS, &value, &len);
            printf("  first-accepted=%d\n", value);
            rights_send("first", first, "k", 1, 0, p[0]);
            close(got);
            got = accept(l, NULL, NULL);
            value = -7;
            getsockopt(got, SOL_SOCKET, SO_PASSRIGHTS, &value, &len);
            printf("  second-accepted=%d\n", value);
            rights_send("second", second, "l", 1, 0, p[0]);
            rights_receive("second", got, 0);
            close(got);
            close(first);
            close(second);
            close(l);
        }
        close(p[0]);
        close(p[1]);
        return 0;
    }
    if (!strcmp(mode, "socket-passsec")) {
        /* SO_PASSSEC on AF_UNIX sockets, as Linux's sock.c and scm.c have
           it: the flag it sets, which getsockopt gives back, and, with no
           security module that gives a sender's context (AppArmor's
           socket_getpeersec_dgram is ENOPROTOOPT), no SCM_SECURITY, but a
           MSG_CTRUNC with no control buffer (scm_has_secdata). A socket a
           listener accepts takes its SO_PASSCRED, SO_PASSSEC and
           SO_PASSPIDFD as they were when the client connected
           (unix_stream_connect copies sk_scm_recv_flags). */
        const int types[] = {SOCK_STREAM, SOCK_DGRAM, SOCK_SEQPACKET};
        for (int t = 0; t < 3; t++) {
            int sv[2];
            if (socketpair(AF_UNIX, types[t], 0, sv) != 0) {
                perror("socketpair");
                return 1;
            }
            printf("type %d\n", types[t]);
            passing("none", sv[1]);
            int_option("short", sv[1], SO_PASSSEC, 1, 2);
            int_option("on", sv[1], SO_PASSSEC, 5, 4);
            passing("on", sv[1]);
            passing("peer", sv[0]);
            send(sv[0], "a", 1, 0);
            passsec_receive("no-control", sv[1], 0);
            send(sv[0], "b", 1, 0);
            passsec_receive("control", sv[1], 256);
            int_option("passcred", sv[1], SO_PASSCRED, 1, 4);
            send(sv[0], "c", 1, 0);
            passsec_receive("credentials", sv[1], 256);
            int_option("passcred", sv[1], SO_PASSCRED, 0, 4);
            int_option("off", sv[1], SO_PASSSEC, 0, 4);
            send(sv[0], "d", 1, 0);
            passsec_receive("off", sv[1], 0);
            close(sv[0]);
            close(sv[1]);
        }
        const int listening[] = {SOCK_STREAM, SOCK_SEQPACKET};
        for (int t = 0; t < 2; t++) {
            struct sockaddr_un a;
            socklen_t alen = unix_abstract(&a, "passsec");
            int l = socket(AF_UNIX, listening[t], 0);
            if (l < 0 || bind(l, (struct sockaddr *)&a, alen) != 0 || listen(l, 4) != 0) {
                perror("listener");
                return 1;
            }
            printf("listener %d\n", listening[t]);
            const int names[] = {SO_PASSCRED, SO_PASSSEC, SO_PASSPIDFD};
            int one = 1, zero = 0;
            for (int i = 0; i < 3; i++)
                setsockopt(l, SOL_SOCKET, names[i], &one, sizeof one);
            passing("listener", l);
            int first = socket(AF_UNIX, listening[t], 0);
            if (connect(first, (struct sockaddr *)&a, alen) != 0) {
                perror("connect");
                return 1;
            }
            /* What the listener sets after the connect does not reach the
               socket waiting to be accepted. */
            for (int i = 0; i < 3; i++)
                setsockopt(l, SOL_SOCKET, names[i], &zero, sizeof zero);
            int second = socket(AF_UNIX, listening[t], 0);
            if (connect(second, (struct sockaddr *)&a, alen) != 0) {
                perror("connect");
                return 1;
            }
            int got = accept(l, NULL, NULL);
            passing("first-accepted", got);
            passing("first-client", first);
            /* The accepted socket passes credentials, so what the client
               sends carries them. */
            send(first, "e", 1, 0);
            passsec_receive("first-message", got, 256);
            close(got);
            got = accept(l, NULL, NULL);
            passing("second-accepted", got);
            close(got);
            close(first);
            close(second);
            close(l);
        }
        return 0;
    }
    if (!strcmp(mode, "socket-timestamping")) {
        /* SO_TIMESTAMPING on socket pairs, as Linux's sock.c and af_unix
           have it: the flags it takes, which getsockopt gives back with no
           PTP clock (the _NEW form only when set through it), and the
           SCM_TIMESTAMPING after the SO_TIMESTAMP one that a datagram or
           packet receiver taking both gets, its first stamp the software
           one when the flags report it. Alone it stamps nothing, and a
           stream gets none. Flags past SOF_TIMESTAMPING_OPT_RX_FILTER are
           left out: older kernels refuse them. */
        int sv[2];
        long long sent;
        const int kinds[] = {SOCK_STREAM, SOCK_DGRAM, SOCK_SEQPACKET};
        for (int k = 0; k < 3; k++) {
            socketpair(AF_UNIX, kinds[k], 0, sv);
            printf("kind %d\n", kinds[k]);
            stamping_options("none", sv[1]);
            /* Refused: unknown flags, OPT_ID_TCP without OPT_ID, OPT_STATS
               without OPT_TSONLY, a PTP clock with no device, a short
               value. */
            stamping_option("unknown", sv[1], TSG_OLD, 1 << 19, 4);
            stamping_option("negative", sv[1], TSG_OLD, -1, 4);
            stamping_option("id-tcp", sv[1], TSG_OLD, 1 << 16, 4);
            stamping_option("stats", sv[1], TSG_OLD, 1 << 12, 4);
            stamping_option("bind-phc", sv[1], TSG_OLD, 1 << 15, 4);
            stamping_option("short", sv[1], TSG_OLD, 0x18, 2);
            stamping_options("refused", sv[1]);
            stamping_option("ids", sv[1], TSG_OLD, (1 << 7) | (1 << 16), 4);
            stamping_option("stats-tsonly", sv[1], TSG_OLD, (1 << 12) | (1 << 11), 4);
            stamping_options("taken", sv[1]);
            /* A struct so_timestamping, whose clock needs BIND_PHC, and a
               length of neither 4 nor 8, read as an int. */
            int both[2] = {0x18, 3};
            errno = 0;
            int r = setsockopt(sv[1], SOL_SOCKET, TSG_OLD, both, sizeof both);
            printf("  set struct=%d errno=%d\n", r, r ? errno : 0);
            stamping_options("struct", sv[1]);
            stamping_option("six", sv[1], TSG_OLD, 0x10, 6);
            stamping_options("six", sv[1]);
            /* _NEW shares SO_TIMESTAMP's _NEW flag. */
            int_option("ts-old", sv[1], TS_OLD, 1, 4);
            stamping_option("new", sv[1], TSG_NEW, 0x18, 4);
            stamping_options("new", sv[1]);
            timestamp_options("new", sv[1]);
            stamping_option("old", sv[1], TSG_OLD, 0x18, 4);
            stamping_options("old", sv[1]);
            timestamp_options("old", sv[1]);
            /* With SO_TIMESTAMP, each message gets both. */
            send(sv[0], "a", 1, 0);
            sent = real_ns();
            receive_stamped("both", sv[1], 256, MSG_DONTWAIT, sent, NULL);
            int_option("ts-ns", sv[1], TS_NS_OLD, 1, 4);
            send(sv[0], "b", 1, 0);
            sent = real_ns();
            receive_stamped("both-ns", sv[1], 256, MSG_DONTWAIT, sent, NULL);
            stamping_option("new", sv[1], TSG_NEW, 0x18, 4);
            send(sv[0], "c", 1, 0);
            sent = real_ns();
            receive_stamped("both-new", sv[1], 256, MSG_DONTWAIT, sent, NULL);
            /* The software stamp is reported unless filtered out. */
            const int reports[] = {0x10, 0x08, 0x10 | (1 << 17), 0x18 | (1 << 17), 0};
            for (int i = 0; i < 5; i++) {
                stamping_option("report", sv[1], TSG_OLD, reports[i], 4);
                send(sv[0], "d", 1, 0);
                sent = real_ns();
                receive_stamped("report", sv[1], 256, MSG_DONTWAIT, sent, NULL);
            }
            /* Without SO_TIMESTAMP, none. */
            stamping_option("alone", sv[1], TSG_OLD, 0x18, 4);
            int_option("ts-off", sv[1], TS_OLD, 0, 4);
            send(sv[0], "e", 1, 0);
            sent = real_ns();
            receive_stamped("alone", sv[1], 256, MSG_DONTWAIT, sent, NULL);
            /* A control buffer that holds less cuts it. */
            int_option("ts-old", sv[1], TS_OLD, 1, 4);
            const size_t rooms[] = {32, 40, 64, 88};
            for (int i = 0; i < 4; i++) {
                send(sv[0], "f", 1, 0);
                sent = real_ns();
                char label[16];
                snprintf(label, sizeof label, "room%zu", rooms[i]);
                receive_stamped(label, sv[1], rooms[i], MSG_DONTWAIT, sent, NULL);
            }
            close(sv[0]);
            close(sv[1]);
        }
        return 0;
    }
    if (!strcmp(mode, "socket-oob")) {
        /* A stream's out-of-band byte, as Linux's AF_UNIX keeps it: the last
           byte of a MSG_OOB send, which reads stop before, SIOCATMARK and
           POLLPRI show, and recv(MSG_OOB) takes; a read that reaches it with
           nothing read yet drops it. */
        int sv[2] = {-1, -1}, fd, flags;
        char buf[16];
        long n;
#define OOB_FRESH() do { close(sv[0]); close(sv[1]); socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, sv); } while (0)
#define OOB_READ(what, how, len) do { memset(buf, 0, sizeof buf); errno = 0; n = recv(sv[1], buf, len, how); \
        printf("  %s=%ld errno=%d data=%s\n", what, n, n < 0 ? errno : 0, buf); } while (0)
#define OOB_MARK(what) do { int at = -1; int r = ioctl(sv[1], SIOCATMARK, &at); \
        struct pollfd p = {sv[1], POLLIN | POLLPRI, 0}; poll(&p, 1, 0); \
        printf("  %s: atmark=%d r=%d revents=%#x\n", what, at, r, p.revents); } while (0)
        OOB_FRESH();
        puts("basic");
        errno = 0;
        n = send(sv[0], "abc", 3, MSG_OOB);
        printf("  send=%ld\n", n);
        OOB_MARK("sent");
        OOB_READ("read", 0, 8);
        OOB_MARK("at mark");
        struct iovec iov = {buf, 8};
        struct msghdr m = {.msg_iov = &iov, .msg_iovlen = 1};
        memset(buf, 0, sizeof buf);
        n = recvmsg(sv[1], &m, MSG_OOB | MSG_PEEK);
        printf("  peek-oob=%ld data=%s flags=%#x\n", n, buf, m.msg_flags);
        memset(buf, 0, sizeof buf);
        m.msg_flags = 0;
        n = recvmsg(sv[1], &m, MSG_OOB);
        printf("  recvmsg-oob=%ld data=%s flags=%#x\n", n, buf, m.msg_flags);
        OOB_MARK("taken");
        OOB_READ("oob-again", MSG_OOB, 8);
        OOB_READ("read-again", 0, 8);
        puts("data after the mark");
        OOB_FRESH();
        send(sv[0], "abc", 3, MSG_OOB);
        send(sv[0], "de", 2, 0);
        OOB_READ("read", 0, 8);
        OOB_READ("peek-at-mark", MSG_PEEK, 8);
        OOB_READ("read-at-mark", 0, 8);
        OOB_READ("oob", MSG_OOB, 8);
        puts("out of band first");
        OOB_FRESH();
        send(sv[0], "abc", 3, MSG_OOB);
        send(sv[0], "de", 2, 0);
        OOB_READ("oob", MSG_OOB, 8);
        OOB_READ("read", 0, 8);
        OOB_READ("read2", 0, 8);
        puts("a later one");
        OOB_FRESH();
        send(sv[0], "ab", 2, MSG_OOB);
        send(sv[0], "cd", 2, MSG_OOB);
        OOB_READ("read", 0, 8);
        OOB_MARK("at mark");
        OOB_READ("oob", MSG_OOB, 8);
        OOB_READ("read2", 0, 8);
        puts("one byte, dropped by a read");
        OOB_FRESH();
        send(sv[0], "x", 1, MSG_OOB);
        OOB_MARK("one");
        OOB_READ("read", 0, 8);
        OOB_MARK("dropped");
        OOB_READ("oob", MSG_OOB, 8);
        puts("small reads");
        OOB_FRESH();
        send(sv[0], "abcd", 4, MSG_OOB);
        OOB_READ("read2", 0, 2);
        OOB_READ("read2b", 0, 2);
        OOB_READ("read2c", 0, 2);
        puts("select and epoll");
        OOB_FRESH();
        send(sv[0], "ab", 2, MSG_OOB);
        fd_set except;
        FD_ZERO(&except);
        FD_SET(sv[1], &except);
        struct timeval zero = {0, 0};
        n = select(sv[1] + 1, NULL, NULL, &except, &zero);
        printf("  select=%ld except=%d\n", n, FD_ISSET(sv[1], &except));
        int ep = epoll_create1(0);
        struct epoll_event ev = {.events = EPOLLPRI}, out = {0};
        epoll_ctl(ep, EPOLL_CTL_ADD, sv[1], &ev);
        n = epoll_wait(ep, &out, 1, 0);
        printf("  epoll=%ld events=%#x\n", n, out.events);
        OOB_READ("oob", MSG_OOB, 8);
        n = epoll_wait(ep, &out, 1, 0);
        printf("  epoll-after=%ld\n", n);
        close(ep);
        puts("errors");
        OOB_FRESH();
        errno = 0;
        n = send(sv[0], "", 0, MSG_OOB);
        printf("  empty=%ld errno=%d\n", n, errno);
        OOB_READ("none", MSG_OOB, 8);
        int pipe_fds[2];
        pipe(pipe_fds);
        /* One byte sent out of band with a descriptor. */
        union { char bytes[CMSG_SPACE(sizeof(int))]; struct cmsghdr align; } control;
        struct iovec one = {"z", 1};
        struct msghdr with = {.msg_iov = &one, .msg_iovlen = 1, .msg_control = control.bytes,
                              .msg_controllen = sizeof control.bytes};
        struct cmsghdr *header = CMSG_FIRSTHDR(&with);
        header->cmsg_level = SOL_SOCKET;
        header->cmsg_type = SCM_RIGHTS;
        header->cmsg_len = CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(header), pipe_fds, sizeof(int));
        n = sendmsg(sv[0], &with, MSG_OOB);
        printf("  with-fds=%ld\n", n);
        OOB_MARK("with fds");
        n = receive_fd(sv[1], buf, 8, MSG_OOB, &fd, &flags);
        printf("  oob-fds=%ld errno=%d fd=%d flags=%#x\n", n, n < 0 ? errno : 0, fd >= 0, flags);
        OOB_READ("read-fds", 0, 8);
        close(pipe_fds[0]);
        close(pipe_fds[1]);
        shutdown(sv[1], SHUT_RD);
        errno = 0;
        n = send(sv[0], "y", 1, MSG_OOB | MSG_NOSIGNAL);
        printf("  shut=%ld errno=%d\n", n, errno);
        puts("waitall stops at the mark");
        close(sv[0]);
        close(sv[1]);
        socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
        send(sv[0], "abc", 3, MSG_OOB);
        send(sv[0], "de", 2, 0);
        memset(buf, 0, sizeof buf);
        n = recv(sv[1], buf, 8, MSG_WAITALL);
        printf("  waitall=%ld data=%s\n", n, buf);
        close(sv[0]);
        memset(buf, 0, sizeof buf);
        n = recv(sv[1], buf, 8, MSG_WAITALL);
        printf("  waitall2=%ld data=%s\n", n, buf);
        close(sv[1]);
        /* A byte that comes out of band while MSG_WAITALL waits ends it. */
        socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
        fflush(stdout);
        pid_t pid = fork();
        if (pid == 0) {
            send(sv[0], "ab", 2, 0);
            usleep(50000);
            send(sv[0], "x", 1, MSG_OOB);
            usleep(50000);
            send(sv[0], "cd", 2, 0);
            _exit(0);
        }
        memset(buf, 0, sizeof buf);
        n = recv(sv[1], buf, 8, MSG_WAITALL);
        printf("  waitall-late=%ld data=%s\n", n, buf);
        int status;
        waitpid(pid, &status, 0);
        OOB_READ("late-oob", MSG_OOB, 8);
        OOB_READ("late-rest", 0, 8);
        close(sv[0]);
        close(sv[1]);
#undef OOB_FRESH
#undef OOB_READ
#undef OOB_MARK
        return 0;
    }
    if (!strcmp(mode, "socket-flags")) {
        /* recvmsg and recvfrom flags on socket pairs: MSG_PEEK leaves the
           data and copies the descriptors, MSG_WAITALL fills a stream's
           buffer, MSG_TRUNC gives a message's whole length, and MSG_OOB
           finds no out-of-band byte where none was sent; other flags are
           ignored. */
        int sv[2], pipe_fds[2], fd, flags;
        char buf[16];
        pipe(pipe_fds);
        socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
        send(sv[0], "ab", 2, 0);
        send_fds(sv[0], "cd", 2, pipe_fds, 1);
        send(sv[0], "ef", 2, 0);
        memset(buf, 0, sizeof buf);
        long n = receive_fd(sv[1], buf, 8, MSG_PEEK, &fd, &flags);
        printf("stream peek=%ld data=%s fd=%d same=%d\n", n, buf, fd >= 0, same_file(fd, pipe_fds[0]));
        int peeked = fd;
        memset(buf, 0, sizeof buf);
        n = receive_fd(sv[1], buf, 8, 0, &fd, &flags);
        printf("stream read=%ld data=%s fd=%d same=%d other=%d\n", n, buf, fd >= 0, same_file(fd, pipe_fds[0]), fd != peeked);
        close(fd);
        close(peeked);
        memset(buf, 0, sizeof buf);
        n = recv(sv[1], buf, 8, MSG_PEEK | MSG_DONTWAIT);
        printf("stream rest-peek=%ld data=%s\n", n, buf);
        memset(buf, 0, sizeof buf);
        n = recv(sv[1], buf, 8, MSG_DONTWAIT);
        printf("stream rest=%ld data=%s\n", n, buf);
        /* MSG_WAITALL stops at a write that passes descriptors. */
        send(sv[0], "gh", 2, 0);
        send_fds(sv[0], "ij", 2, pipe_fds, 1);
        send(sv[0], "kl", 2, 0);
        memset(buf, 0, sizeof buf);
        n = receive_fd(sv[1], buf, 8, MSG_WAITALL, &fd, &flags);
        printf("waitall-fds=%ld data=%s fd=%d\n", n, buf, fd >= 0);
        close(fd);
        recv(sv[1], buf, 8, MSG_DONTWAIT);
        errno = 0;
        n = recv(sv[1], buf, 8, MSG_OOB | MSG_DONTWAIT);
        printf("stream oob=%ld errno=%d\n", n, errno);
        /* A stream checks the address before MSG_OOB (EISCONN). */
        struct sockaddr_un nowhere = {.sun_family = AF_UNIX, .sun_path = "/tmp/none"};
        errno = 0;
        n = sendto(sv[0], "z", 1, MSG_OOB, (struct sockaddr *)&nowhere, sizeof nowhere);
        printf("stream oob-address=%ld errno=%d\n", n, errno);
        fflush(stdout);
        /* MSG_WAITALL waits for writes to come, and ends with the stream. */
        pid_t pid = fork();
        if (pid == 0) {
            close(sv[1]);
            send(sv[0], "12", 2, 0);
            usleep(20000);
            send(sv[0], "34", 2, 0);
            usleep(20000);
            send(sv[0], "56", 2, 0);
            usleep(20000);
            send(sv[0], "78", 2, MSG_MORE | MSG_EOR);
            _exit(0);
        }
        close(sv[0]);
        memset(buf, 0, sizeof buf);
        n = recv(sv[1], buf, 6, MSG_WAITALL);
        printf("waitall=%ld data=%s\n", n, buf);
        memset(buf, 0, sizeof buf);
        n = recv(sv[1], buf, 6, MSG_WAITALL);
        printf("waitall-end=%ld data=%s\n", n, buf);
        int status;
        waitpid(pid, &status, 0);
        close(sv[1]);
        /* A message's whole length with MSG_TRUNC, peeked or taken. */
        const int kinds[] = {SOCK_DGRAM, SOCK_SEQPACKET};
        const char *names[] = {"dgram", "seqpacket"};
        for (int k = 0; k < 2; k++) {
            socketpair(AF_UNIX, kinds[k], 0, sv);
            send(sv[0], "abcdef", 6, MSG_EOR | MSG_DONTROUTE);
            send_fds(sv[0], "xy", 2, pipe_fds, 1);
            memset(buf, 0, sizeof buf);
            n = receive_fd(sv[1], buf, 2, MSG_TRUNC | MSG_PEEK, &fd, &flags);
            printf("%s peek-trunc=%ld data=%s flags=%#x\n", names[k], n, buf, flags);
            memset(buf, 0, sizeof buf);
            n = recvfrom(sv[1], buf, 2, MSG_TRUNC, NULL, NULL);
            printf("%s recvfrom-trunc=%ld data=%s\n", names[k], n, buf);
            memset(buf, 0, sizeof buf);
            n = receive_fd(sv[1], buf, 8, MSG_PEEK, &fd, &flags);
            printf("%s peek-fd=%ld data=%s fd=%d same=%d\n", names[k], n, buf, fd >= 0, same_file(fd, pipe_fds[0]));
            peeked = fd;
            n = receive_fd(sv[1], buf, 8, MSG_WAITALL | MSG_ERRQUEUE, &fd, &flags);
            printf("%s read-fd=%ld fd=%d other=%d\n", names[k], n, fd >= 0, fd != peeked);
            close(fd);
            close(peeked);
            errno = 0;
            n = recv(sv[1], buf, 8, MSG_OOB | MSG_DONTWAIT);
            printf("%s oob=%ld errno=%d\n", names[k], n, errno);
            errno = 0;
            n = send(sv[0], "z", 1, MSG_OOB);
            printf("%s send-oob=%ld errno=%d\n", names[k], n, errno);
            /* The address is read before MSG_OOB is refused. */
            struct sockaddr_un none = {.sun_family = AF_UNIX, .sun_path = "/tmp/none"};
            errno = 0;
            n = sendto(sv[0], "z", 1, MSG_OOB, (struct sockaddr *)&none, 200);
            printf("%s oob-long-address=%ld errno=%d\n", names[k], n, errno);
            errno = 0;
            n = sendto(sv[0], "z", 1, MSG_OOB, (struct sockaddr *)&none, sizeof none);
            printf("%s oob-address=%ld errno=%d\n", names[k], n, errno);
            close(sv[0]);
            close(sv[1]);
        }
        return 0;
    }
    if (!strcmp(mode, "unix-abstract")) {
        /* AF_UNIX sockets from socket(), named in the abstract namespace
           (af_unix.c): bind, listen, connect, accept and the names, the
           errors of each state, and a listener's close resetting what it
           had not accepted. An autobound name is random: only its length is
           printed. */
        signal(SIGPIPE, SIG_IGN);
        int types[] = {SOCK_STREAM, SOCK_SEQPACKET};
        for (int t = 0; t < 2; t++) {
            int type = types[t];
            struct sockaddr_un a;
            char buf[16];
            printf("type=%d\n", type);
            int u = socket(AF_UNIX, type, 0);
            unix_call("socket-ok", u >= 0 ? 0 : -1);
            unix_name("name-unbound", u, 0, NULL, 0);
            unix_name("peer-unbound", u, 1, NULL, 0);
            unix_poll("unbound", u);
            unix_call("send-unbound", send(u, "x", 1, 0));
            unix_call("recv-unbound", recv(u, buf, 1, MSG_DONTWAIT));
            unix_call("listen-unbound", listen(u, 1));
            unix_call("accept-unbound", accept(u, NULL, NULL));
            close(u);
            int l = socket(AF_UNIX, type, 0);
            socklen_t len = unix_abstract(&a, "listener");
            unix_call("bind-short", bind(l, (void *)&a, 1));
            a.sun_family = AF_INET;
            unix_call("bind-family", bind(l, (void *)&a, len));
            a.sun_family = AF_UNIX;
            unix_call("bind", bind(l, (void *)&a, len));
            unix_name("name-bound", l, 0, &a, len);
            unix_call("bind-again", bind(l, (void *)&a, len));
            int o = socket(AF_UNIX, type, 0);
            unix_call("bind-in-use", bind(o, (void *)&a, len));
            unix_call("connect-not-listening", connect(o, (void *)&a, len));
            unix_call("listen", listen(l, 1));
            unix_poll("listen-empty", l);
            unix_call("listen-again", listen(l, 5));
            int pending[3];
            for (int i = 0; i < 3; i++) {
                pending[i] = socket(AF_UNIX, type | SOCK_NONBLOCK, 0);
                unix_call("connect", connect(pending[i], (void *)&a, len));
            }
            unix_poll("listen-pending", l);
            unix_poll("client-pending", pending[0]);
            unix_name("client-peer", pending[0], 1, &a, len);
            unix_name("client-name", pending[0], 0, NULL, 0);
            unix_call("connect-again", connect(pending[0], (void *)&a, len));
            unix_call("connect-listener", connect(l, (void *)&a, len));
            unix_call("send-pending", send(pending[0], "hi", 2, 0));
            struct sockaddr_un peer;
            socklen_t peer_len = sizeof peer;
            memset(&peer, 0x55, sizeof peer);
            int s = accept4(l, (void *)&peer, &peer_len, SOCK_CLOEXEC);
            unix_call("accept-ok", s >= 0 ? 0 : -1);
            printf("accept-address len=%u family=%d\n", (unsigned)peer_len, peer.sun_family);
            printf("cloexec=%d nonblock=%d\n", !!(fcntl(s, F_GETFD) & FD_CLOEXEC),
                   !!(fcntl(s, F_GETFL) & O_NONBLOCK));
            unix_name("server-name", s, 0, &a, len);
            unix_name("server-peer", s, 1, NULL, 0);
            unix_poll("server", s);
            unix_call("recv-server", recv(s, buf, sizeof buf, 0));
            unix_call("send-server", send(s, "yo", 2, 0));
            unix_call("recv-client", recv(pending[0], buf, sizeof buf, 0));
            int on;
            socklen_t on_len = sizeof on;
            getsockopt(l, SOL_SOCKET, SO_ACCEPTCONN, &on, &on_len);
            printf("acceptconn-listener=%d\n", on);
            getsockopt(s, SOL_SOCKET, SO_ACCEPTCONN, &on, &on_len);
            printf("acceptconn-server=%d\n", on);
            unix_call("listen-connected", listen(s, 1));
            unix_call("accept-connected", accept(s, NULL, NULL));
            close(l);
            usleep(10000);
            unix_poll("pending-after-close", pending[1]);
            unix_call("recv-reset", recv(pending[1], buf, sizeof buf, MSG_DONTWAIT));
            unix_call("recv-after-reset", recv(pending[1], buf, sizeof buf, MSG_DONTWAIT));
            unix_call("send-after-reset", send(pending[1], "x", 1, 0));
            int late = socket(AF_UNIX, type, 0);
            unix_call("connect-closed-name", connect(late, (void *)&a, len));
            int again = socket(AF_UNIX, type, 0);
            unix_call("bind-freed-name", bind(again, (void *)&a, len));
            int autobound = socket(AF_UNIX, type, 0);
            unix_call("autobind", bind(autobound, (void *)&a, sizeof(sa_family_t)));
            unix_name("autobind-name", autobound, 0, NULL, 0);
            unix_call("autobind-again", bind(autobound, (void *)&a, sizeof(sa_family_t)));
            close(s);
            for (int i = 0; i < 3; i++) close(pending[i]);
            close(o);
            close(late);
            close(again);
            close(autobound);
        }
        /* A full queue: backlog 0 takes one connection. */
        struct sockaddr_un a;
        socklen_t len = unix_abstract(&a, "full");
        int full = socket(AF_UNIX, SOCK_STREAM, 0);
        bind(full, (void *)&a, len);
        listen(full, 0);
        for (int i = 0; i < 3; i++) {
            int c = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0);
            unix_call("connect-full", connect(c, (void *)&a, len));
        }
        /* A path that no socket has. */
        struct sockaddr_un p = {.sun_family = AF_UNIX};
        strcpy(p.sun_path, "/nonexistent-socket");
        int c = socket(AF_UNIX, SOCK_STREAM, 0);
        unix_call("connect-missing-path", connect(c, (void *)&p, sizeof p));
        /* A file of this process's own, as connect needs write permission
           there, which an unprivileged native run lacks on "/". */
        strcpy(p.sun_path, "unix-not-a-socket");
        close(open(p.sun_path, O_CREAT | O_WRONLY, 0600));
        unix_call("connect-not-a-socket", connect(c, (void *)&p, sizeof p));
        unlink(p.sun_path);
        unix_call("socket-protocol", socket(AF_UNIX, SOCK_STREAM, 2));
        unix_call("socket-type", socket(AF_UNIX, 4, 0));
        return 0;
    }
    if (!strcmp(mode, "unix-path")) {
        /* AF_UNIX sockets bound to paths in the file system (af_unix.c's
           unix_bind_bsd and unix_find_bsd): the socket file bind makes, what
           finds it (its inode, so a rename keeps it and an unlink loses it),
           and the errors of each. It works in a directory of its own. */
        signal(SIGPIPE, SIG_IGN);
        char dir[64];
        snprintf(dir, sizeof dir, "unix-path-%d", getpid());
        mkdir(dir, 0700);
        if (chdir(dir)) return 98;
        umask(022);
        struct sockaddr_un a = {.sun_family = AF_UNIX};
        socklen_t len;
#define UNIX_PATH(p) (strcpy(a.sun_path, p), len = (socklen_t)(sizeof(sa_family_t) + strlen(p)), (void *)&a)
        char buf[16];
        struct stat st;
        int l = socket(AF_UNIX, SOCK_STREAM, 0);
        unix_call("bind", bind(l, UNIX_PATH("sock"), len));
        {
            struct sockaddr_un n;
            socklen_t n_len = sizeof n;
            memset(&n, 0x55, sizeof n);
            getsockname(l, (void *)&n, &n_len);
            printf("name len=%u path=%s\n", (unsigned)n_len, n.sun_path);
        }
        unix_call("stat", stat("sock", &st));
        printf("socket=%d mode=%o size=%lld\n", S_ISSOCK(st.st_mode), (unsigned)(st.st_mode & 07777), (long long)st.st_size);
        unix_call("bind-again", bind(l, UNIX_PATH("sock2"), len));
        unix_call("again-left", access("sock2", F_OK));
        int o = socket(AF_UNIX, SOCK_STREAM, 0);
        unix_call("bind-in-use", bind(o, UNIX_PATH("sock"), len));
        unix_call("bind-missing-dir", bind(o, UNIX_PATH("missing/sock"), len));
        close(open("file", O_CREAT | O_WRONLY, 0600));
        unix_call("bind-file", bind(o, UNIX_PATH("file"), len));
        unix_call("bind-under-file", bind(o, UNIX_PATH("file/sock"), len));
        symlink("nowhere", "dangling");
        unix_call("bind-dangling", bind(o, UNIX_PATH("dangling"), len));
        unix_call("dangling-left", access("nowhere", F_OK));
        unix_call("connect-not-listening", connect(o, UNIX_PATH("sock"), len));
        unix_call("open", open("sock", O_RDONLY));
        {
            DIR *d = opendir(".");
            struct dirent *e;
            while ((e = readdir(d)))
                if (!strcmp(e->d_name, "sock")) printf("dirent-sock=%d\n", e->d_type == DT_SOCK);
            closedir(d);
        }
        unix_call("listen", listen(l, 4));
        int client = socket(AF_UNIX, SOCK_STREAM, 0);
        unix_call("connect", connect(client, UNIX_PATH("sock"), len));
        int server = accept(l, NULL, NULL);
        {
            struct sockaddr_un n;
            socklen_t n_len = sizeof n;
            getpeername(client, (void *)&n, &n_len);
            printf("peer len=%u path=%s\n", (unsigned)n_len, n.sun_path);
            send(server, "hi", 2, 0);
            n_len = sizeof n;
            memset(&n, 0x55, sizeof n);
            long r = recvfrom(client, buf, sizeof buf, 0, (void *)&n, &n_len);
            printf("from=%ld len=%u path=%s\n", r, (unsigned)n_len, n.sun_path);
        }
        int dg = socket(AF_UNIX, SOCK_DGRAM, 0);
        unix_call("connect-other-type", connect(dg, UNIX_PATH("sock"), len));
        int sp = socket(AF_UNIX, SOCK_SEQPACKET, 0);
        unix_call("connect-packet-to-stream", connect(sp, UNIX_PATH("sock"), len));
        unix_call("connect-file", connect(o, UNIX_PATH("file"), len));
        unix_call("connect-missing", connect(o, UNIX_PATH("missing"), len));
        unix_call("connect-under-file", connect(o, UNIX_PATH("file/x"), len));
        /* The path ends at its first 0. */
        memcpy(a.sun_path, "sock\0junk", 9);
        unix_call("connect-nul", connect(socket(AF_UNIX, SOCK_STREAM, 0), (void *)&a, sizeof(sa_family_t) + 9));
        unix_call("rename", rename("sock", "moved"));
        unix_call("connect-renamed", connect(socket(AF_UNIX, SOCK_STREAM, 0), UNIX_PATH("moved"), len));
        unix_call("connect-old-name", connect(o, UNIX_PATH("sock"), len));
        symlink("moved", "link");
        unix_call("connect-symlink", connect(socket(AF_UNIX, SOCK_STREAM, 0), UNIX_PATH("link"), len));
        unix_call("unlink", unlink("moved"));
        unix_call("connect-unlinked", connect(o, UNIX_PATH("link"), len));
        {
            struct sockaddr_un n;
            socklen_t n_len = sizeof n;
            getsockname(l, (void *)&n, &n_len);
            printf("name-after-unlink len=%u path=%s\n", (unsigned)n_len, n.sun_path);
        }
        unix_call("bind-unlinked-name", bind(o, UNIX_PATH("sock"), len));
        unix_call("connect-new-socket", connect(client = socket(AF_UNIX, SOCK_STREAM, 0), UNIX_PATH("sock"), len));
        close(o);
        unix_call("connect-closed", connect(socket(AF_UNIX, SOCK_STREAM, 0), UNIX_PATH("sock"), len));
        unix_call("closed-left", stat("sock", &st));
        printf("closed-socket=%d\n", S_ISSOCK(st.st_mode));
        /* Datagrams to a path, and the sender's path. */
        int r = socket(AF_UNIX, SOCK_DGRAM, 0);
        unix_call("bind-dgram", bind(r, UNIX_PATH("dgram"), len));
        unix_call("sendto-unbound", sendto(dg, "one", 3, 0, UNIX_PATH("dgram"), len));
        int named = socket(AF_UNIX, SOCK_DGRAM, 0);
        bind(named, UNIX_PATH("dgram-b"), len);
        unix_call("sendto-named", sendto(named, "two", 3, 0, UNIX_PATH("dgram"), len));
        unix_call("sendto-stream-path", sendto(named, "x", 1, 0, UNIX_PATH("sock"), len));
        unix_call("sendto-missing", sendto(named, "x", 1, 0, UNIX_PATH("missing"), len));
        for (int i = 0; i < 2; i++) {
            struct sockaddr_un n;
            socklen_t n_len = sizeof n;
            memset(&n, 0, sizeof n);
            long got = recvfrom(r, buf, sizeof buf, MSG_DONTWAIT, (void *)&n, &n_len);
            printf("dgram-from=%ld len=%u path=%s\n", got, (unsigned)n_len, n.sun_path);
        }
#undef UNIX_PATH
        const char *made[] = {"sock", "file", "dangling", "link", "dgram", "dgram-b"};
        for (unsigned i = 0; i < sizeof made / sizeof *made; i++) unlink(made[i]);
        if (chdir("..")) return 97;
        unix_call("rmdir", rmdir(dir));
        return 0;
    }
    if (!strcmp(mode, "unix-dgram-disconnect")) {
        /* A datagram socket that disconnects (af_unix.c's
           unix_dgram_disconnected), by connecting elsewhere, to AF_UNSPEC
           or by finding its peer gone: what it has not read goes, with the
           descriptors in it, and a peer connected back to it gets
           ECONNRESET once, from a read, a send or SO_ERROR, and POLLERR
           until then. */
        signal(SIGPIPE, SIG_IGN);
        struct sockaddr_un an, bn, cn;
        socklen_t al = unix_abstract(&an, "dc-a"), bl = unix_abstract(&bn, "dc-b"), cl = unix_abstract(&cn, "dc-c");
        struct sockaddr unspec = {.sa_family = AF_UNSPEC};
        char buf[16];
        int err;
        socklen_t err_len = sizeof err;
        int a = socket(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK, 0);
        int b = socket(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK, 0);
        int c = socket(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK, 0);
        bind(a, (void *)&an, al);
        bind(b, (void *)&bn, bl);
        bind(c, (void *)&cn, cl);
        /* a and b connected to each other; a reconnects with data unread. */
        connect(a, (void *)&bn, bl);
        connect(b, (void *)&an, al);
        unix_call("send-to-a", send(b, "x", 1, 0));
        unix_call("send-to-b", send(a, "y", 1, 0));
        unix_call("reconnect", connect(a, (void *)&cn, cl));
        unix_call("recv-purged", recv(a, buf, sizeof buf, 0));
        unix_poll("old-peer", b);
        err = -1;
        getsockopt(b, SOL_SOCKET, SO_ERROR, &err, &err_len);
        printf("so-error=%d\n", err);
        getsockopt(b, SOL_SOCKET, SO_ERROR, &err, &err_len);
        printf("so-error-again=%d\n", err);
        unix_poll("old-peer-after", b);
        unix_call("old-peer-kept", recv(b, buf, sizeof buf, 0));
        /* The error comes before a queued datagram, once. */
        connect(a, (void *)&bn, bl);
        unix_call("send-to-a-2", send(b, "x", 1, 0));
        unix_call("send-to-b-2", send(a, "z", 1, 0));
        unix_call("disconnect", connect(a, &unspec, sizeof unspec));
        unix_call("recv-error", recv(b, buf, sizeof buf, 0));
        unix_call("recv-after-error", recv(b, buf, sizeof buf, 0));
        /* And before a send. */
        connect(a, (void *)&bn, bl);
        unix_call("send-to-a-3", send(b, "x", 1, 0));
        connect(a, (void *)&cn, cl);
        unix_call("send-error", send(b, "w", 1, 0));
        unix_call("send-after-error", send(b, "w", 1, 0));
        /* With nothing unread nothing is reset; nor is a peer that is not
           connected back. */
        connect(a, (void *)&bn, bl);
        unix_call("reconnect-empty", connect(a, (void *)&cn, cl));
        unix_poll("peer-of-empty", b);
        connect(b, &unspec, sizeof unspec);
        connect(a, (void *)&bn, bl);
        unix_call("sendto-a", sendto(b, "v", 1, 0, (void *)&an, al));
        unix_call("reconnect-one-way", connect(a, (void *)&cn, cl));
        unix_call("recv-one-way", recv(a, buf, sizeof buf, 0));
        unix_poll("one-way-peer", b);
        /* Connecting again to the same socket keeps the queue. */
        unix_call("sendto-a-2", sendto(c, "u", 1, 0, (void *)&an, al));
        unix_call("connect-same", connect(a, (void *)&cn, cl));
        unix_call("recv-kept", recv(a, buf, sizeof buf, 0));
        /* The peer goes: the refused send drops the queue, and the
           descriptors in it close. */
        int pipe_fds[2];
        pipe(pipe_fds);
        int d = socket(AF_UNIX, SOCK_DGRAM, 0);
        connect(a, &unspec, sizeof unspec);
        connect(d, (void *)&an, al);
        unix_call("pass", send_fds(d, "p", 1, &pipe_fds[1], 1));
        close(pipe_fds[1]);
        close(d);
        connect(a, (void *)&cn, cl);
        close(c);
        unix_call("send-gone", send(a, "x", 1, 0));
        unix_call("recv-gone", recv(a, buf, sizeof buf, 0));
        unix_call("pipe-closed", read(pipe_fds[0], buf, 1));
        unix_call("send-after-gone", send(a, "x", 1, 0));
        /* A socket pair's end does the same. */
        int sp[2];
        socketpair(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK, 0, sp);
        send(sp[1], "1", 1, 0);
        send(sp[1], "2", 1, 0);
        close(sp[1]);
        unix_call("pair-read", recv(sp[0], buf, sizeof buf, 0));
        unix_call("pair-send", send(sp[0], "x", 1, 0));
        unix_call("pair-purged", recv(sp[0], buf, sizeof buf, 0));
        close(sp[0]);
        close(a);
        close(b);
        close(pipe_fds[0]);
        return 0;
    }
    if (!strcmp(mode, "unix-peercred")) {
        /* SO_PEERCRED and SO_PEERPIDFD of AF_UNIX sockets from socket()
           (af_unix.c): none before listen or connect, the listen()er's own
           on a listener (init_peercred), the connecting process's on the
           accepted socket, and the listener's on the client
           (copy_peercred). A child connects, so the two differ; IDs are
           compared with this process's own, as the native run need not be
           root. */
        signal(SIGPIPE, SIG_IGN);
        int types[] = {SOCK_STREAM, SOCK_SEQPACKET};
        for (int t = 0; t < 2; t++) {
            printf("type=%d\n", types[t]);
            struct sockaddr_un a;
            socklen_t len = unix_abstract(&a, t ? "peercred-packet" : "peercred-stream");
            struct ucred cred;
            socklen_t cred_len = sizeof cred;
            int pidfd;
            socklen_t pidfd_len = sizeof pidfd;
            int l = socket(AF_UNIX, types[t], 0);
            getsockopt(l, SOL_SOCKET, SO_PEERCRED, &cred, &cred_len);
            printf("unconnected pid=%d uid=%d gid=%d\n", (int)cred.pid, (int)cred.uid, (int)cred.gid);
            unix_call("unconnected-pidfd", getsockopt(l, SOL_SOCKET, SO_PEERPIDFD, &pidfd, &pidfd_len));
            bind(l, (void *)&a, len);
            getsockopt(l, SOL_SOCKET, SO_PEERCRED, &cred, &cred_len);
            printf("bound pid=%d\n", (int)cred.pid);
            listen(l, 1);
            getsockopt(l, SOL_SOCKET, SO_PEERCRED, &cred, &cred_len);
            printf("listener self=%d uid-own=%d gid-own=%d\n", cred.pid == getpid(), cred.uid == geteuid(),
                   cred.gid == getegid());
            int report[2];
            pipe(report);
            pid_t child = fork();
            if (!child) {
                int c = socket(AF_UNIX, types[t], 0);
                struct ucred mine;
                socklen_t mine_len = sizeof mine;
                getsockopt(c, SOL_SOCKET, SO_PEERCRED, &mine, &mine_len);
                int before = mine.pid;
                int r = connect(c, (void *)&a, len);
                getsockopt(c, SOL_SOCKET, SO_PEERCRED, &mine, &mine_len);
                int pidfd_ok = getsockopt(c, SOL_SOCKET, SO_PEERPIDFD, &pidfd, &pidfd_len) == 0;
                int answer[4] = {before, r, (int)mine.pid, pidfd_ok};
                if (write(report[1], answer, sizeof answer) != sizeof answer) _exit(2);
                char b;
                read(c, &b, 1);
                _exit(0);
            }
            int answer[4];
            if (read(report[0], answer, sizeof answer) != sizeof answer) return 96;
            printf("client before=%d connect=%d peer-is-listener=%d pidfd=%d\n", answer[0], answer[1],
                   answer[2] == getpid(), answer[3]);
            int s = accept(l, NULL, NULL);
            getsockopt(s, SOL_SOCKET, SO_PEERCRED, &cred, &cred_len);
            printf("accepted peer-is-child=%d uid-own=%d\n", cred.pid == child, cred.uid == geteuid());
            unix_call("accepted-pidfd", getsockopt(s, SOL_SOCKET, SO_PEERPIDFD, &pidfd, &pidfd_len));
            close(pidfd);
            getsockopt(l, SOL_SOCKET, SO_PEERCRED, &cred, &cred_len);
            printf("listener-after self=%d\n", cred.pid == getpid());
            send(s, "x", 1, 0);
            int status;
            waitpid(child, &status, 0);
            printf("child status=%d\n", status);
            close(s);
            close(l);
            close(report[0]);
            close(report[1]);
        }
        /* A socket pair names its maker on both ends. */
        int sp[2];
        socketpair(AF_UNIX, SOCK_STREAM, 0, sp);
        struct ucred cred;
        socklen_t cred_len = sizeof cred;
        getsockopt(sp[0], SOL_SOCKET, SO_PEERCRED, &cred, &cred_len);
        int first = cred.pid == getpid();
        getsockopt(sp[1], SOL_SOCKET, SO_PEERCRED, &cred, &cred_len);
        printf("pair self=%d %d\n", first, cred.pid == getpid());
        return 0;
    }
    if (!strcmp(mode, "unix-socketpair")) {
        /* The sockets of an AF_UNIX socketpair (unix_socketpair) are
           unnamed and connected to each other: each may bind, which its
           peer's getpeername and the sender's address then show; a stream
           or packet socket connects no more (EISCONN), and a datagram
           socket connects elsewhere, which drops what it had not read and
           resets its old peer. */
        signal(SIGPIPE, SIG_IGN);
        int types[] = {SOCK_STREAM, SOCK_SEQPACKET, SOCK_DGRAM};
        for (int t = 0; t < 3; t++) {
            int type = types[t];
            int sv[2];
            struct sockaddr_un a, l, none, from;
            char buf[16];
            printf("type=%d\n", type);
            unix_call("socketpair", socketpair(AF_UNIX, type, 0, sv));
            unix_name("name", sv[0], 0, NULL, 0);
            unix_name("peer", sv[0], 1, NULL, 0);
            socklen_t nlen = unix_abstract(&none, "pair-none");
            unix_call("connect-missing", connect(sv[0], (void *)&none, nlen));
            unix_call("connect-short", connect(sv[0], (void *)&none, 1));
            unix_call("listen-unbound", listen(sv[0], 1));
            unix_call("accept", accept(sv[0], NULL, NULL));
            socklen_t alen = unix_abstract(&a, "pair-a");
            unix_call("bind", bind(sv[0], (void *)&a, alen));
            unix_name("name-bound", sv[0], 0, &a, alen);
            unix_name("other-peer", sv[1], 1, &a, alen);
            unix_call("bind-again", bind(sv[0], (void *)&a, alen));
            int o = socket(AF_UNIX, type, 0);
            unix_call("bind-taken", bind(o, (void *)&a, alen));
            close(o);
            unix_call("send-named", send(sv[0], "ab", 2, 0));
            unix_from("from-named", sv[1], sizeof from, &a, alen);
            unix_call("autobind", bind(sv[1], (void *)&a, sizeof(sa_family_t)));
            unix_name("autobind-name", sv[1], 0, NULL, 0);
            unix_name("autobind-peer", sv[0], 1, NULL, 0);
            unix_call("send-autobound", send(sv[1], "cd", 2, 0));
            unix_from("from-autobound", sv[0], sizeof from, NULL, 0);
            socklen_t llen = unix_abstract(&l, "pair-listener");
            int listener = socket(AF_UNIX, type, 0);
            bind(listener, (void *)&l, llen);
            if (type != SOCK_DGRAM) {
                unix_call("listen-bound", listen(sv[0], 1));
                /* It stays connected in Linux's eyes once its peer has gone. */
                int gone[2];
                if (socketpair(AF_UNIX, type, 0, gone)) return 80;
                struct sockaddr_un named;
                socklen_t named_len = unix_abstract(&named, "pair-gone");
                bind(gone[0], (void *)&named, named_len);
                close(gone[1]);
                unix_call("listen-peer-gone", listen(gone[0], 1));
                close(gone[0]);
                listen(listener, 1);
                unix_call("connect-listener", connect(sv[1], (void *)&l, llen));
                unix_call("send-still", send(sv[1], "ef", 2, 0));
                unix_call("recv-still", recv(sv[0], buf, sizeof buf, MSG_DONTWAIT));
                unix_poll("pair", sv[0]);
            } else {
                /* sv[0] connects to the listener's socket: what it had not
                   read goes, sv[1], connected to it, is reset, and may no
                   longer send to it. */
                send(sv[1], "gh", 2, 0);
                unix_call("connect-other", connect(sv[0], (void *)&l, llen));
                unix_name("peer-other", sv[0], 1, &l, llen);
                unix_call("recv-dropped", recv(sv[0], buf, sizeof buf, MSG_DONTWAIT));
                int err = 0;
                socklen_t err_len = sizeof err;
                getsockopt(sv[1], SOL_SOCKET, SO_ERROR, &err, &err_len);
                printf("old-peer-error=%d\n", err);
                unix_call("send-refused", send(sv[1], "ij", 2, 0));
                unix_call("send-other", send(sv[0], "kl", 2, 0));
                unix_from("from-pair", listener, sizeof from, &a, alen);
                struct sockaddr unspec = {.sa_family = AF_UNSPEC};
                unix_call("disconnect", connect(sv[0], &unspec, sizeof unspec));
                unix_name("peer-disconnected", sv[0], 1, NULL, 0);
                unix_call("send-disconnected", send(sv[0], "mn", 2, 0));
                unix_call("send-to-free", send(sv[1], "op", 2, 0));
                unix_from("from-free", sv[0], sizeof from, NULL, 0);
            }
            close(listener);
            close(sv[0]);
            close(sv[1]);
        }
        return 0;
    }
    if (!strcmp(mode, "stdio-flags")) {
        /* F_SETFL on the standard streams, as setfl keeps their status
           flags. Standard input is /dev/null natively, which has no
           fasync: O_ASYNC is dropped and FIOASYNC is ENOTTY. */
        errno = 0;
        result("nonblock", fcntl(0, F_SETFL, O_NONBLOCK));
        result("errno", errno);
        result("getfl", fcntl(0, F_GETFL) & (O_NONBLOCK | O_ASYNC | O_APPEND));
        char byte;
        result("read-nonblocking", read(0, &byte, 1));
        result("async", fcntl(0, F_SETFL, O_ASYNC));
        result("getfl-async", fcntl(0, F_GETFL) & (O_NONBLOCK | O_ASYNC | O_APPEND));
        int on = 1;
        errno = 0;
        result("fioasync", ioctl(0, FIOASYNC, &on));
        result("errno", errno);
        on = 1;
        result("fionbio", ioctl(0, FIONBIO, &on));
        result("getfl-fionbio", fcntl(0, F_GETFL) & (O_NONBLOCK | O_ASYNC | O_APPEND));
        /* Standard output is a pipe natively, which has fasync. */
        result("async-out", fcntl(1, F_SETFL, O_ASYNC));
        result("getfl-async-out", fcntl(1, F_GETFL) & (O_ACCMODE | O_ASYNC));
        on = 0;
        result("fioasync-out-off", ioctl(1, FIOASYNC, &on));
        on = 1;
        result("fioasync-out", ioctl(1, FIOASYNC, &on));
        result("getfl-fioasync-out", fcntl(1, F_GETFL) & (O_ACCMODE | O_ASYNC));
        result("append", fcntl(1, F_SETFL, O_APPEND));
        result("getfl-out", fcntl(1, F_GETFL) & (O_ACCMODE | O_NONBLOCK | O_APPEND));
        result("getfl-err", fcntl(2, F_GETFL) & (O_ACCMODE | O_NONBLOCK | O_APPEND));
        /* A duplicate shares the open file description's flags. */
        int copy = dup(1);
        result("getfl-copy", fcntl(copy, F_GETFL) & (O_ACCMODE | O_NONBLOCK | O_APPEND));
        fcntl(1, F_SETFL, 0);
        result("getfl-copy-after", fcntl(copy, F_GETFL) & (O_ACCMODE | O_NONBLOCK | O_APPEND));
        return 0;
    }
    if (!strcmp(mode, "unix-dgram-sndbuf")) {
        /* What an AF_UNIX datagram takes of its sender's send buffer, as
           unix_dgram_sendmsg allocates it (skb->truesize, charged to
           sk_wmem_alloc): SIOCOUTQ counts it until the datagram is read or
           its receiver goes. A sender with no room left is EAGAIN, or
           waits, and is not writable to poll until a quarter of the buffer
           is free; SO_SNDBUF less 32 bytes bounds a datagram. */
        static char big[212992];
        int sv[2], q;
        socketpair(AF_UNIX, SOCK_DGRAM, 0, sv);
        const int lens[] = {0, 1, 192, 193, 384, 385, 1000, 3776, 3777, 7872, 7873, 16064,
                            16065, 20000, 50000, 85696, 85697, 100000, 212960, 212961};
        for (unsigned i = 0; i < sizeof lens / sizeof lens[0]; i++) {
            errno = 0;
            long n = send(sv[0], big, lens[i], 0);
            int e = n < 0 ? errno : 0;
            ioctl(sv[0], SIOCOUTQ, &q);
            printf("len=%d send=%ld errno=%d outq=%d", lens[i], n, e, q);
            if (n >= 0) recv(sv[1], big, sizeof big, 0);
            ioctl(sv[0], SIOCOUTQ, &q);
            printf(" read=%d\n", q);
        }
        int value = 8192;
        socklen_t value_len = sizeof value;
        setsockopt(sv[0], SOL_SOCKET, SO_SNDBUF, &value, sizeof value);
        getsockopt(sv[0], SOL_SOCKET, SO_SNDBUF, &value, &value_len);
        printf("sndbuf=%d\n", value);
        int sent = 0;
        errno = 0;
        while (send(sv[0], big, 1000, MSG_DONTWAIT) == 1000) sent++;
        ioctl(sv[0], SIOCOUTQ, &q);
        printf("filled=%d errno=%d outq=%d\n", sent, errno, q);
        unix_poll("full", sv[0]);
        for (int i = 0; i < sent; i++) {
            recv(sv[1], big, sizeof big, 0);
            ioctl(sv[0], SIOCOUTQ, &q);
            struct pollfd p = {.fd = sv[0], .events = POLLOUT};
            poll(&p, 1, 0);
            printf("read %d outq=%d writable=%d\n", i + 1, q, !!(p.revents & POLLOUT));
        }
        unix_call("send-too-long", send(sv[0], big, 16353, 0));
        unix_call("send-longest", send(sv[0], big, 16352, 0));
        recv(sv[1], big, sizeof big, 0);
        send(sv[0], big, 1, 0);
        send(sv[0], big, 2, 0);
        ioctl(sv[0], SIOCOUTQ, &q);
        printf("before-close outq=%d\n", q);
        close(sv[1]);
        ioctl(sv[0], SIOCOUTQ, &q);
        printf("receiver-closed outq=%d\n", q);
        close(sv[0]);
        /* A blocking sender waits for room: a read that leaves less than a
           quarter of the buffer free does not wake it, so it waits out
           SO_SNDTIMEO and then looks once more; reads that leave it
           writable wake it. */
        socketpair(AF_UNIX, SOCK_DGRAM, 0, sv);
        value = 2048;
        setsockopt(sv[0], SOL_SOCKET, SO_SNDBUF, &value, sizeof value);
        struct timeval half = {.tv_usec = 500000};
        setsockopt(sv[0], SOL_SOCKET, SO_SNDTIMEO, &half, sizeof half);
        sent = 0;
        while (send(sv[0], big, 1000, MSG_DONTWAIT) == 1000) sent++;
        printf("small-filled=%d\n", sent);
        for (int reads = 1; reads <= 2; reads++) {
            pid_t child = fork();
            if (child == 0) {
                usleep(100000);
                for (int i = 0; i < reads; i++) recv(sv[1], big, sizeof big, 0);
                _exit(0);
            }
            struct timespec start, end;
            clock_gettime(CLOCK_MONOTONIC, &start);
            long n = send(sv[0], big, 1000, 0);
            clock_gettime(CLOCK_MONOTONIC, &end);
            long ms = (end.tv_sec - start.tv_sec) * 1000 + (end.tv_nsec - start.tv_nsec) / 1000000;
            int status;
            waitpid(child, &status, 0);
            /* Only the timed-out wait is timed: it lasts at least the
               timeout however slow the machine. */
            printf("blocked-send reads=%d send=%ld", reads, n);
            if (reads == 1) printf(" waited-out=%d", ms >= 450);
            printf("\n");
            while (recv(sv[1], big, sizeof big, MSG_DONTWAIT) >= 0) {}
            while (send(sv[0], big, 1000, MSG_DONTWAIT) == 1000) {}
        }
        close(sv[0]);
        close(sv[1]);
        /* With no room left, an unconnected socket sending with no address
           is EAGAIN: Linux looks for room (sock_alloc_send_pskb) before it
           looks for the peer. */
        struct sockaddr_un to;
        socklen_t to_len = unix_abstract(&to, "sndbuf-to");
        int receiver = socket(AF_UNIX, SOCK_DGRAM, 0);
        bind(receiver, (void *)&to, to_len);
        int u = socket(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK, 0);
        value = 2048;
        setsockopt(u, SOL_SOCKET, SO_SNDBUF, &value, sizeof value);
        sent = 0;
        while (sendto(u, big, 1000, 0, (void *)&to, to_len) == 1000) sent++;
        printf("named-filled=%d errno=%d\n", sent, errno);
        unix_call("send-unconnected-full", send(u, big, 1000, 0));
        close(u);
        close(receiver);
        /* A packet socket's messages take the same: unix_seqpacket_sendmsg
           sends through unix_dgram_sendmsg, which checks the size before a
           shutdown. */
        signal(SIGPIPE, SIG_IGN);
        socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv);
        const int packet_lens[] = {0, 193, 1000, 16065, 100000, 212960, 212961};
        for (unsigned i = 0; i < sizeof packet_lens / sizeof packet_lens[0]; i++) {
            errno = 0;
            long n = send(sv[0], big, packet_lens[i], 0);
            int e = n < 0 ? errno : 0;
            ioctl(sv[0], SIOCOUTQ, &q);
            printf("packet len=%d send=%ld errno=%d outq=%d", packet_lens[i], n, e, q);
            if (n >= 0) recv(sv[1], big, sizeof big, 0);
            ioctl(sv[0], SIOCOUTQ, &q);
            printf(" read=%d\n", q);
        }
        value = 8192;
        setsockopt(sv[0], SOL_SOCKET, SO_SNDBUF, &value, sizeof value);
        sent = 0;
        errno = 0;
        while (send(sv[0], big, 1000, MSG_DONTWAIT) == 1000) sent++;
        ioctl(sv[0], SIOCOUTQ, &q);
        printf("packet filled=%d errno=%d outq=%d\n", sent, errno, q);
        for (int i = 0; i < sent; i++) {
            recv(sv[1], big, sizeof big, 0);
            struct pollfd p = {.fd = sv[0], .events = POLLOUT};
            poll(&p, 1, 0);
            printf("packet read %d writable=%d\n", i + 1, !!(p.revents & POLLOUT));
        }
        value = 2048;
        setsockopt(sv[0], SOL_SOCKET, SO_SNDBUF, &value, sizeof value);
        setsockopt(sv[0], SOL_SOCKET, SO_SNDTIMEO, &half, sizeof half);
        sent = 0;
        while (send(sv[0], big, 1000, MSG_DONTWAIT) == 1000) sent++;
        pid_t reader = fork();
        if (reader == 0) {
            usleep(100000);
            recv(sv[1], big, sizeof big, 0);
            _exit(0);
        }
        struct timespec start, end;
        clock_gettime(CLOCK_MONOTONIC, &start);
        long n = send(sv[0], big, 1000, 0);
        clock_gettime(CLOCK_MONOTONIC, &end);
        long ms = (end.tv_sec - start.tv_sec) * 1000 + (end.tv_nsec - start.tv_nsec) / 1000000;
        int status;
        waitpid(reader, &status, 0);
        printf("packet small-filled=%d blocked-send=%ld waited-out=%d\n", sent, n, ms >= 450);
        shutdown(sv[0], SHUT_WR);
        unix_call("packet-too-long-shut", send(sv[0], big, 4065, MSG_NOSIGNAL));
        unix_call("packet-shut", send(sv[0], big, 1, MSG_NOSIGNAL));
        close(sv[0]);
        close(sv[1]);
        /* A stream charges each part unix_stream_sendmsg sends, of half the
           send buffer less 64 bytes at most, and the out-of-band byte its
           own; SIOCOUTQ counts them until they are read whole. */
        socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
        const int stream_lens[] = {1, 3776, 3777, 4000, 36544, 36545, 100000};
        for (unsigned i = 0; i < sizeof stream_lens / sizeof stream_lens[0]; i++) {
            long n = send(sv[0], big, stream_lens[i], 0);
            ioctl(sv[0], SIOCOUTQ, &q);
            printf("stream len=%d send=%ld outq=%d", stream_lens[i], n, q);
            recv(sv[1], big, 1, 0);
            ioctl(sv[0], SIOCOUTQ, &q);
            printf(" read-one=%d", q);
            recv(sv[1], big, sizeof big, MSG_WAITALL | MSG_DONTWAIT);
            ioctl(sv[0], SIOCOUTQ, &q);
            printf(" read=%d\n", q);
        }
        unix_call("stream-oob", send(sv[0], "!", 1, MSG_OOB));
        ioctl(sv[0], SIOCOUTQ, &q);
        printf("stream oob outq=%d\n", q);
        recv(sv[1], big, 1, MSG_OOB);
        ioctl(sv[0], SIOCOUTQ, &q);
        printf("stream oob-read outq=%d\n", q);
        value = 8192;
        setsockopt(sv[0], SOL_SOCKET, SO_SNDBUF, &value, sizeof value);
        errno = 0;
        n = send(sv[0], big, 100000, MSG_DONTWAIT);
        ioctl(sv[0], SIOCOUTQ, &q);
        printf("stream filled=%ld errno=%d outq=%d\n", n, errno, q);
        unix_call("stream-full", send(sv[0], big, 1, MSG_DONTWAIT));
        /* Each read takes one whole part of 8128 bytes, so its room goes
           back. */
        for (int i = 0; i < 3; i++) {
            long r = recv(sv[1], big, 8128, MSG_DONTWAIT);
            struct pollfd p = {.fd = sv[0], .events = POLLOUT};
            poll(&p, 1, 0);
            ioctl(sv[0], SIOCOUTQ, &q);
            printf("stream read %d got=%ld outq=%d writable=%d\n", i + 1, r, q, !!(p.revents & POLLOUT));
        }
        close(sv[0]);
        close(sv[1]);
        return 0;
    }
    if (!strcmp(mode, "unix-datagram")) {
        /* AF_UNIX datagram sockets from socket() (af_unix.c's
           unix_dgram_*): names in the abstract namespace, which each type
           has its own of, sendto and connect, who may send to a connected
           socket, a queue full past net.unix.max_dgram_qlen (10), a peer
           that goes, and the sender's address recvfrom and recvmsg give,
           for streams and packet sockets too. */
        signal(SIGPIPE, SIG_IGN);
        struct sockaddr_un a, b, c;
        socklen_t alen = unix_abstract(&a, "dgram-a"), blen = unix_abstract(&b, "dgram-b");
        socklen_t clen = unix_abstract(&c, "dgram-c");
        struct sockaddr unspec = {.sa_family = AF_UNSPEC};
        char buf[16];
        int on = 1;
        socklen_t on_len = sizeof on;
        int u = socket(AF_UNIX, SOCK_DGRAM, 0);
        unix_call("socket-ok", u >= 0 ? 0 : -1);
        getsockopt(u, SOL_SOCKET, SO_TYPE, &on, &on_len);
        printf("type=%d\n", on);
        int raw = socket(AF_UNIX, SOCK_RAW, 0);
        getsockopt(raw, SOL_SOCKET, SO_TYPE, &on, &on_len);
        printf("raw-type=%d\n", on);
        close(raw);
        unix_name("name-unbound", u, 0, NULL, 0);
        unix_name("peer-unbound", u, 1, NULL, 0);
        unix_poll("unbound", u);
        unix_call("send-unconnected", send(u, "x", 1, 0));
        unix_call("write-unconnected", write(u, "x", 1));
        unix_call("recv-empty", recv(u, buf, 1, MSG_DONTWAIT));
        unix_call("listen", listen(u, 1));
        unix_call("accept", accept(u, NULL, NULL));
        unix_call("accept4-flags", syscall(SYS_accept4, u, NULL, NULL, 1));
        unix_call("sendto-missing", sendto(u, "x", 1, 0, (void *)&a, alen));
        unix_call("sendto-short", sendto(u, "x", 1, 0, (void *)&a, sizeof(sa_family_t)));
        unix_call("connect-missing", connect(u, (void *)&a, alen));
        unix_call("connect-short", connect(u, (void *)&a, 1));
        unix_call("disconnect-unconnected", connect(u, &unspec, sizeof unspec));
        struct ucred peer;
        socklen_t peer_len = sizeof peer;
        getsockopt(u, SOL_SOCKET, SO_PEERCRED, &peer, &peer_len);
        printf("peercred pid=%d uid=%d gid=%d\n", (int)peer.pid, (int)peer.uid, (int)peer.gid);
        int pidfd;
        socklen_t pidfd_len = sizeof pidfd;
        unix_call("peerpidfd", getsockopt(u, SOL_SOCKET, SO_PEERPIDFD, &pidfd, &pidfd_len));

        int r = socket(AF_UNIX, SOCK_DGRAM, 0);
        unix_call("bind", bind(r, (void *)&a, alen));
        unix_name("name-bound", r, 0, &a, alen);
        int stream = socket(AF_UNIX, SOCK_STREAM, 0);
        unix_call("bind-other-type", bind(stream, (void *)&a, alen));
        close(stream);
        int o = socket(AF_UNIX, SOCK_DGRAM, 0);
        unix_call("bind-in-use", bind(o, (void *)&a, alen));
        unix_call("sendto-unbound", sendto(u, "one", 3, 0, (void *)&a, alen));
        unix_poll("receiver", r);
        unix_from("from-unbound", r, sizeof(struct sockaddr_un), NULL, 0);
        unix_poll("receiver-empty", r);
        unix_call("bind-b", bind(o, (void *)&b, blen));
        unix_call("sendto-bound", sendto(o, "two", 3, 0, (void *)&a, alen));
        unix_call("sendto-again", sendto(o, "2b", 2, 0, (void *)&a, alen));
        unix_from("from-bound", r, sizeof(struct sockaddr_un), &b, blen);
        unix_from("from-short", r, 4, &b, blen);
        unix_call("sendto-message", sendto(o, "msg", 3, 0, (void *)&a, alen));
        {
            struct sockaddr_un from;
            memset(&from, 0x55, sizeof from);
            struct iovec iov = {buf, sizeof buf};
            struct msghdr m = {.msg_name = &from, .msg_namelen = sizeof from, .msg_iov = &iov, .msg_iovlen = 1};
            long n = recvmsg(r, &m, 0);
            printf("recvmsg=%ld same=%d\n", n, m.msg_namelen == blen && !memcmp(&from, &b, blen));
        }

        unix_call("connect", connect(u, (void *)&a, alen));
        unix_name("peer-connected", u, 1, &a, alen);
        /* Connecting records no peer process (unix_dgram_connect). */
        getsockopt(u, SOL_SOCKET, SO_PEERCRED, &peer, &peer_len);
        printf("peercred-connected pid=%d uid=%d gid=%d\n", (int)peer.pid, (int)peer.uid, (int)peer.gid);
        unix_poll("connected", u);
        unix_call("send-connected", send(u, "three", 5, 0));
        unix_call("write-connected", write(u, "3b", 2));
        unix_from("from-connected", r, sizeof(struct sockaddr_un), NULL, 0);
        unix_from("from-write", r, sizeof(struct sockaddr_un), NULL, 0);
        unix_call("connect-r-to-b", connect(r, (void *)&b, blen));
        unix_call("send-not-peer", send(u, "x", 1, 0));
        unix_call("sendto-not-peer", sendto(u, "x", 1, 0, (void *)&a, alen));
        int fresh = socket(AF_UNIX, SOCK_DGRAM, 0);
        unix_call("connect-not-peer", connect(fresh, (void *)&a, alen));
        unix_call("sendto-peer", sendto(o, "four", 4, 0, (void *)&a, alen));
        unix_from("from-peer", r, sizeof(struct sockaddr_un), &b, blen);
        unix_call("disconnect", connect(r, &unspec, sizeof unspec));
        unix_name("peer-disconnected", r, 1, NULL, 0);
        unix_call("send-after-disconnect", send(u, "five", 4, 0));
        unix_from("from-after-disconnect", r, sizeof(struct sockaddr_un), NULL, 0);

        /* The queue: ten wait, and the eleventh too, then it is full. */
        int sent = 0;
        long w = 0;
        for (int i = 0; i < 12 && (w = send(u, "q", 1, MSG_DONTWAIT)) == 1; i++) sent++;
        printf("queued=%d last=%ld errno=%d\n", sent, w, w < 0 ? errno : 0);
        errno = 0;
        unix_poll("sender-full", u);
        unix_poll("receiver-full", r);
        unix_call("sendto-full", sendto(o, "x", 1, MSG_DONTWAIT, (void *)&a, alen));
        struct timeval brief = {0, 50000};
        setsockopt(u, SOL_SOCKET, SO_SNDTIMEO, &brief, sizeof brief);
        unix_call("send-timeout", send(u, "x", 1, 0));
        unix_call("recv-one", recv(r, buf, sizeof buf, 0));
        unix_poll("sender-room", u);
        unix_call("send-room", send(u, "x", 1, MSG_DONTWAIT));
        while (recv(r, buf, sizeof buf, MSG_DONTWAIT) >= 0) {}
        errno = 0;
        /* A socket's own queue, and one connected to the sender, are not
           limited so. */
        sent = 0;
        for (int i = 0; i < 20; i++) sent += sendto(r, "s", 1, MSG_DONTWAIT, (void *)&a, alen) == 1;
        printf("self-queued=%d\n", sent);
        while (recv(r, buf, sizeof buf, MSG_DONTWAIT) >= 0) {}
        connect(r, (void *)&b, blen);
        sent = 0;
        for (int i = 0; i < 20; i++) sent += sendto(o, "p", 1, MSG_DONTWAIT, (void *)&a, alen) == 1;
        printf("peer-queued=%d\n", sent);
        while (recv(r, buf, sizeof buf, MSG_DONTWAIT) >= 0) {}
        errno = 0;
        connect(r, &unspec, sizeof unspec);

        /* Shutdowns. */
        int s2 = socket(AF_UNIX, SOCK_DGRAM, 0);
        unix_call("shutdown-unconnected", shutdown(s2, SHUT_WR));
        unix_call("sendto-shut-missing", sendto(s2, "x", 1, 0, (void *)&c, clen));
        unix_call("send-shut-unconnected", send(s2, "x", 1, 0));
        close(s2);
        int shut = socket(AF_UNIX, SOCK_DGRAM, 0);
        bind(shut, (void *)&c, clen);
        shutdown(shut, SHUT_RD);
        unix_poll("read-shut", shut);
        unix_call("sendto-read-shut", sendto(o, "x", 1, 0, (void *)&c, clen));
        close(shut);

        /* SO_PASSCRED autobinds a sender, and the receiver reads its
           credentials. */
        int p = socket(AF_UNIX, SOCK_DGRAM, 0);
        on = 1;
        setsockopt(p, SOL_SOCKET, SO_PASSCRED, &on, sizeof on);
        unix_call("sendto-passcred", sendto(p, "cred", 4, 0, (void *)&a, alen));
        unix_name("passcred-name", p, 0, NULL, 0);
        setsockopt(r, SOL_SOCKET, SO_PASSCRED, &on, sizeof on);
        unix_call("sendto-to-passcred", sendto(u, "c2", 2, 0, (void *)&a, alen));
        for (int i = 0; i < 2; i++) {
            struct sockaddr_un from;
            union { char bytes[CMSG_SPACE(sizeof(struct ucred))]; struct cmsghdr align; } control;
            struct iovec iov = {buf, sizeof buf};
            struct msghdr m = {.msg_name = &from, .msg_namelen = sizeof from, .msg_iov = &iov, .msg_iovlen = 1,
                               .msg_control = control.bytes, .msg_controllen = sizeof control.bytes};
            long n = recvmsg(r, &m, MSG_DONTWAIT);
            struct cmsghdr *h = CMSG_FIRSTHDR(&m);
            struct ucred cred = {0};
            if (h && h->cmsg_type == SCM_CREDENTIALS) memcpy(&cred, CMSG_DATA(h), sizeof cred);
            printf("passcred-recv=%ld namelen=%u pid-ok=%d uid-ok=%d\n", n, (unsigned)m.msg_namelen,
                   cred.pid == getpid(), cred.uid == getuid());
        }
        on = 0;
        setsockopt(r, SOL_SOCKET, SO_PASSCRED, &on, sizeof on);
        close(p);

        /* A message keeps its sender's name once the sender goes; a
           socket pair's end may send to a name too. */
        int gone = socket(AF_UNIX, SOCK_DGRAM, 0);
        bind(gone, (void *)&c, clen);
        sendto(gone, "bye", 3, 0, (void *)&a, alen);
        close(gone);
        unix_from("from-closed", r, sizeof(struct sockaddr_un), &c, clen);
        int sp[2];
        socketpair(AF_UNIX, SOCK_DGRAM, 0, sp);
        unix_call("sendto-from-pair", sendto(sp[0], "pair", 4, 0, (void *)&a, alen));
        unix_from("from-pair", r, sizeof(struct sockaddr_un), NULL, 0);
        unix_call("sendto-pair-missing", sendto(sp[0], "x", 1, 0, (void *)&c, clen));
        close(sp[0]);
        close(sp[1]);

        /* The receiver goes: the next send is refused, the one after has
           no peer. */
        unix_name("peer-before-close", u, 1, &a, alen);
        close(r);
        unix_name("peer-after-close", u, 1, &a, alen);
        unix_call("send-closed", send(u, "x", 1, 0));
        unix_call("send-after-closed", send(u, "x", 1, 0));
        unix_name("peer-after-refused", u, 1, NULL, 0);
        unix_call("connect-closed", connect(fresh, (void *)&a, alen));
        close(u);
        close(o);
        close(fresh);

        /* A stream's and a packet socket's sender address. */
        int types[] = {SOCK_STREAM, SOCK_SEQPACKET};
        for (int t = 0; t < 2; t++) {
            printf("type=%d\n", types[t]);
            int l = socket(AF_UNIX, types[t], 0);
            bind(l, (void *)&c, clen);
            listen(l, 1);
            int client = socket(AF_UNIX, types[t], 0);
            connect(client, (void *)&c, clen);
            int server = accept(l, NULL, NULL);
            send(server, "srv", 3, 0);
            send(client, "cli", 3, 0);
            unix_from("from-server", client, sizeof(struct sockaddr_un), &c, clen);
            unix_from("from-client", server, sizeof(struct sockaddr_un), NULL, 0);
            close(server);
            close(client);
            close(l);
        }
        return 0;
    }
    if (!strcmp(mode, "scm-garbage")) {
        /* Linux's garbage collector (unix_gc), which runs when an AF_UNIX
           socket goes, closes the sockets only unread messages hold: one
           whose descriptor waits in its own queue, two that hold each
           other, and what was passed with them. One a held socket's queue
           holds stays. The collection may run a little later, hence the
           waits for the hang-up. Nothing is printed between a close and
           the collection this mode starts: Linux's collector is the whole
           machine's, so another process's socket going may have run it
           already (run 41040442998). */
        signal(SIGPIPE, SIG_IGN);
        int s[2], u[2], pipe_fds[2];
        char byte;
        socketpair(AF_UNIX, SOCK_STREAM, 0, s);
        printf("send-self=%ld\n", send_fds(s[0], "x", 1, &s[1], 1));
        close(s[1]);
        gc_trigger(s[0]);
        gc_state("self-collected", s[0]);
        printf("read=%zd\n", read(s[0], &byte, 1));
        errno = 0;
        long w = write(s[0], "y", 1);
        printf("write=%ld errno=%d\n", w, w < 0 ? errno : 0);
        socketpair(AF_UNIX, SOCK_STREAM, 0, s);
        socketpair(AF_UNIX, SOCK_STREAM, 0, u);
        pipe(pipe_fds);
        int with[2] = {u[1], pipe_fds[1]};
        printf("send-cycle=%ld %ld\n", send_fds(s[0], "x", 1, with, 2), send_fds(u[0], "x", 1, &s[1], 1));
        close(s[1]);
        close(u[1]);
        close(pipe_fds[1]);
        gc_trigger(s[0]);
        gc_state("cycle-a-collected", s[0]);
        gc_state("cycle-c-collected", u[0]);
        gc_state("cycle-pipe-collected", pipe_fds[0]);
        printf("pipe-read=%zd\n", read(pipe_fds[0], &byte, 1));
        close(s[0]);
        close(u[0]);
        close(pipe_fds[0]);
        socketpair(AF_UNIX, SOCK_STREAM, 0, s);
        socketpair(AF_UNIX, SOCK_STREAM, 0, u);
        printf("send-held=%ld\n", send_fds(u[0], "x", 1, &s[1], 1));
        close(s[1]);
        gc_trigger(-1);
        gc_state("held", s[0]);
        int got, flags;
        long n = receive_fd(u[1], &byte, 1, 0, &got, &flags);
        printf("received=%ld fd-ok=%d\n", n, got >= 0);
        printf("back=%zd\n", write(got, "z", 1));
        printf("read-back=%zd byte=%c\n", read(s[0], &byte, 1), byte);
        close(got);
        gc_state("held-closed", s[0]);
        /* A listener that only the queue of a connection it has not
           accepted holds is garbage too, as Linux counts what an embryo
           holds as its listener's: it goes, and resets the client. */
        struct sockaddr_un a;
        socklen_t len = unix_abstract(&a, "gc-listener");
        int l = socket(AF_UNIX, SOCK_STREAM, 0);
        bind(l, (void *)&a, len);
        listen(l, 1);
        int client = socket(AF_UNIX, SOCK_STREAM, 0);
        printf("connect=%d\n", connect(client, (void *)&a, len));
        printf("send-listener=%ld\n", send_fds(client, "x", 1, &l, 1));
        close(l);
        gc_trigger(client);
        gc_state("listener-collected", client);
        errno = 0;
        n = recv(client, &byte, 1, MSG_DONTWAIT);
        printf("recv-reset=%ld errno=%d\n", n, n < 0 ? errno : 0);
        close(client);
        return 0;
    }
    if (!strcmp(mode, "scm-rights")) {
        int stream[2], pipe_fds[2];
        socketpair(AF_UNIX, SOCK_STREAM, 0, stream);
        pipe(pipe_fds);
        /* Received descriptors take the lowest free numbers from here. */
        int base = dup(0);
        close(base);
        char byte;
        result("plain", write(stream[0], "ab", 2));
        result("with-fds", send_fds(stream[0], "cd", 2, pipe_fds, 2));
        result("after", write(stream[0], "ef", 2));
        int received = -1;
        /* The read goes on into the write that passed them, and ends there. */
        receive_fds("first", stream[1], 16, 64, MSG_CMSG_CLOEXEC, base, &received);
        result("same-pipe", write(received + 1, "x", 1) == 1 && read(pipe_fds[0], &byte, 1) == 1 && byte == 'x');
        close(received);
        close(received + 1);
        receive_fds("rest", stream[1], 16, 64, 0, base, NULL);
        send_fds(stream[0], "gh", 2, pipe_fds, 1);
        receive_fds("partial", stream[1], 1, 64, 0, base, &received);
        close(received);
        receive_fds("partial-rest", stream[1], 16, 64, 0, base, NULL);
        /* Room for one of two: the other is closed, with MSG_CTRUNC. */
        send_fds(stream[0], "ij", 2, pipe_fds, 2);
        receive_fds("small-control", stream[1], 16, CMSG_LEN(sizeof(int)), 0, base, &received);
        close(received);
        send_fds(stream[0], "kl", 2, pipe_fds, 2);
        receive_fds("no-control", stream[1], 16, 0, 0, base, NULL);
        /* A stream write of no bytes passes nothing. */
        result("empty-with-fds", send_fds(stream[0], "", 0, pipe_fds, 1));
        result("next", write(stream[0], "m", 1));
        receive_fds("after-empty", stream[1], 16, 64, 0, base, NULL);
        /* recvmsg with no buffer still takes them; read closes them. */
        send_fds(stream[0], "no", 2, pipe_fds, 1);
        receive_fds("empty-buffer", stream[1], 0, 64, 0, base, &received);
        close(received);
        receive_fds("empty-buffer-rest", stream[1], 16, 64, 0, base, NULL);
        send_fds(stream[0], "pq", 2, pipe_fds, 1);
        char bytes[8];
        result("read", read(stream[1], bytes, sizeof bytes));
        receive_fds("drained", stream[1], 16, 64, MSG_DONTWAIT, base, NULL);
        /* RLIMIT_NOFILE leaves room for one: the other is closed. */
        struct rlimit old_limit, one = {base + 1, 0};
        getrlimit(RLIMIT_NOFILE, &old_limit);
        one.rlim_max = old_limit.rlim_max;
        send_fds(stream[0], "rs", 2, pipe_fds, 2);
        setrlimit(RLIMIT_NOFILE, &one);
        receive_fds("nofile", stream[1], 16, 64, 0, base, &received);
        setrlimit(RLIMIT_NOFILE, &old_limit);
        close(received);
        /* Messages keep their descriptors; recvmsg with no buffer discards one. */
        int datagram[2];
        socketpair(AF_UNIX, SOCK_DGRAM, 0, datagram);
        send_fds(datagram[0], "hello", 5, pipe_fds, 1);
        send_fds(datagram[0], "world", 5, pipe_fds, 1);
        receive_fds("truncated", datagram[1], 2, 64, 0, base, &received);
        close(received);
        receive_fds("discarded", datagram[1], 0, 64, 0, base, &received);
        close(received);
        receive_fds("datagram-drained", datagram[1], 16, 64, MSG_DONTWAIT, base, NULL);
        int packets[2];
        socketpair(AF_UNIX, SOCK_SEQPACKET, 0, packets);
        result("empty-packet", send_fds(packets[0], "", 0, pipe_fds, 1));
        receive_fds("packet", packets[1], 16, 64, 0, base, &received);
        close(received);
        /* What sendmsg checks. */
        union { char bytes[64]; struct cmsghdr align; } control;
        struct cmsghdr *header = (struct cmsghdr *)control.bytes;
        int bad = 999;
        result("bad-fd", send_fds(stream[0], "z", 1, &bad, 1));
        result("errno", errno);
        header->cmsg_len = CMSG_LEN(sizeof(int));
        header->cmsg_level = SOL_SOCKET;
        header->cmsg_type = SCM_RIGHTS + 76;
        send_raw("other-type", stream[0], NULL, 0, control.bytes, CMSG_SPACE(sizeof(int)));
        header->cmsg_level = SOL_SOCKET + 5;
        send_raw("other-level", stream[0], NULL, 0, control.bytes, CMSG_SPACE(sizeof(int)));
        header->cmsg_level = SOL_SOCKET;
        header->cmsg_type = SCM_RIGHTS;
        header->cmsg_len = 40;
        send_raw("too-long", stream[0], NULL, 0, control.bytes, 32);
        header->cmsg_len = 8;
        send_raw("too-short", stream[0], NULL, 0, control.bytes, 32);
        send_raw("short-buffer", stream[0], NULL, 0, control.bytes, 12);
        receive_fds("checked", stream[1], 16, 64, MSG_DONTWAIT, base, NULL);
        struct sockaddr_un address = {.sun_family = AF_UNIX};
        send_raw("stream-address", stream[0], &address, sizeof address, NULL, 0);
        send_raw("packet-address", packets[0], &address, sizeof address, NULL, 0);
        receive_fds("packet-sent", packets[1], 16, 64, MSG_DONTWAIT, base, NULL);
        send_raw("family-only", datagram[0], &address, 2, NULL, 0);
        send_raw("abstract", datagram[0], &address, sizeof address, NULL, 0);
        strcpy(address.sun_path, "/missing-socket");
        send_raw("missing", datagram[0], &address, sizeof address, NULL, 0);
        // Writable by everyone, so the write check passes without root.
        strcpy(address.sun_path, "/tmp");
        send_raw("not-a-socket", datagram[0], &address, sizeof address, NULL, 0);
        address.sun_family = AF_INET;
        send_raw("inet", datagram[0], &address, sizeof address, NULL, 0);
        send_raw("pipe", pipe_fds[1], NULL, 0, NULL, 0);
        struct iovec iov = {"z", 1};
        struct msghdr many = {.msg_iov = &iov, .msg_iovlen = 1025};
        errno = 0;
        result("iovecs", sendmsg(stream[0], &many, 0));
        result("errno", errno);
        /* A descriptor still queued closes with the receiving socket. */
        int carrier[2], ends[2];
        socketpair(AF_UNIX, SOCK_STREAM, 0, carrier);
        pipe(ends);
        send_fds(carrier[0], "w", 1, &ends[1], 1);
        close(ends[1]);
        fcntl(ends[0], F_SETFL, O_NONBLOCK);
        errno = 0;
        result("writer-queued", read(ends[0], &byte, 1));
        result("errno", errno);
        close(carrier[1]);
        result("writer-closed", read(ends[0], &byte, 1));
        /* From one process to another. */
        int link[2];
        socketpair(AF_UNIX, SOCK_STREAM, 0, link);
        pid_t pid = child();
        if (pid == 0) {
            int made[2];
            pipe(made);
            send_fds(link[1], "c", 1, &made[0], 1);
            if (write(made[1], "from-child", 10) != 10) _exit(1);
            _exit(0);
        }
        int status;
        waitpid(pid, &status, 0);
        result("child", WIFEXITED(status) ? WEXITSTATUS(status) : -1);
        received = -1;
        receive_fds("from-child", link[0], 16, 64, 0, base, &received);
        char text[16] = {0};
        result("child-pipe", read(received, text, sizeof text) == 10 && !memcmp(text, "from-child", 10));
        return 0;
    }
    if (!strcmp(mode, "posix-timer")) {
        sigset_t set;
        sigemptyset(&set);
        sigaddset(&set, SIGUSR1);
        sigprocmask(SIG_BLOCK, &set, NULL);
        struct sigevent event = {0};
        event.sigev_notify = SIGEV_SIGNAL;
        event.sigev_signo = SIGUSR1;
        event.sigev_value.sival_int = 42;
        timer_t timer;
        result("create", timer_create(CLOCK_MONOTONIC, &event, &timer));
        struct itimerspec once = {{0, 0}, {0, 20000000}}, now;
        result("arm", timer_settime(timer, 0, &once, NULL));
        struct timespec limit = {5, 0};
        siginfo_t info;
        result("signal", sigtimedwait(&set, &info, &limit));
        result("code", info.si_code == SI_TIMER);
        result("value", info.si_value.sival_int);
        result("timer-id", info.si_timerid == (int)(intptr_t)timer);
        result("disarmed", timer_gettime(timer, &now) == 0 && now.it_value.tv_sec == 0 && now.it_value.tv_nsec == 0);
        /* An interval timer whose signal stays blocked counts overruns. */
        struct itimerspec every = {{0, 10000000}, {0, 10000000}};
        result("interval", timer_settime(timer, 0, &every, NULL));
        struct timespec pause_for = {0, 80000000};
        nanosleep(&pause_for, NULL);
        result("repeated", sigtimedwait(&set, &info, &limit));
        result("overrun", info.si_overrun > 0);
        result("armed", timer_gettime(timer, &now) == 0 && now.it_interval.tv_nsec == 10000000);
        result("delete", timer_delete(timer));
        struct timespec zero = {0, 0};
        errno = 0;
        result("drained", sigtimedwait(&set, &info, &zero));
        result("errno", errno);
        errno = 0;
        result("bad-clock", syscall(SYS_timer_create, 99, NULL, &timer));
        result("errno", errno);
        event.sigev_signo = 99;
        errno = 0;
        int id;
        result("bad-signal", syscall(SYS_timer_create, CLOCK_MONOTONIC, &event, &id));
        result("errno", errno);
        errno = 0;
        result("bad-timer", syscall(SYS_timer_settime, 0x3ffff, 0, &once, NULL));
        result("errno", errno);
        errno = 0;
        result("bad-delete", syscall(SYS_timer_delete, (int)(intptr_t)timer));
        result("errno", errno);
        return 0;
    }
    if (!strcmp(mode, "prctl")) {
        int value = -1;
        result("pdeathsig", prctl(PR_SET_PDEATHSIG, SIGUSR1));
        prctl(PR_GET_PDEATHSIG, &value);
        result("pdeathsig-value", value);
        result("dumpable", prctl(PR_GET_DUMPABLE));
        result("not-dumpable", prctl(PR_SET_DUMPABLE, 0));
        result("dumpable-now", prctl(PR_GET_DUMPABLE));
        errno = 0;
        result("bad-dumpable", prctl(PR_SET_DUMPABLE, 2));
        result("errno", errno);
        result("no-new-privs", prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0));
        result("no-new-privs-now", prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0));
        errno = 0;
        result("bad-signal", prctl(PR_SET_PDEATHSIG, 65));
        result("errno", errno);
        errno = 0;
        result("unknown", prctl(9999));
        result("errno", errno);
        return 0;
    }
    if (!strcmp(mode, "thread-name")) {
        /* The first name comes from the executable's path, which differs. */
        char name[16];
        result("set", prctl(PR_SET_NAME, "paludarium-guest-name"));
        memset(name, 'x', sizeof name);
        result("get", prctl(PR_GET_NAME, name));
        result("truncated", !strcmp(name, "paludarium-gues"));
        result("short", prctl(PR_SET_NAME, "ab"));
        memset(name, 'x', sizeof name);
        prctl(PR_GET_NAME, name);
        result("cleared", !strcmp(name, "ab") && name[3] == 0 && name[15] == 0);
        errno = 0;
        result("set-fault", prctl(PR_SET_NAME, (char *)1));
        result("errno", errno);
        errno = 0;
        result("get-fault", prctl(PR_GET_NAME, (char *)1));
        result("errno", errno);
        pthread_t worker;
        pthread_create(&worker, NULL, name_reader, NULL);
        pthread_join(worker, NULL);
        result("thread-inherits", !strcmp(thread_name, "ab"));
        prctl(PR_GET_NAME, name);
        result("own-name-kept", !strcmp(name, "ab"));
        pid_t pid = child();
        if (pid == 0) {
            prctl(PR_GET_NAME, name);
            _exit(!strcmp(name, "ab") ? 5 : 6);
        }
        int status = 0;
        waitpid(pid, &status, 0);
        result("fork-inherits", WEXITSTATUS(status));
        return 0;
    }
    if (!strcmp(mode, "timer-thread")) {
        sigset_t set;
        sigemptyset(&set);
        sigaddset(&set, SIGUSR1);
        sigprocmask(SIG_BLOCK, &set, NULL);
        if (pipe(timer_report)) return 81;
        pthread_t waiter;
        pthread_create(&waiter, NULL, timer_waiter, NULL);
        int tid = 0;
        read(timer_report[0], &tid, sizeof tid);
        struct thread_event event = {7, SIGUSR1, 4, tid, {0}};
        int timer = -1;
        result("create", syscall(SYS_timer_create, CLOCK_MONOTONIC, &event, &timer));
        struct itimerspec once = {{0, 0}, {0, 20000000}};
        result("arm", syscall(SYS_timer_settime, timer, 0, &once, NULL));
        int got[3] = {0};
        read(timer_report[0], got, sizeof got);
        pthread_join(waiter, NULL);
        result("signal", got[0]);
        result("code", got[1] == SI_TIMER);
        result("value", got[2]);
        sigset_t pending;
        sigpending(&pending);
        result("not-for-main", sigismember(&pending, SIGUSR1));
        result("delete", syscall(SYS_timer_delete, timer));
        /* The thread must be in this thread group; a bad notify is EINVAL. */
        struct thread_event elsewhere = {0, SIGUSR1, 4, 999999, {0}};
        errno = 0;
        result("other-thread", syscall(SYS_timer_create, CLOCK_MONOTONIC, &elsewhere, &timer));
        result("errno", errno);
        struct thread_event bad_signal = {0, 0, 4, (int)syscall(SYS_gettid), {0}};
        errno = 0;
        result("bad-signal", syscall(SYS_timer_create, CLOCK_MONOTONIC, &bad_signal, &timer));
        result("errno", errno);
        struct thread_event mixed = {0, SIGUSR1, 6, (int)syscall(SYS_gettid), {0}};
        errno = 0;
        result("bad-notify", syscall(SYS_timer_create, CLOCK_MONOTONIC, &mixed, &timer));
        result("errno", errno);
        /* The kernel takes SIGEV_THREAD as a signal to the process. */
        struct thread_event as_signal = {0, SIGUSR1, 2, 0, {0}};
        result("sigev-thread", syscall(SYS_timer_create, CLOCK_MONOTONIC, &as_signal, &timer));
        result("delete-sigev-thread", syscall(SYS_timer_delete, timer));
        return 0;
    }
    if (!strcmp(mode, "ignore-discards")) {
        /* Making a signal ignored discards its pending instances, and only
           those: one sent while ignored and blocked stays pending. SIG_DFL
           discards a signal whose default is to ignore it. */
        sigset_t set, pending;
        sigemptyset(&set);
        sigaddset(&set, SIGUSR1);
        sigaddset(&set, SIGUSR2);
        sigaddset(&set, SIGURG);
        sigprocmask(SIG_BLOCK, &set, NULL);
        raise(SIGUSR1);
        signal(SIGUSR1, SIG_IGN);
        sigpending(&pending);
        result("ignored", sigismember(&pending, SIGUSR1));
        raise(SIGUSR1);
        sigpending(&pending);
        result("sent-while-ignored", sigismember(&pending, SIGUSR1));
        signal(SIGUSR1, SIG_DFL);
        sigpending(&pending);
        result("default-terminate", sigismember(&pending, SIGUSR1));
        raise(SIGURG);
        signal(SIGURG, SIG_DFL);
        sigpending(&pending);
        result("default-ignore", sigismember(&pending, SIGURG));
        signal(SIGUSR1, SIG_IGN);
        /* A signal another thread already has pending goes too. */
        pthread_t reader;
        char byte;
        if (pipe(discard_go) || pipe(discard_done) || pthread_create(&reader, NULL, discard_reader, NULL)) return 84;
        pthread_kill(reader, SIGUSR2);
        if (write(discard_go[1], "x", 1) != 1 || read(discard_done[0], &byte, 1) != 1) return 85;
        signal(SIGUSR2, SIG_IGN);
        if (write(discard_go[1], "x", 1) != 1 || read(discard_done[0], &byte, 1) != 1) return 86;
        pthread_join(reader, NULL);
        return 0;
    }
    if (!strcmp(mode, "autoreap")) {
        /* With SIGCHLD ignored, or SA_NOCLDWAIT, an exiting child is reaped
           at once: a wait blocks until it has exited, then fails with
           ECHILD. Ignored, SIGCHLD is not even queued while blocked. */
        sigset_t chld, pending;
        sigemptyset(&chld);
        sigaddset(&chld, SIGCHLD);
        sigprocmask(SIG_BLOCK, &chld, NULL);
        int status = 0;
        siginfo_t info;
        /* A zombie from before SIGCHLD is ignored stays for a wait. */
        pid_t zombie = child();
        if (zombie == 0) _exit(5);
        waitid(P_PID, zombie, &info, WEXITED | WNOWAIT);
        sigwaitinfo(&chld, &info);
        signal(SIGCHLD, SIG_IGN);
        pid_t pid = child();
        if (pid == 0) _exit(3);
        errno = 0;
        result("ignored-wait", waitpid(pid, &status, 0));
        result("ignored-errno", errno);
        sigpending(&pending);
        result("ignored-pending", sigismember(&pending, SIGCHLD));
        errno = 0;
        result("ignored-gone", kill(pid, 0) == -1 && errno == ESRCH);
        result("zombie-kept", reaped(zombie));
        /* SA_NOCLDWAIT with a handler: reaped as well, but SIGCHLD comes. */
        struct sigaction action = { .sa_handler = interrupted, .sa_flags = SA_NOCLDWAIT };
        sigaction(SIGCHLD, &action, NULL);
        pid = child();
        if (pid == 0) _exit(4);
        errno = 0;
        result("nocldwait-wait", waitpid(pid, &status, 0));
        result("nocldwait-errno", errno);
        sigpending(&pending);
        result("nocldwait-pending", sigismember(&pending, SIGCHLD));
        /* A child whose exit signal is not SIGCHLD is not reaped. */
        signal(SIGCHLD, SIG_IGN);
        pid = syscall(SYS_clone, 0, 0, 0, 0, 0);
        if (pid == 0) _exit(6);
        result("other-signal", waitpid(pid, &status, __WALL) == pid);
        result("other-status", WEXITSTATUS(status));
        return 0;
    }
    if (!strcmp(mode, "reparent")) {
        /* A child subreaper adopts the children of a child that exits, and
           can wait for them; its own children do not inherit the setting. */
        int flag = -1;
        result("subreaper-default", prctl(PR_GET_CHILD_SUBREAPER, &flag) == 0 ? flag : -1);
        prctl(PR_SET_CHILD_SUBREAPER, 1);
        prctl(PR_GET_CHILD_SUBREAPER, &flag);
        result("subreaper", flag);
        int ready[2], go[2];
        if (pipe(ready) || pipe(go)) return 87;
        pid_t self = getpid(), grand = 0, zombie = 0;
        int status = 0;
        pid_t middle = child();
        if (middle == 0) {
            int inherited = -1;
            prctl(PR_GET_CHILD_SUBREAPER, &inherited);
            pid_t pid = child();
            if (pid == 0) {
                char byte;
                if (read(go[0], &byte, 1) != 1) _exit(5);
                _exit(getppid() == self ? 3 : 4);
            }
            if (write(ready[1], &pid, sizeof pid) != sizeof pid) _exit(6);
            _exit(inherited);
        }
        if (read(ready[0], &grand, sizeof grand) != sizeof grand) return 88;
        result("middle", waitpid(middle, &status, 0) == middle);
        result("middle-inherited", WEXITSTATUS(status));
        if (write(go[1], "x", 1) != 1) return 89;
        result("adopted", waitpid(grand, &status, 0) == grand);
        result("adopted-ppid", WEXITSTATUS(status));
        /* A zombie that an exiting child leaves comes along too. */
        middle = child();
        if (middle == 0) {
            pid_t pid = child();
            if (pid == 0) _exit(5);
            siginfo_t info;
            waitid(P_PID, pid, &info, WEXITED | WNOWAIT);
            if (write(ready[1], &pid, sizeof pid) != sizeof pid) _exit(6);
            _exit(0);
        }
        if (read(ready[0], &zombie, sizeof zombie) != sizeof zombie) return 90;
        waitpid(middle, &status, 0);
        result("zombie-adopted", waitpid(zombie, &status, 0) == zombie);
        result("zombie-status", WEXITSTATUS(status));
        return 0;
    }
    if (!strcmp(mode, "orphaned-group")) {
        /* A group orphaned by an exit while a member is stopped gets SIGHUP
           and then SIGCONT from the kernel; a group with no stopped member
           gets nothing. A subreaper keeps the adopted members in reach, and
           a new session puts it outside theirs. */
        prctl(PR_SET_CHILD_SUBREAPER, 1);
        int pids[2], ready[2];
        if (pipe(pids) || pipe(ready)) return 91;
        for (int stop = 1; stop >= 0; stop--) {
            /* The session leader links its child's group to the session. */
            pid_t leader = child(), member = 0;
            if (leader == 0) {
                setsid();
                pid_t pid = child();
                if (pid == 0) {
                    setpgid(0, 0);
                    hangup_member(stop, ready[1]);
                }
                char byte;
                if (read(ready[0], &byte, 1) != 1) _exit(71);
                int status;
                if (stop && waitpid(pid, &status, WUNTRACED) != pid) _exit(72);
                if (write(pids[1], &pid, sizeof pid) != sizeof pid) _exit(73);
                _exit(0);
            }
            if (read(pids[0], &member, sizeof member) != sizeof member) return 92;
            int status;
            waitpid(leader, &status, 0);
            if (!stop) kill(member, SIGUSR1);
            if (waitpid(member, &status, 0) != member) return 93;
            result(stop ? "stopped-child-group" : "running-child-group",
                   WIFEXITED(status) ? WEXITSTATUS(status) : -WTERMSIG(status));
        }
        /* The member that linked its own group exits: the stopped member it
           leaves behind in that group is told. */
        pid_t leader = child(), member = 0;
        if (leader == 0) {
            setsid();
            pid_t linker = child();
            if (linker == 0) {
                setpgid(0, 0);
                pid_t pid = child();
                if (pid == 0) hangup_member(1, ready[1]);
                char byte;
                int status;
                if (read(ready[0], &byte, 1) != 1) _exit(74);
                if (waitpid(pid, &status, WUNTRACED) != pid) _exit(75);
                if (write(pids[1], &pid, sizeof pid) != sizeof pid) _exit(76);
                _exit(0);
            }
            int status;
            waitpid(linker, &status, 0);
            _exit(0);
        }
        if (read(pids[0], &member, sizeof member) != sizeof member) return 94;
        int status;
        waitpid(leader, &status, 0);
        if (waitpid(member, &status, 0) != member) return 95;
        result("stopped-own-group", WIFEXITED(status) ? WEXITSTATUS(status) : -WTERMSIG(status));
        return 0;
    }
    if (!strcmp(mode, "kill-group")) {
        /* kill(0) signals the caller's whole group, kill(-pgid) another
           group and kill(-1) every other process; a target with no process
           is ESRCH, even for an invalid signal, and a zombie still counts.
           The test runs in a group of its own, so that kill(0) reaches
           nothing outside it. Bit 0 of a pending set is SIGUSR1, bit 1
           SIGUSR2; both stay blocked. */
        pid_t leader = child();
        if (leader == 0) {
            setpgid(0, 0);
            sigset_t usr;
            sigemptyset(&usr);
            sigaddset(&usr, SIGUSR1);
            sigaddset(&usr, SIGUSR2);
            sigprocmask(SIG_BLOCK, &usr, NULL);
            int ready[2], go[2][2], seen[2];
            if (pipe(ready) || pipe(go[0]) || pipe(go[1]) || pipe(seen)) _exit(80);
            pid_t members[2];
            for (int i = 0; i < 2; i++) {
                members[i] = child();
                if (members[i] == 0) {
                    /* The second member leads a group of its own. */
                    if (i == 1) setpgid(0, 0);
                    char byte = 0;
                    if (write(ready[1], &byte, 1) != 1) _exit(81);
                    if (read(go[i][0], &byte, 1) != 1) _exit(82);
                    sigset_t set;
                    sigpending(&set);
                    int bits = sigismember(&set, SIGUSR1) | sigismember(&set, SIGUSR2) << 1;
                    if (write(seen[1], &bits, sizeof bits) != sizeof bits) _exit(83);
                    _exit(0);
                }
            }
            char byte = 0;
            for (int i = 0; i < 2; i++)
                if (read(ready[0], &byte, 1) != 1) _exit(84);
            result("own-group", kill(0, SIGUSR1));
            result("other-group", kill(-members[1], SIGUSR2));
            result("everyone", kill(-1, 0));
            result("no-group", kill(-members[0], 0) == -1 ? errno : 0);
            result("no-group-bad-signal", kill(-members[0], 65) == -1 ? errno : 0);
            result("group-bad-signal", kill(-members[1], 65) == -1 ? errno : 0);
            result("int-min", kill(INT_MIN, 0) == -1 ? errno : 0);
            sigset_t set;
            sigpending(&set);
            result("leader-pending", sigismember(&set, SIGUSR1) | sigismember(&set, SIGUSR2) << 1);
            for (int i = 0; i < 2; i++) {
                int bits = -1;
                if (write(go[i][1], &byte, 1) != 1) _exit(85);
                if (read(seen[0], &bits, sizeof bits) != sizeof bits) _exit(86);
                result(i ? "other-member-pending" : "member-pending", bits);
                waitpid(members[i], NULL, 0);
            }
            pid_t zombie = child();
            if (zombie == 0) _exit(0);
            siginfo_t info;
            waitid(P_PID, zombie, &info, WEXITED | WNOWAIT);
            result("zombie", kill(zombie, SIGUSR1));
            waitpid(zombie, NULL, 0);
            result("reaped-bad-signal", kill(zombie, 65) == -1 ? errno : 0);
            fflush(stdout);
            _exit(0);
        }
        int status;
        if (waitpid(leader, &status, 0) != leader) return 96;
        return WIFEXITED(status) ? WEXITSTATUS(status) : 97;
    }
    if (!strcmp(mode, "kill-before-sleep")) {
        /* A SIGKILL that comes while a child runs on to a long sleep ends
           the child: it does not sleep first. GNU parallel kills its
           `sleep 10101` placeholders so, as they start. The child says it
           runs, waits for the parent's go and spins a while after it, swept
           four times from none to about a checkpoint budget of
           instructions, so that some kills land just before its nanosleep
           however fast the kill comes; a kill missed until the sleep ends
           shows as a wait of more than 1000 s on the monotonic clock. */
        volatile int *shared = mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
        if (shared == MAP_FAILED) return 80;
        volatile int *ready = shared, *go = shared + 1;
        int killed = 0, late = 0;
        for (int i = 0; i < 400; i++) {
            *ready = 0;
            *go = 0;
            fflush(stdout);
            pid_t pid = child();
            if (pid < 0) return 79;
            if (pid == 0) {
                *ready = 1;
                while (!*go) {}
                for (volatile int spin = 0; spin < (i % 100) * 500; spin++) {}
                struct timespec forever = {10101, 0};
                syscall(SYS_nanosleep, &forever, NULL);
                _exit(0);
            }
            while (!*ready) {}
            struct timespec before, after;
            clock_gettime(CLOCK_MONOTONIC, &before);
            *go = 1;
            kill(pid, SIGKILL);
            int status = 0;
            if (waitpid(pid, &status, 0) != pid) return 78;
            clock_gettime(CLOCK_MONOTONIC, &after);
            killed += WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL;
            late += after.tv_sec - before.tv_sec > 1000;
        }
        result("killed", killed);
        result("late", late);
        return 0;
    }
    if (!strcmp(mode, "signal-sender")) {
        /* A signal from kill or pidfd_send_signal names its sender in
           si_pid, and the parent-death signal names the parent that exited;
           all three are SI_USER. The first two are different signals, as a
           second SIGUSR1 sent while the first is pending would be dropped. */
        sigset_t usr, usr2;
        sigemptyset(&usr);
        sigaddset(&usr, SIGUSR1);
        sigemptyset(&usr2);
        sigaddset(&usr2, SIGUSR2);
        sigprocmask(SIG_BLOCK, &usr, NULL);
        sigprocmask(SIG_BLOCK, &usr2, NULL);
        siginfo_t info;
        pid_t pid = child();
        if (pid == 0) {
            kill(getppid(), SIGUSR1);
            int pidfd = syscall(SYS_pidfd_open, getppid(), 0);
            if (pidfd < 0 || syscall(SYS_pidfd_send_signal, pidfd, SIGUSR2, NULL, 0)) _exit(81);
            _exit(0);
        }
        if (sigwaitinfo(&usr, &info) != SIGUSR1) return 82;
        result("kill-sender", info.si_pid == pid);
        result("kill-code", info.si_code);
        if (sigwaitinfo(&usr2, &info) != SIGUSR2) return 83;
        result("pidfd-sender", info.si_pid == pid);
        result("pidfd-code", info.si_code);
        waitpid(pid, NULL, 0);
        int ready[2], seen[2];
        if (pipe(ready) || pipe(seen)) return 84;
        pid_t parent = child();
        if (parent == 0) {
            pid_t orphan = child();
            if (orphan == 0) {
                prctl(PR_SET_PDEATHSIG, SIGUSR1);
                pid_t before = getppid();
                char byte = 0;
                if (write(ready[1], &byte, 1) != 1) _exit(85);
                if (sigwaitinfo(&usr, &info) != SIGUSR1) _exit(86);
                int found[2] = {info.si_pid == before, info.si_code};
                if (write(seen[1], found, sizeof found) != sizeof found) _exit(87);
                _exit(0);
            }
            char byte;
            if (read(ready[0], &byte, 1) != 1) _exit(88);
            _exit(0);
        }
        int found[2] = {-1, -1};
        if (read(seen[0], found, sizeof found) != sizeof found) return 89;
        waitpid(parent, NULL, 0);
        result("death-sender", found[0]);
        result("death-code", found[1]);
        return 0;
    }
    if (!strcmp(mode, "core-dump")) {
        /* A core-dumping signal writes `core` in the working directory when
           RLIMIT_CORE allows a page and the process is dumpable; wait then
           reports CLD_DUMPED and WCOREDUMP. A core past the limit is cut
           there and still reported. An old core is replaced. */
        char dir[] = "/tmp/core-XXXXXX";
        if (!mkdtemp(dir) || chdir(dir)) return 80;
        umask(022);
        core_report("full", core_child(RLIM_INFINITY, 1, 0, 0));
        core_report("threads", core_child(RLIM_INFINITY, 1, 1, 0));
        int old = open("core", O_CREAT | O_WRONLY, 0644);
        if (old < 0 || write(old, "old", 3) != 3) return 81;
        close(old);
        core_report("replaced", core_child(RLIM_INFINITY, 1, 0, 0));
        core_report("default", core_child(0, 1, 0, 0));
        core_report("small", core_child(4096, 1, 0, 0));
        core_report("undumpable", core_child(RLIM_INFINITY, 0, 0, 0));
        core_report("abort", core_child(RLIM_INFINITY, 1, 0, SIGABRT));
        core_report("term", core_child(RLIM_INFINITY, 1, 0, SIGTERM));
        if (chdir("/") || rmdir(dir)) return 82;
        return 0;
    }
    if (!strcmp(mode, "core-mappings")) {
        /* Which mappings a core holds, by the default coredump_filter as
           Linux's vma_dump_size applies it: a private mapping whole once a
           page of its VMA was written (its anon_vma: kept through a split,
           MADV_DONTNEED and fork, given to a mapping that merges with it,
           and made by populating a writable one), nothing of one only read
           or never touched, and of a private file mapping from the start of
           an ELF file only that first page. A shared mapping it holds whole
           when its file has no name (an anonymous one, a memfd, a file
           unlinked since), and nothing of it otherwise, written or not.
           None of this asks whether the mapping can be read, as Linux reads
           it with FOLL_FORCE; only an ELF header's page does. Each VMA is
           one segment, mappings merged into it too. The NT_FILE note, right
           after NT_AUXV, names the file of each VMA that maps one and its
           page there: a file by its path, marked " (deleted)" once
           unlinked, a memfd by its name, shared anonymous memory as
           /dev/zero (deleted), and the program's own segments the program.
           NT_X86_XSTATE follows NT_PRFPREG when the CPU has XSAVE, enabled
           (OSXSAVE), as large as CPUID leaf 0xd gives, and is left out
           otherwise. Each mapping lies between
           PROT_NONE pages, so that none merges with another but the one
           placed to. */
        char dir[] = "/tmp/core-XXXXXX";
        if (!mkdtemp(dir) || chdir(dir)) return 80;
        long page = 4096;
        char *base = mmap(NULL, 96 * page, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (base == MAP_FAILED) return 81;
        int fd = open("data", O_CREAT | O_RDWR, 0644);
        char fill[3 * 4096];
        memset(fill, 'x', sizeof fill);
        if (fd < 0 || write(fd, fill, sizeof fill) != (long)sizeof fill) return 82;
        int exe = open(self, O_RDONLY);
        int gone = open("gone", O_CREAT | O_RDWR, 0644);
        int memfd = memfd_create("core", 0);
        if (exe < 0 || gone < 0 || write(gone, fill, sizeof fill) != (long)sizeof fill || memfd < 0 ||
            ftruncate(memfd, 2 * page))
            return 83;
        const char *names[] = {"untouched", "read", "written", "read-only", "split", "populated",
                               "file-untouched", "file-written", "elf", "dontneed", "merged",
                               "child-written", "shared-anonymous", "shared-file",
                               "shared-unlinked", "shared-memfd", "unreadable-written",
                               "unreadable-shared", "unreadable-elf"};
        enum { COUNT = 19 };
        char *at[COUNT];
        for (int i = 0; i < COUNT; i++) {
            char *where = base + (1 + 5 * i) * page;
            int prot = i == 17 || i == 18                       ? PROT_NONE
                       : i == 3 || i == 8 || i == 14 || i == 15 ? PROT_READ
                                                                : PROT_READ | PROT_WRITE;
            int file = i == 6 || i == 7 || i == 13 ? fd
                       : i == 8 || i == 18         ? exe
                       : i == 14                   ? gone
                       : i == 15                   ? memfd
                                                   : -1;
            int shared = (i >= 12 && i <= 15) || i == 17;
            int flags = (shared ? MAP_SHARED : MAP_PRIVATE) | MAP_FIXED |
                        (file < 0 ? MAP_ANONYMOUS : 0) | (i == 5 ? MAP_POPULATE : 0);
            /* The one to merge sits right after the written one, which it
               merges with, still before the next one's PROT_NONE page. */
            if (i == 10) where = at[2] + 2 * page;
            at[i] = mmap(where, 2 * page, prot, flags, file, 0);
            if (at[i] != where) return 84;
        }
        volatile char sink = 0;
        sink += at[1][page];
        at[2][page] = 1;
        at[4][page] = 1;
        if (mprotect(at[4], page, PROT_READ)) return 85;
        at[7][0] = 1;
        at[9][0] = 1;
        if (madvise(at[9], 2 * page, MADV_DONTNEED)) return 86;
        at[13][0] = 1;
        if (unlink("gone")) return 86;
        at[16][page] = 0x5a;
        if (mprotect(at[16], 2 * page, PROT_NONE)) return 85;
        (void)sink;
        pid_t pid = fork();
        if (pid == 0) {
            struct rlimit r;
            getrlimit(RLIMIT_CORE, &r);
            r.rlim_cur = r.rlim_max;
            setrlimit(RLIMIT_CORE, &r);
            at[11][0] = 1;
            *(volatile int *)0 = 1;
            _exit(70);
        }
        int status = 0;
        waitpid(pid, &status, 0);
        int core = open("core", O_RDONLY);
        struct stat st;
        if (core < 0 || fstat(core, &st)) {
            printf("core=0 dumped=%d\n", WCOREDUMP(status) ? 1 : 0);
            return 0;
        }
        unsigned char *b = calloc(st.st_size + 1, 1);
        long size = 0, n;
        while (b && size < st.st_size && (n = read(core, b + size, st.st_size - size)) > 0) size += n;
        close(core);
        core_bytes = b;
        core_size = b ? (uint64_t)size : 0;
        /* Whether the core holds the bytes at `p`, and whether a segment
           covers it at all. */
#define CORE_HOLDS(p, held, covered) do { held = covered = 0; \
        for (int k = 0; k < (int)le(56, 2); k++) { uint64_t h = le(32, 8) + 56 * (uint64_t)k; \
            uint64_t v = le(h + 16, 8), f = le(h + 32, 8), m = le(h + 40, 8), x = (uintptr_t)(p); \
            if (le(h, 4) != 1 || x < v) continue; if (x < v + f) held = 1; if (x < v + m) covered = 1; } } while (0)
        for (int i = 0; i < COUNT; i++) {
            int first, second, covered, unused;
            CORE_HOLDS(at[i], first, covered);
            CORE_HOLDS(at[i] + page, second, unused);
            printf("%s: first=%d second=%d covered=%d\n", names[i], first, second, covered);
        }
        /* The byte written before the mapping became unreadable. */
        int byte = -1;
        for (int k = 0; k < (int)le(56, 2); k++) {
            uint64_t h = le(32, 8) + 56 * (uint64_t)k, x = (uintptr_t)(at[16] + page);
            uint64_t v = le(h + 16, 8), f = le(h + 32, 8);
            if (le(h, 4) == 1 && x >= v && x < v + f) byte = core_bytes[le(h + 8, 8) + (x - v)];
        }
        printf("unreadable-written: byte=%#x\n", byte);
        /* One segment for each VMA: the merged mapping shares the written
           one's, and the split one, two VMAs, has two. */
        int merged = 0, split = 0;
        for (int k = 0; k < (int)le(56, 2); k++) {
            uint64_t h = le(32, 8) + 56 * (uint64_t)k, v = le(h + 16, 8), m = le(h + 40, 8);
            if (le(h, 4) != 1) continue;
            if (v == (uintptr_t)at[2] && m == 4 * (uint64_t)page) merged = 1;
            if (v == (uintptr_t)at[4] && m == 2 * (uint64_t)page) split = 1;
        }
        printf("segments: merged-whole=%d split-whole=%d\n", merged, split);
        unsigned eax, ebx, ecx, edx, xsave_size = 0;
        __cpuid(1, eax, ebx, ecx, edx);
        int osxsave = ecx >> 27 & 1;
        if (osxsave) __cpuid_count(0xd, 0, eax, xsave_size, ecx, edx);
        uint64_t files = 0;
        int after_auxv = 0, xstate = 0, xstate_whole = 0;
        for (int k = 0; k < (int)le(56, 2); k++) {
            uint64_t h = le(32, 8) + 56 * (uint64_t)k, offset = le(h + 8, 8), filesz = le(h + 32, 8);
            if (le(h, 4) != 4) continue;
            uint64_t previous = 0;
            for (uint64_t q = offset; q + 12 <= offset + filesz && q + 12 <= core_size;) {
                uint64_t namesz = le(q, 4), descsz = le(q + 4, 4), type = le(q + 8, 4);
                uint64_t desc = q + 12 + ((namesz + 3) & ~3ULL);
                if (type == 0x46494c45 && !files) files = desc, after_auxv = previous == 6;
                if (type == 0x202 && !xstate++)
                    xstate_whole = previous == 2 && descsz == xsave_size && namesz == 6 &&
                                   !memcmp(core_bytes + q + 12, "LINUX", 6);
                previous = type;
                q = desc + ((descsz + 3) & ~3ULL);
            }
        }
        printf("files: page=%llu after-auxv=%d\n", (unsigned long long)le(files + 8, 8), after_auxv);
        char cwd[PATH_MAX], data_path[PATH_MAX + 8], gone_path[PATH_MAX + 24];
        if (!getcwd(cwd, sizeof cwd)) return 88;
        snprintf(data_path, sizeof data_path, "%s/data", cwd);
        snprintf(gone_path, sizeof gone_path, "%s/gone (deleted)", cwd);
        for (int i = 0; i < COUNT; i++) {
            const char *want = i == 6 || i == 7 || i == 13 ? data_path
                               : i == 14                   ? gone_path
                               : i == 15                   ? "/memfd:core (deleted)"
                               : i == 12 || i == 17        ? "/dev/zero (deleted)"
                               : i == 8 || i == 18         ? self
                                                           : NULL;
            uint64_t start = 0, end = 0, pgoff = 0;
            const char *name = file_entry(files, (uintptr_t)at[i], &start, &end, &pgoff);
            int same = name && want && start == (uintptr_t)at[i] &&
                       end == (uintptr_t)at[i] + 2 * page && pgoff == 0 &&
                       (want == self ? same_path(name, self) : !strcmp(name, want));
            printf("%s: file=%d\n", names[i], !name ? 0 : same ? 1 : 2);
        }
        dl_iterate_phdr(text_segment, NULL);
        uint64_t start = 0, end = 0, pgoff = 0;
        const char *name = file_entry(files, (uintptr_t)&text_segment, &start, &end, &pgoff);
        printf("program: file=%d\n", name && start == text_start && pgoff == text_pgoff &&
                                          same_path(name, (const char *)getauxval(AT_EXECFN)));
        printf("xstate: as-cpu=%d\n", osxsave ? xstate == 1 && xstate_whole : !xstate);
#undef CORE_HOLDS
        free(b);
        unlink("core");
        unlink("data");
        if (chdir("/") || rmdir(dir)) return 87;
        return 0;
    }
    if (!strcmp(mode, "sigqueue")) {
        /* sigqueue delivers its value with SI_QUEUE, and a realtime signal
           keeps every one. rt_sigqueueinfo takes the caller's siginfo as it
           is, but only a thread signalling itself may give a code kill or
           tkill would (EPERM, before ESRCH); an unknown layout needs a zero
           tail (E2BIG). rt_tgsigqueueinfo reaches one thread. */
        sigset_t set;
        sigemptyset(&set);
        sigaddset(&set, SIGUSR1);
        sigaddset(&set, SIGRTMIN);
        sigprocmask(SIG_BLOCK, &set, NULL);
        pid_t pid = fork();
        if (pid == 0) {
            pid_t parent = getppid();
            if (sigqueue(parent, SIGRTMIN, (union sigval){.sival_int = 1}) ||
                sigqueue(parent, SIGRTMIN, (union sigval){.sival_int = 2}) ||
                sigqueue(parent, SIGUSR1, (union sigval){.sival_int = 5}))
                _exit(1);
            _exit(0);
        }
        int status;
        waitpid(pid, &status, 0);
        result("child", WEXITSTATUS(status));
        siginfo_t info;
        for (int i = 0; i < 3; i++) {
            int number = sigwaitinfo(&set, &info);
            printf("%s: code=%d value=%d sender=%d\n", number == SIGUSR1 ? "usr1" : "rt",
                   info.si_code, info.si_value.sival_int, info.si_pid == pid);
        }
        /* pid is reaped now, so it names no process. */
        siginfo_t given;
        memset(&given, 0, sizeof given);
        given.si_code = SI_QUEUE;
        given.si_value.sival_int = 9;
        errno = 0;
        result("self", syscall(SYS_rt_sigqueueinfo, getpid(), SIGUSR1, &given));
        result("self-taken", sigwaitinfo(&set, &info) == SIGUSR1 && info.si_value.sival_int == 9);
        result("none", syscall(SYS_rt_sigqueueinfo, pid, SIGUSR1, &given) ? errno : 0);
        result("probe", syscall(SYS_rt_sigqueueinfo, getpid(), 0, &given));
        errno = 0;
        result("bad-signal", syscall(SYS_rt_sigqueueinfo, getpid(), 65, &given) ? errno : 0);
        errno = 0;
        result("fault", syscall(SYS_rt_sigqueueinfo, getpid(), SIGUSR1, (void *)8) ? errno : 0);
        given.si_code = SI_USER;
        errno = 0;
        result("user-other", syscall(SYS_rt_sigqueueinfo, pid, SIGUSR1, &given) ? errno : 0);
        result("user-self", syscall(SYS_rt_sigqueueinfo, getpid(), SIGUSR1, &given));
        result("user-taken", sigwaitinfo(&set, &info) == SIGUSR1 && info.si_code == SI_USER);
        given.si_code = SI_TKILL;
        errno = 0;
        result("tkill-other", syscall(SYS_rt_sigqueueinfo, pid, SIGUSR1, &given) ? errno : 0);
        unsigned char raw[128] = {0};
        int unknown = -8;
        memcpy(raw + 8, &unknown, 4);
        raw[100] = 1;
        errno = 0;
        result("unknown-tail", syscall(SYS_rt_sigqueueinfo, getpid(), SIGUSR1, raw) ? errno : 0);
        raw[100] = 0;
        result("unknown-zero", syscall(SYS_rt_sigqueueinfo, getpid(), SIGUSR1, raw));
        result("unknown-code", sigwaitinfo(&set, &info) == SIGUSR1 ? info.si_code : 0);
        /* Past SI_KERNEL, and past SIGUSR1's codes (NSIGPOLL), unknown too. */
        int high[] = {0x81, 7};
        for (int i = 0; i < 2; i++) {
            memcpy(raw + 8, &high[i], 4);
            raw[100] = 1;
            errno = 0;
            result(i ? "past-poll-tail" : "past-kernel-tail",
                   syscall(SYS_rt_sigqueueinfo, getpid(), SIGUSR1, raw) ? errno : 0);
        }
        given.si_code = SI_QUEUE;
        given.si_value.sival_int = 4;
        pid_t tid = syscall(SYS_gettid);
        result("thread", syscall(SYS_rt_tgsigqueueinfo, getpid(), tid, SIGUSR1, &given));
        result("thread-taken", sigwaitinfo(&set, &info) == SIGUSR1 && info.si_value.sival_int == 4);
        errno = 0;
        result("thread-no-group", syscall(SYS_rt_tgsigqueueinfo, 0, tid, SIGUSR1, &given) ? errno : 0);
        errno = 0;
        result("thread-fault", syscall(SYS_rt_tgsigqueueinfo, 0, tid, SIGUSR1, (void *)8) ? errno : 0);
        errno = 0;
        result("thread-none", syscall(SYS_rt_tgsigqueueinfo, getpid(), pid, SIGUSR1, &given) ? errno : 0);
        return 0;
    }
    if (!strcmp(mode, "sparse")) {
        /* A file grown by ftruncate is a hole: no blocks, zeros to read and
           no data for SEEK_DATA. A write allocates its page, fallocate
           allocates pages that stay a hole until written, a punched hole
           frees its pages, and shrinking frees what is past the end. */
        char path[] = "/tmp/sparse-XXXXXX";
        int fd = mkstemp(path);
        if (fd < 0) return 80;
        unlink(path);
        struct stat st;
        const off_t mib = 1 << 20;
#define BLOCKS() (fstat(fd, &st) ? -1 : (long)st.st_blocks)
#define SEEK(off, whence) (lseek(fd, (off), (whence)) < 0 ? -errno : (long)lseek(fd, (off), (whence)))
        result("grow", ftruncate(fd, 1L << 30));
        result("grown-blocks", BLOCKS());
        char b[8] = {1, 1, 1, 1, 1, 1, 1, 1};
        result("hole-read", pread(fd, b, 8, 512 * mib) == 8 && !memcmp(b, "\0\0\0\0\0\0\0\0", 8));
        result("no-data", SEEK(0, SEEK_DATA));
        result("hole-here", SEEK(5, SEEK_HOLE));
        result("write", pwrite(fd, "x", 1, mib));
        result("written-blocks", BLOCKS());
        result("data-at", SEEK(0, SEEK_DATA) == mib);
        result("hole-after", SEEK(mib, SEEK_HOLE) == mib + 4096);
        result("allocate", fallocate(fd, 0, 2 * mib, 8192));
        result("allocated-blocks", BLOCKS());
        result("allocated-is-hole", SEEK(mib + 4096, SEEK_DATA));
        result("punch", fallocate(fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, mib, 4096));
        result("punched-blocks", BLOCKS());
        result("punched-data", SEEK(0, SEEK_DATA));
        result("size", fstat(fd, &st) ? -1 : st.st_size == 1L << 30);
        result("past-end", SEEK(1L << 30, SEEK_HOLE));
        result("shrink", ftruncate(fd, 100));
        result("shrunk-blocks", BLOCKS());
#undef BLOCKS
#undef SEEK
        close(fd);
        return 0;
    }
    if (!strcmp(mode, "waitid")) {
        siginfo_t info;
        pid_t pid = child();
        if (pid == 0) _exit(5);
        memset(&info, 0x55, sizeof info);
        result("nowait", waitid(P_PID, pid, &info, WEXITED | WNOWAIT));
        result("signo", info.si_signo);
        result("code", info.si_code);
        result("pid", info.si_pid == pid);
        result("status", info.si_status);
        result("uid", info.si_uid == getuid());
        result("again", waitid(P_PID, pid, &info, WEXITED));
        result("status", info.si_status);
        pid = child();
        if (pid == 0) {
            pause();
            _exit(0);
        }
        kill(pid, SIGTERM);
        /* Without WEXITED an exited child cannot be waited for (ECHILD), and
           stays for a later wait (brush asks for WSTOPPED alone). */
        siginfo_t stopped;
        while (waitid(P_PID, pid, &stopped, WEXITED | WNOHANG | WNOWAIT) == 0 && stopped.si_pid == 0)
            sched_yield();
        errno = 0;
        result("stopped-only", waitid(P_PID, pid, &stopped, WSTOPPED | WNOHANG));
        result("errno", errno);
        result("killed", waitid(P_ALL, 0, &info, WEXITED));
        result("code", info.si_code);
        result("status", info.si_status);
        /* Nothing to report: the fields are zero, and so they are on an error. */
        int gate[2];
        pid = gated(gate, 6);
        memset(&info, 0x55, sizeof info);
        result("nohang", waitid(P_PID, pid, &info, WEXITED | WNOHANG));
        result("nohang-cleared", info.si_signo == 0 && info.si_pid == 0 && info.si_status == 0);
        memset(&info, 0x55, sizeof info);
        errno = 0;
        result("bad-pid", waitid(P_PID, 0, &info, WEXITED));
        result("errno", errno);
        result("error-cleared", info.si_signo == 0 && info.si_code == 0 && info.si_pid == 0);
        errno = 0;
        result("no-options", waitid(P_ALL, 0, &info, 0));
        result("errno", errno);
        errno = 0;
        result("bad-option", waitid(P_ALL, 0, &info, WEXITED | 0x10));
        result("errno", errno);
        errno = 0;
        result("bad-type", syscall(SYS_waitid, 9, 0, &info, WEXITED, NULL));
        result("errno", errno);
        errno = 0;
        result("bad-pidfd", syscall(SYS_waitid, 3, 0, &info, WEXITED, NULL));
        result("errno", errno);
        write(gate[1], "x", 1);
        result("gated", waitid(P_PID, pid, &info, WEXITED));
        result("status", info.si_status);
        errno = 0;
        result("no-children", waitid(P_ALL, 0, &info, WEXITED));
        result("errno", errno);
        /* Process groups, through waitid and wait4. */
        pid = gated(gate, 3);
        setpgid(pid, pid);
        write(gate[1], "x", 1);
        result("pgid", waitid(P_PGID, pid, &info, WEXITED));
        result("status", info.si_status);
        pid = gated(gate, 4);
        setpgid(pid, pid);
        write(gate[1], "x", 1);
        int status = 0;
        result("wait-pgid", waitpid(-pid, &status, 0) == pid);
        result("status", WEXITSTATUS(status));
        pid = gated(gate, 8);
        write(gate[1], "x", 1);
        result("wait-own-group", waitpid(0, &status, 0) == pid);
        result("status", WEXITSTATUS(status));
        /* pidfds: readable after the exit, waitable, and EAGAIN when nonblocking. */
        pid = gated(gate, 7);
        int pidfd = syscall(SYS_pidfd_open, pid, 0);
        result("pidfd", pidfd >= 0);
        result("cloexec", fcntl(pidfd, F_GETFD) & FD_CLOEXEC);
        struct pollfd ready = {pidfd, POLLIN, 0};
        result("running", poll(&ready, 1, 0));
        int nonblocking = syscall(SYS_pidfd_open, pid, PIDFD_NONBLOCK);
        errno = 0;
        result("nonblocking", syscall(SYS_waitid, P_PIDFD, nonblocking, &info, WEXITED, NULL));
        result("errno", errno);
        char byte;
        errno = 0;
        result("read", read(pidfd, &byte, 1));
        result("errno", errno);
        write(gate[1], "x", 1);
        /* epoll waits for the exit (Tokio's reaper does so); no timeout, as
           the emulated harness runs a virtual clock. */
        int epoll = epoll_create1(EPOLL_CLOEXEC);
        struct epoll_event watch = {.events = EPOLLIN, .data.u64 = 42}, seen = {0};
        epoll_ctl(epoll, EPOLL_CTL_ADD, pidfd, &watch);
        result("exited", epoll_wait(epoll, &seen, 1, -1));
        result("readable", (seen.events & EPOLLIN) && seen.data.u64 == 42);
        close(epoll);
        result("by-pidfd", syscall(SYS_waitid, P_PIDFD, pidfd, &info, WEXITED, NULL));
        result("status", info.si_status);
        errno = 0;
        result("signal-reaped", syscall(SYS_pidfd_send_signal, pidfd, SIGTERM, NULL, 0));
        result("errno", errno);
        close(nonblocking);
        close(pidfd);
        pid = gated(gate, 0);
        pidfd = syscall(SYS_pidfd_open, pid, 0);
        errno = 0;
        result("signal-flags", syscall(SYS_pidfd_send_signal, pidfd, SIGTERM, NULL, 8));
        result("errno", errno);
        result("signal", syscall(SYS_pidfd_send_signal, pidfd, SIGTERM, NULL, 0));
        result("signalled", waitid(P_PID, pid, &info, WEXITED));
        result("status", info.si_status);
        close(pidfd);
        close(gate[1]);
        errno = 0;
        result("open-zero", syscall(SYS_pidfd_open, 0, 0));
        result("errno", errno);
        errno = 0;
        result("open-flags", syscall(SYS_pidfd_open, getpid(), 1));
        result("errno", errno);
        errno = 0;
        result("open-missing", syscall(SYS_pidfd_open, 999999, 0));
        result("errno", errno);
        pipe(tid_report);
        pipe(tid_release);
        pthread_t thread;
        pthread_create(&thread, NULL, parked, NULL);
        int tid = 0;
        read(tid_report[0], &tid, sizeof tid);
        errno = 0;
        result("open-thread", syscall(SYS_pidfd_open, tid, 0));
        result("errno", errno);
        write(tid_release[1], "x", 1);
        pthread_join(thread, NULL);
        return 0;
    }
    if (!strcmp(mode, "pio")) {
        /* pread64, pwrite64, readv, preadv and pwritev: positioned calls leave
           the file position; errors come in Linux's order. */
        char buf[32] = {0};
        int fd = open("/tmp/pio", O_RDWR | O_CREAT | O_TRUNC, 0600);
        if (fd < 0 || write(fd, "abcdefgh", 8) != 8) return 81;
        lseek(fd, 2, SEEK_SET);
        result("pread", pread(fd, buf, 3, 4));
        result("pread-bytes", !memcmp(buf, "efg", 3));
        result("position", lseek(fd, 0, SEEK_CUR));
        result("pwrite", pwrite(fd, "XY", 2, 6));
        result("position", lseek(fd, 0, SEEK_CUR));
        memset(buf, 0, sizeof buf);
        result("whole", pread(fd, buf, sizeof buf, 0));
        result("whole-bytes", !memcmp(buf, "abcdefXY", 8));
        result("gap", pwrite(fd, "Q", 1, 10));
        memset(buf, 1, sizeof buf);
        result("gap-read", pread(fd, buf, sizeof buf, 7));
        result("gap-bytes", buf[0] == 'Y' && buf[1] == 0 && buf[2] == 0 && buf[3] == 'Q');
        result("past-end", pread(fd, buf, 4, 100));
        result("empty", pread(fd, buf, 0, 0));
        struct iovec parts[2] = {{buf, 2}, {buf + 8, 3}};
        memset(buf, 0, sizeof buf);
        result("preadv", preadv(fd, parts, 2, 1));
        result("preadv-bytes", !memcmp(buf, "bc", 2) && !memcmp(buf + 8, "def", 3));
        struct iovec out[2] = {{"12", 2}, {"345", 3}};
        result("pwritev", pwritev(fd, out, 2, 0));
        result("position", lseek(fd, 0, SEEK_CUR));
        memset(buf, 0, sizeof buf);
        pread(fd, buf, 8, 0);
        result("pwritev-bytes", !memcmp(buf, "12345fXY", 8));
        errno = 0;
        result("negative", pread(fd, buf, 1, -1));
        result("errno", errno);
        errno = 0;
        result("negative-bad-fd", pread(99, buf, 1, -1));
        result("errno", errno);
        errno = 0;
        result("bad-fd", pread(99, buf, 1, 0));
        result("errno", errno);
        errno = 0;
        result("preadv-negative", preadv(fd, parts, 2, -5));
        result("errno", errno);
        errno = 0;
        result("too-many", preadv(fd, parts, 1025, 0));
        result("errno", errno);
        result("none", preadv(fd, parts, 0, 0));
        close(fd);
        /* A read-only and a write-only file, an append-mode file, a directory. */
        fd = open("/tmp/pio", O_RDONLY);
        errno = 0;
        result("pwrite-read-only", pwrite(fd, "x", 1, 0));
        result("errno", errno);
        close(fd);
        fd = open("/tmp/pio", O_WRONLY);
        errno = 0;
        result("pread-write-only", pread(fd, buf, 1, 0));
        result("errno", errno);
        /* The access mode is checked before the iovec array. */
        errno = 0;
        result("preadv-write-only-too-many", preadv(fd, parts, 1025, 0));
        result("errno", errno);
        close(fd);
        fd = open("/tmp/pio", O_RDWR | O_APPEND);
        result("append", pwrite(fd, "Z", 1, 0));
        result("append-position", lseek(fd, 0, SEEK_CUR));
        memset(buf, 0, sizeof buf);
        result("append-size", pread(fd, buf, sizeof buf, 0));
        result("append-last", buf[11]);
        close(fd);
        fd = open("/tmp", O_RDONLY | O_DIRECTORY);
        errno = 0;
        result("directory", pread(fd, buf, 1, 0));
        result("errno", errno);
        close(fd);
        /* Pipes have no position; readv gathers what one read gives. */
        int pipefd[2];
        if (pipe(pipefd)) return 82;
        errno = 0;
        result("pipe-pread", pread(pipefd[0], buf, 1, 0));
        result("errno", errno);
        errno = 0;
        result("pipe-pwrite", pwrite(pipefd[1], "x", 1, 0));
        result("errno", errno);
        if (write(pipefd[1], "hello world", 11) != 11) return 83;
        struct iovec two[2] = {{buf, 5}, {buf + 16, 6}};
        memset(buf, 0, sizeof buf);
        result("readv", readv(pipefd[0], two, 2));
        result("readv-bytes", !memcmp(buf, "hello", 5) && !memcmp(buf + 16, " world", 6));
        errno = 0;
        result("readv-too-many", readv(pipefd[0], two, 1025));
        result("errno", errno);
        errno = 0;
        result("readv-write-end", readv(pipefd[1], two, 2));
        result("errno", errno);
        errno = 0;
        result("readv-write-end-too-many", readv(pipefd[1], two, 1025));
        result("errno", errno);
        /* /dev/null reads nothing and takes everything at any offset. */
        fd = open("/dev/null", O_RDWR);
        result("null-pread", pread(fd, buf, 4, 3));
        result("null-pwrite", pwrite(fd, "abc", 3, 7));
        close(fd);
        unlink("/tmp/pio");
        return 0;
    }
    if (!strcmp(mode, "stop-restart")) {
        /* A child blocked in read, then in poll with no timeout, then in
           nanosleep, poll with a timeout, an absolute clock_nanosleep and a
           timed futex wait, is
           stopped and continued: each call runs again (the timed ones with
           the time they had left) instead of failing with EINTR, as no
           handler ran. The child says "ready" before each call; a stop
           that lands before the call is entered changes nothing. */
        int ready[2], data[2];
        if (pipe(ready) || pipe(data)) return 81;
        pid_t pid = child();
        if (pid == 0) {
            char byte;
            if (write(ready[1], "r", 1) != 1) _exit(82);
            ssize_t n = read(data[0], &byte, 1);
            if (n != 1) _exit(n < 0 && errno == EINTR ? 83 : 84);
            if (write(ready[1], "p", 1) != 1) _exit(85);
            struct pollfd pfd = {data[0], POLLIN, 0};
            int r = poll(&pfd, 1, -1);
            if (r != 1) _exit(r < 0 && errno == EINTR ? 86 : 87);
            /* Timed waits resume with the time they had left. */
            if (read(data[0], &byte, 1) != 1) _exit(88);
            if (write(ready[1], "s", 1) != 1) _exit(89);
            struct timespec sleep = {0, 300000000};
            if (nanosleep(&sleep, NULL)) _exit(90);
            if (write(ready[1], "t", 1) != 1) _exit(91);
            r = poll(&pfd, 1, 300);
            if (r != 0) _exit(r < 0 ? (errno == EINTR ? 95 : 96) : 92);
            if (write(ready[1], "a", 1) != 1) _exit(93);
            struct timespec until;
            clock_gettime(CLOCK_MONOTONIC, &until);
            until.tv_nsec += 300000000;
            if (until.tv_nsec >= 1000000000) { until.tv_sec++; until.tv_nsec -= 1000000000; }
            if (clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &until, NULL)) _exit(94);
            /* A timed futex wait nobody wakes ends with ETIMEDOUT, not EINTR. */
            if (write(ready[1], "f", 1) != 1) _exit(99);
            static int word;
            struct timespec wait = {0, 300000000};
            long f = syscall(SYS_futex, &word, 128 /* FUTEX_WAIT_PRIVATE */, 0, &wait, NULL, 0);
            if (f != -1 || errno != ETIMEDOUT) _exit(f == -1 && errno == EINTR ? 100 : 101);
            /* Wait for the parent, so that a sleep which ends before the stop
               (the emulated harness's clock is virtual) cannot exit early. */
            if (read(data[0], &byte, 1) != 1) _exit(97);
            _exit(0);
        }
        /* Only the child writes ready and reads data, so an early exit of
           the child ends the parent's read instead of hanging it. */
        close(ready[1]);
        close(data[0]);
        signal(SIGPIPE, SIG_IGN);
        int status;
        char byte;
        for (int round = 0; round < 6; round++) {
            if (read(ready[0], &byte, 1) != 1) break;
            struct timespec nap = {0, 20000000};
            nanosleep(&nap, NULL);
            kill(pid, SIGSTOP);
            result("stopped", waitpid(pid, &status, WUNTRACED) == pid && WIFSTOPPED(status));
            kill(pid, SIGCONT);
            result("continued", waitpid(pid, &status, WCONTINUED) == pid && WIFCONTINUED(status));
            /* A byte for the read, then one for the poll (read after it). */
            if (round < 2 && write(data[1], "x", 1) != 1) break;
        }
        if (write(data[1], "z", 1) != 1) return 98;
        result("exited", waitpid(pid, &status, 0) == pid);
        result("code", WEXITSTATUS(status));
        return 0;
    }
    if (!strcmp(mode, "sigsuspend")) {
        /* rt_sigsuspend swaps in its mask until a handler has run, then the
           old mask is back; pause waits with the mask as it is. Neither
           ends for an ignored signal. */
        struct sigaction act = {0};
        act.sa_handler = note_mask;
        sigaction(SIGUSR1, &act, NULL);
        signal(SIGHUP, SIG_IGN);
        sigset_t usr1, suspend, now;
        sigemptyset(&usr1);
        sigaddset(&usr1, SIGUSR1);
        sigprocmask(SIG_BLOCK, &usr1, NULL);
        pid_t pid = pester(SIGUSR1);
        sigemptyset(&suspend);
        sigaddset(&suspend, SIGUSR2);
        errno = 0;
        result("suspend", sigsuspend(&suspend));
        result("errno", errno);
        result("received", received >= 1);
        result("usr2-blocked-in-handler", usr2_blocked_in_handler);
        sigprocmask(SIG_BLOCK, NULL, &now);
        result("usr1-blocked-after", sigismember(&now, SIGUSR1));
        result("usr2-blocked-after", sigismember(&now, SIGUSR2));
        kill(pid, SIGKILL);
        waitpid(pid, NULL, 0);
        /* pause: SIGHUP (ignored) arrives first and does not end it. */
        received = 0;
        sigprocmask(SIG_UNBLOCK, &usr1, NULL);
        kill(getpid(), SIGHUP);
        pid = pester(SIGUSR1);
        errno = 0;
        result("pause", pause());
        result("errno", errno);
        result("received", received >= 1);
        kill(pid, SIGKILL);
        waitpid(pid, NULL, 0);
        errno = 0;
        result("bad-size", syscall(SYS_rt_sigsuspend, &suspend, 7));
        result("errno", errno);
        errno = 0;
        result("bad-mask", syscall(SYS_rt_sigsuspend, (void *)16, 8));
        result("errno", errno);
        return 0;
    }
    if (!strcmp(mode, "select")) {
        /* select, pselect6 and ppoll: ready sets, timeouts written back with
           the time left (none for a zero timeout), errors in Linux's order,
           and a temporary signal mask that a handler runs with. The calls
           with a timeout are raw syscalls: musl passes the kernel a copy of
           the timeout, so its wrappers never show the written-back time. */
        int p[2];
        if (pipe(p)) return 81;
        fd_set r, w, e;
        FD_ZERO(&r); FD_SET(p[0], &r);
        struct timeval zero = {0, 0};
        result("empty", syscall(SYS_select, p[0] + 1, &r, NULL, NULL, &zero));
        result("empty-cleared", !FD_ISSET(p[0], &r));
        result("zero-kept", zero.tv_sec == 0 && zero.tv_usec == 0);
        if (write(p[1], "x", 1) != 1) return 82;
        FD_ZERO(&r); FD_ZERO(&w); FD_ZERO(&e);
        FD_SET(p[0], &r); FD_SET(p[1], &w); FD_SET(p[0], &e);
        struct timeval five = {5, 0};
        result("ready", syscall(SYS_select, p[1] + 1, &r, &w, &e, &five));
        result("read", FD_ISSET(p[0], &r));
        result("write", FD_ISSET(p[1], &w));
        result("except", FD_ISSET(p[0], &e));
        long left = five.tv_sec * 1000000L + five.tv_usec;
        result("left", left > 4000000 && left <= 5000000);
        char byte;
        if (read(p[0], &byte, 1) != 1) return 83;
        FD_ZERO(&r); FD_SET(p[0], &r);
        struct timeval short_wait = {0, 20000};
        result("timeout", syscall(SYS_select, p[0] + 1, &r, NULL, NULL, &short_wait));
        result("timeout-left", short_wait.tv_sec == 0 && short_wait.tv_usec == 0);
        FD_ZERO(&r); FD_SET(60, &r);
        errno = 0;
        result("closed", select(61, &r, NULL, NULL, &zero));
        result("errno", errno);
        errno = 0;
        result("negative", select(-1, NULL, NULL, NULL, &zero));
        result("errno", errno);
        /* Whole seconds of microseconds carry into the seconds; a negative
           part is EINVAL. */
        struct timeval carry = {0, 1000000};
        result("carried-timeval", syscall(SYS_select, 1, NULL, NULL, NULL, &carry));
        struct timeval bad = {0, -1};
        errno = 0;
        result("bad-timeval", syscall(SYS_select, 1, NULL, NULL, NULL, &bad));
        result("errno", errno);
        /* ppoll */
        struct pollfd pfd = {p[0], POLLIN, 0};
        struct timespec ts = {0, 20000000};
        result("ppoll-timeout", syscall(SYS_ppoll, &pfd, 1, &ts, NULL, 8));
        result("ppoll-left", ts.tv_sec == 0 && ts.tv_nsec == 0);
        if (write(p[1], "y", 1) != 1) return 84;
        struct timespec ten = {10, 0};
        result("ppoll-ready", syscall(SYS_ppoll, &pfd, 1, &ten, NULL, 8));
        result("ppoll-revents", pfd.revents);
        long ns_left = ten.tv_sec * 1000000000L + ten.tv_nsec;
        result("ppoll-left-ready", ns_left > 9000000000L && ns_left <= 10000000000L);
        struct timespec bad_ts = {0, 1000000000};
        errno = 0;
        result("ppoll-bad-timespec", ppoll(&pfd, 1, &bad_ts, NULL));
        result("errno", errno);
        errno = 0;
        result("ppoll-bad-size", syscall(SYS_ppoll, &pfd, 1, NULL, &ten, 7));
        result("errno", errno);
        /* A blocked SIGUSR1 is let in by the temporary mask; the handler runs
           with it (SIGUSR2 blocked), and the old mask is back afterwards. */
        struct sigaction act = {0};
        act.sa_handler = note_mask;
        sigaction(SIGUSR1, &act, NULL);
        sigset_t usr1, temporary, now;
        sigemptyset(&usr1);
        sigaddset(&usr1, SIGUSR1);
        sigprocmask(SIG_BLOCK, &usr1, NULL);
        sigemptyset(&temporary);
        sigaddset(&temporary, SIGUSR2);
        if (read(p[0], &byte, 1) != 1) return 85;
        raise(SIGUSR1);
        received = 0;
        errno = 0;
        result("ppoll-signal", ppoll(&pfd, 1, NULL, &temporary));
        result("errno", errno);
        result("received", received);
        result("usr2-blocked-in-handler", usr2_blocked_in_handler);
        sigprocmask(SIG_BLOCK, NULL, &now);
        result("usr1-blocked-after", sigismember(&now, SIGUSR1));
        raise(SIGUSR1);
        received = 0;
        usr2_blocked_in_handler = -1;
        FD_ZERO(&r); FD_SET(p[0], &r);
        errno = 0;
        result("pselect-signal", pselect(p[0] + 1, &r, NULL, NULL, NULL, &temporary));
        result("errno", errno);
        result("received", received);
        result("usr2-blocked-in-handler", usr2_blocked_in_handler);
        sigprocmask(SIG_BLOCK, NULL, &now);
        result("usr1-blocked-after", sigismember(&now, SIGUSR1));
        struct timespec pzero = {0, 0};
        FD_ZERO(&r); FD_SET(p[0], &r);
        result("pselect-empty", syscall(SYS_pselect6, p[0] + 1, &r, NULL, NULL, &pzero, NULL));
        result("pselect-zero-kept", pzero.tv_sec == 0 && pzero.tv_nsec == 0);
        struct timespec pshort = {0, 20000000};
        FD_ZERO(&r); FD_SET(p[0], &r);
        result("pselect-timeout", syscall(SYS_pselect6, p[0] + 1, &r, NULL, NULL, &pshort, NULL));
        result("pselect-left", pshort.tv_sec == 0 && pshort.tv_nsec == 0);
        errno = 0;
        result("pselect-bad-timespec", pselect(1, NULL, NULL, NULL, &bad_ts, NULL));
        result("errno", errno);
        return 0;
    }
    if (!strcmp(mode, "job-stop")) {
        /* A child stops itself, then is stopped and continued by kill; waits
           report each event once, and SIGCHLD follows unless SA_NOCLDSTOP.
           The child polls its gate, so no blocking call of its is interrupted
           by the stop. */
        sigset_t chld;
        sigemptyset(&chld);
        sigaddset(&chld, SIGCHLD);
        sigprocmask(SIG_BLOCK, &chld, NULL);
        int gate[2];
        if (pipe2(gate, O_NONBLOCK)) return 81;
        pid_t pid = child();
        if (pid == 0) {
            /* Not raise(): after a raw fork glibc's cached tid is the parent's. */
            kill(getpid(), SIGSTOP);
            char byte;
            while (read(gate[0], &byte, 1) != 1) sched_yield();
            _exit(7);
        }
        int status;
        result("untraced", waitpid(pid, &status, WUNTRACED) == pid);
        result("stopped", WIFSTOPPED(status));
        result("stop-signal", WSTOPSIG(status));
        sigset_t pending;
        sigpending(&pending);
        result("sigchld-stop", sigismember(&pending, SIGCHLD));
        siginfo_t info;
        result("sigchld", sigwaitinfo(&chld, &info));
        result("sigchld-code", info.si_code);
        result("sigchld-status", info.si_status);
        result("sigchld-pid", info.si_pid == pid);
        memset(&info, 0x55, sizeof info);
        result("consumed", waitid(P_PID, pid, &info, WSTOPPED | WNOHANG));
        result("consumed-pid", info.si_pid);
        result("not-untraced", waitpid(pid, &status, WNOHANG));
        kill(pid, SIGCONT);
        result("nowait", waitid(P_PID, pid, &info, WCONTINUED | WNOWAIT));
        result("code", info.si_code);
        result("status", info.si_status);
        result("pid", info.si_pid == pid);
        result("continued", waitpid(pid, &status, WCONTINUED) == pid);
        result("ifcontinued", WIFCONTINUED(status));
        result("raw", status);
        result("sigchld-cont", sigwaitinfo(&chld, &info));
        result("sigchld-cont-code", info.si_code);
        result("sigchld-cont-status", info.si_status);
        result("sigchld-cont-pid", info.si_pid == pid);
        result("again", waitpid(pid, &status, WCONTINUED | WNOHANG));
        /* A stop by kill, now with SA_NOCLDSTOP: no SIGCHLD for it. */
        struct sigaction quiet = { .sa_handler = SIG_DFL, .sa_flags = SA_NOCLDSTOP };
        sigaction(SIGCHLD, &quiet, NULL);
        kill(pid, SIGTSTP);
        result("waitid-stop", waitid(P_PID, pid, &info, WSTOPPED));
        result("code", info.si_code);
        result("status", info.si_status);
        kill(pid, SIGCONT);
        result("waitid-cont", waitid(P_ALL, 0, &info, WCONTINUED));
        result("code", info.si_code);
        sigpending(&pending);
        result("sigchld-quiet", sigismember(&pending, SIGCHLD));
        if (write(gate[1], "x", 1) != 1) return 82;
        result("exited", waitpid(pid, &status, 0) == pid);
        result("code", WEXITSTATUS(status));
        /* SA_NOCLDSTOP leaves the SIGCHLD of an exit, and of a kill. */
        result("sigchld-exit", sigwaitinfo(&chld, &info));
        result("sigchld-exit-code", info.si_code);
        result("sigchld-exit-status", info.si_status);
        result("sigchld-exit-pid", info.si_pid == pid);
        pid = child();
        if (pid == 0) {
            for (;;) pause();
        }
        kill(pid, SIGKILL);
        result("killed", waitpid(pid, &status, 0) == pid);
        result("sigchld-kill", sigwaitinfo(&chld, &info));
        result("sigchld-kill-code", info.si_code);
        result("sigchld-kill-status", info.si_status);
        result("sigchld-kill-pid", info.si_pid == pid);
        return 0;
    }
    if (!strcmp(mode, "timerfd")) {
        /* Values that depend on timing are printed only as conditions. */
        errno = 0;
        result("bad-clock", timerfd_create(99, 0));
        result("errno", errno);
        errno = 0;
        result("bad-flags", timerfd_create(CLOCK_MONOTONIC, 1));
        result("errno", errno);
        int fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
        result("fd", fd >= 0);
        result("getfl", fcntl(fd, F_GETFL));
        result("getfd", fcntl(fd, F_GETFD));
        struct itimerspec value, old;
        memset(&value, 0x55, sizeof value);
        result("gettime", timerfd_gettime(fd, &value));
        result("disarmed", value.it_value.tv_sec == 0 && value.it_value.tv_nsec == 0
                               && value.it_interval.tv_sec == 0 && value.it_interval.tv_nsec == 0);
        uint64_t ticks = 0;
        errno = 0;
        result("empty", read(fd, &ticks, 8));
        result("errno", errno);
        /* Errors, in Linux's order: the value, the flags and times, the fd. */
        struct itimerspec ten = {{0, 0}, {10, 0}};
        errno = 0;
        result("null", timerfd_settime(fd, 0, NULL, NULL));
        result("errno", errno);
        errno = 0;
        result("bad-settime-flags", timerfd_settime(fd, 4, &ten, NULL));
        result("errno", errno);
        struct itimerspec bad = {{0, 0}, {0, 1000000000}};
        errno = 0;
        result("bad-nsec", timerfd_settime(fd, 0, &bad, NULL));
        result("errno", errno);
        errno = 0;
        result("bad-fd", timerfd_settime(99, 0, &bad, NULL));
        result("errno", errno);
        errno = 0;
        result("bad-fd-valid", timerfd_settime(99, 0, &ten, NULL));
        result("errno", errno);
        errno = 0;
        result("not-timer", timerfd_settime(1, 0, &ten, NULL));
        result("errno", errno);
        errno = 0;
        result("not-timer-get", timerfd_gettime(1, &value));
        result("errno", errno);
        /* Ten seconds out: armed, not yet readable. */
        result("arm", timerfd_settime(fd, 0, &ten, NULL));
        timerfd_gettime(fd, &value);
        result("remaining", value.it_value.tv_sec <= 10 && (value.it_value.tv_sec > 0 || value.it_value.tv_nsec > 0));
        errno = 0;
        result("not-yet", read(fd, &ticks, 8));
        result("errno", errno);
        errno = 0;
        result("short", read(fd, &ticks, 7));
        result("errno", errno);
        errno = 0;
        result("write", write(fd, &ticks, 8));
        result("errno", errno);
        /* An absolute time already past fires at once; rearming clears it. */
        struct itimerspec past = {{0, 0}, {0, 1}};
        result("past", timerfd_settime(fd, TFD_TIMER_ABSTIME, &past, &old));
        result("old-interval", old.it_interval.tv_sec == 0 && old.it_interval.tv_nsec == 0);
        result("old-value", old.it_value.tv_sec <= 10);
        struct pollfd pfd = {fd, POLLIN, 0};
        result("poll", poll(&pfd, 1, -1));
        result("revents", pfd.revents);
        result("expired", timerfd_gettime(fd, &value) == 0 && value.it_value.tv_sec == 0 && value.it_value.tv_nsec == 0);
        timerfd_settime(fd, TFD_TIMER_ABSTIME, &past, NULL);
        timerfd_settime(fd, 0, &ten, NULL);
        errno = 0;
        result("cleared", read(fd, &ticks, 8));
        result("errno", errno);
        /* Linux's hrtimer fires a past time just after settime returns, so
           wait for it before a nonblocking read. */
        timerfd_settime(fd, TFD_TIMER_ABSTIME, &past, NULL);
        poll(&pfd, 1, -1);
        result("read", read(fd, &ticks, 8));
        result("ticks", ticks);
        errno = 0;
        result("drained", read(fd, &ticks, 8));
        result("errno", errno);
        close(fd);
        /* A blocking read waits for a 1 ms one-shot timer. */
        fd = timerfd_create(CLOCK_MONOTONIC, 0);
        struct itimerspec ms = {{0, 0}, {0, 1000000}};
        timerfd_settime(fd, 0, &ms, NULL);
        result("blocking", read(fd, &ticks, 8));
        result("ticks", ticks);
        /* A periodic timer counts every expiry; epoll sees it. */
        struct itimerspec every = {{0, 1000000}, {0, 1000000}};
        timerfd_settime(fd, 0, &every, NULL);
        int ep = epoll_create1(0);
        struct epoll_event ev = {EPOLLIN, {.u64 = 7}}, out;
        epoll_ctl(ep, EPOLL_CTL_ADD, fd, &ev);
        result("epoll", epoll_wait(ep, &out, 1, -1));
        result("epoll-events", out.events);
        result("epoll-data", out.data.u64);
        result("periodic", read(fd, &ticks, 8));
        result("at-least-one", ticks >= 1);
        struct itimerspec off = {{0, 0}, {0, 0}};
        result("disarm", timerfd_settime(fd, 0, &off, &old));
        result("old-period", old.it_interval.tv_sec == 0 && old.it_interval.tv_nsec == 1000000);
        timerfd_gettime(fd, &value);
        result("off", value.it_value.tv_sec == 0 && value.it_value.tv_nsec == 0 && value.it_interval.tv_nsec == 0);
        /* A zero value disarms, but the interval is kept and reported. */
        struct itimerspec idle = {{0, 5000000}, {0, 0}};
        timerfd_settime(fd, 0, &idle, NULL);
        timerfd_gettime(fd, &value);
        result("idle-interval", value.it_interval.tv_nsec);
        result("idle-value", value.it_value.tv_sec == 0 && value.it_value.tv_nsec == 0);
        timerfd_settime(fd, 0, &off, &old);
        result("idle-old", old.it_interval.tv_nsec);
        /* Any non-negative time is valid; Linux saturates a huge one. */
        struct itimerspec huge = {{LONG_MAX, 0}, {LONG_MAX, 0}};
        result("huge", timerfd_settime(fd, 0, &huge, NULL));
        timerfd_gettime(fd, &value);
        result("huge-interval", value.it_interval.tv_sec);
        result("huge-armed", value.it_value.tv_sec > 0);
        timerfd_settime(fd, 0, &off, NULL);
        close(ep);
        close(fd);
        /* CLOCK_REALTIME, with CANCEL_ON_SET accepted. */
        fd = timerfd_create(CLOCK_REALTIME, TFD_NONBLOCK);
        result("realtime", timerfd_settime(fd, TFD_TIMER_ABSTIME | TFD_TIMER_CANCEL_ON_SET, &past, NULL));
        pfd.fd = fd;
        result("realtime-poll", poll(&pfd, 1, -1));
        result("realtime-read", read(fd, &ticks, 8));
        result("ticks", ticks);
        close(fd);
        return 0;
    }
    if (!strcmp(mode, "clone3")) {
        signal(SIGUSR1, interrupted);
        signal(SIGUSR2, SIG_IGN);
        int parent_tid = 0;
        struct clone3_args args = {0x100000, 0, 0, (unsigned long)&parent_tid, SIGCHLD, 0, 0, 0};
        long pid = clone3(&args, sizeof args);
        if (pid == 0) _exit(7);
        result("exit", reaped(pid));
        result("parent-tid", parent_tid == pid);
        /* CLONE_CLEAR_SIGHAND: handlers go back to the default, ignored stays ignored. */
        struct clone3_args clear = {1ULL << 32, 0, 0, 0, SIGCHLD, 0, 0, 0};
        pid = clone3(&clear, sizeof clear);
        if (pid == 0) {
            struct sigaction one, two;
            sigaction(SIGUSR1, NULL, &one);
            sigaction(SIGUSR2, NULL, &two);
            _exit((one.sa_handler == SIG_DFL) | (two.sa_handler == SIG_IGN) << 1);
        }
        result("cleared", reaped(pid));
        struct sigaction kept;
        sigaction(SIGUSR1, NULL, &kept);
        result("parent-kept", kept.sa_handler == interrupted);
        /* A larger struct is fine while the part Linux does not know is zero. */
        unsigned long long larger[16] = {0};
        larger[4] = SIGCHLD;
        pid = clone3(larger, sizeof larger);
        if (pid == 0) _exit(9);
        result("larger", reaped(pid));
        larger[12] = 1;
        errno = 0;
        result("larger-nonzero", clone3(larger, sizeof larger));
        result("errno", errno);
        errno = 0;
        result("too-small", clone3(&args, 63));
        result("errno", errno);
        errno = 0;
        result("too-large", clone3(&args, 4097));
        result("errno", errno);
        errno = 0;
        result("fault", clone3((void *)1, 64));
        result("errno", errno);
        result("exit-signal-bits", clone3_error((struct clone3_args){0, 0, 0, 0, 0x100, 0, 0, 0}));
        result("detached", clone3_error((struct clone3_args){0x400000, 0, 0, 0, SIGCHLD, 0, 0, 0}));
        result("csignal-flag", clone3_error((struct clone3_args){SIGCHLD, 0, 0, 0, 0, 0, 0, 0}));
        result("sighand-clear", clone3_error((struct clone3_args){(1ULL << 32) | 0xd00, 0, 0, 0, 0, 0, 0, 0}));
        result("thread-signal", clone3_error((struct clone3_args){0x10900, 0, 0, 0, SIGCHLD, 0, 0, 0}));
        result("size-no-stack", clone3_error((struct clone3_args){0, 0, 0, 0, SIGCHLD, 0, 4096, 0}));
        result("stack-no-size", clone3_error((struct clone3_args){0, 0, 0, 0, SIGCHLD, 4096, 0, 0}));
        result("bad-signal", clone3_error((struct clone3_args){0, 0, 0, 0, 65, 0, 0, 0}));
        return 0;
    }
    if (!strcmp(mode, "credentials")) {
        /* The set*id calls as root and after leaving it (the native side
           runs as root): which IDs each may set, the saved ID following the
           effective one, the capabilities lost on leaving root (kept by
           PR_SET_KEEPCAPS), dropped and raised with the effective ID and,
           for the filesystem ones, the filesystem ID; supplementary groups;
           a change of an effective or filesystem ID making the process
           undumpable and clearing its parent-death signal; raw calls
           changing only the calling thread; and exec taking the effective
           IDs as saved ones, recomputing the capabilities, clearing
           PR_SET_KEEPCAPS, giving AT_SECURE and resetting dumpability. */
        static const char *const steps[] = {"root", "drop", "keepcaps", "effective", "fsuid",
                                            "gids", "pdeath", "thread", "exec", "exec-root"};
        for (size_t step = 0; step < sizeof steps / sizeof *steps; step++) {
            fflush(stdout);
            pid_t pid = child();
            if (pid == 0) {
                const char *name = steps[step];
                if (syscall(SYS_setgroups, 0, NULL)) _exit(70);
                if (!strcmp(name, "root")) {
                    unsigned list[2] = {5, 3}, got[4] = {0}, bad = (unsigned)-1;
                    outcome("setgroups", syscall(SYS_setgroups, 2, list));
                    long n = syscall(SYS_getgroups, 4, got);
                    printf("getgroups=%ld list=%u,%u\n", n, got[0], got[1]);
                    outcome("getgroups-small", syscall(SYS_getgroups, 1, got));
                    outcome("getgroups-count", syscall(SYS_getgroups, 0, NULL));
                    outcome("getgroups-negative", syscall(SYS_getgroups, -1, got));
                    outcome("setgroups-invalid", syscall(SYS_setgroups, 1, &bad));
                    outcome("setgroups-huge", syscall(SYS_setgroups, 65537, list));
                    credentials_line(name);
                } else if (!strcmp(name, "drop")) {
                    outcome("setresuid", syscall(SYS_setresuid, 1000, 1001, 1002));
                    credentials_line(name);
                    outcome("setuid-root", syscall(SYS_setuid, 0));
                    outcome("setuid-saved", syscall(SYS_setuid, 1002));
                    credentials_line("drop-saved");
                    outcome("setresuid-other", syscall(SYS_setresuid, 1003, -1, -1));
                    outcome("setuid-invalid", syscall(SYS_setuid, -1));
                    outcome("setgroups", syscall(SYS_setgroups, 0, NULL));
                    outcome("setgid", syscall(SYS_setgid, 5));
                    outcome("setreuid-real", syscall(SYS_setreuid, 1002, -1));
                    credentials_line("drop-real");
                } else if (!strcmp(name, "keepcaps")) {
                    outcome("set-keepcaps", prctl(PR_SET_KEEPCAPS, 1));
                    outcome("get-keepcaps", prctl(PR_GET_KEEPCAPS));
                    outcome("set-keepcaps-two", prctl(PR_SET_KEEPCAPS, 2));
                    outcome("setresuid", syscall(SYS_setresuid, 1000, 1000, 1000));
                    credentials_line(name);
                    outcome("setuid-root", syscall(SYS_setuid, 0));
                } else if (!strcmp(name, "effective")) {
                    outcome("seteuid", syscall(SYS_setresuid, -1, 1000, -1));
                    credentials_line(name);
                    outcome("setreuid-back", syscall(SYS_setreuid, -1, 0));
                    credentials_line("effective-back");
                    outcome("setreuid-other", syscall(SYS_setreuid, -1, 5));
                    credentials_line("effective-other");
                } else if (!strcmp(name, "fsuid")) {
                    printf("setfsuid=%ld\n", syscall(SYS_setfsuid, 1000));
                    credentials_line(name);
                    printf("setfsuid-back=%ld\n", syscall(SYS_setfsuid, 0));
                    credentials_line("fsuid-back");
                    /* setresuid changing nothing leaves the filesystem ID,
                       which it resets to the effective one otherwise. */
                    syscall(SYS_setfsuid, 1000);
                    outcome("setresuid-same", syscall(SYS_setresuid, -1, -1, -1));
                    credentials_line("fsuid-same");
                    outcome("setresuid-euid", syscall(SYS_setresuid, -1, 0, -1));
                    credentials_line("fsuid-reset");
                    outcome("setgroups-none", syscall(SYS_setgroups, 0, (void *)1));
                    outcome("setresuid", syscall(SYS_setresuid, 1, 1, 1));
                    printf("setfsuid-other=%ld\n", syscall(SYS_setfsuid, 2));
                    printf("setfsgid=%ld\n", syscall(SYS_setfsgid, 9));
                    credentials_line("fsuid-user");
                } else if (!strcmp(name, "gids")) {
                    outcome("setresgid", syscall(SYS_setresgid, 100, 101, 102));
                    outcome("setregid", syscall(SYS_setregid, -1, 103));
                    credentials_line(name);
                    outcome("setresuid", syscall(SYS_setresuid, 1, 1, 1));
                    outcome("setgid-saved", syscall(SYS_setgid, 103));
                    outcome("setgid-other", syscall(SYS_setgid, 5));
                    outcome("setresgid-other", syscall(SYS_setresgid, -1, -1, 5));
                    credentials_line("gids-user");
                } else if (!strcmp(name, "pdeath")) {
                    int signal = 0;
                    prctl(PR_SET_PDEATHSIG, SIGUSR1);
                    outcome("setresuid-same", syscall(SYS_setresuid, -1, -1, -1));
                    prctl(PR_GET_PDEATHSIG, &signal);
                    printf("pdeath-same=%d\n", signal);
                    credentials_line(name);
                    outcome("seteuid", syscall(SYS_setresuid, -1, 1000, -1));
                    prctl(PR_GET_PDEATHSIG, &signal);
                    printf("pdeath-changed=%d\n", signal);
                    credentials_line("pdeath-changed");
                } else if (!strcmp(name, "thread")) {
                    pthread_t t;
                    if (pthread_create(&t, NULL, credentials_thread, NULL) || pthread_join(t, NULL)) _exit(71);
                    printf("thread-uid=%u own-uid=%ld\n", thread_uid, syscall(SYS_getuid));
                } else {
                    if (!strcmp(name, "exec")) {
                        prctl(PR_SET_KEEPCAPS, 1);
                        prctl(PR_SET_PDEATHSIG, SIGUSR1);
                        if (syscall(SYS_setresgid, 100, 101, 102) || syscall(SYS_setresuid, 1000, 1001, 1002))
                            _exit(72);
                    } else {
                        prctl(PR_SET_DUMPABLE, 0);
                        prctl(PR_SET_PDEATHSIG, SIGUSR1);
                    }
                    char *args[] = {"process", "credentials-exec", (char *)self, (char *)name, NULL};
                    char *env[] = {NULL};
                    execve(self, args, env);
                    _exit(73);
                }
                fflush(stdout);
                _exit(0);
            }
            int status = 0;
            waitpid(pid, &status, 0);
            printf("%s: status=%d\n", steps[step], status);
        }
        return 0;
    }
    if (!strcmp(mode, "credentials-exec")) {
        int signal = -1;
        prctl(PR_GET_PDEATHSIG, &signal);
        printf("auxv: uid=%lu euid=%lu gid=%lu egid=%lu secure=%lu keepcaps=%d pdeath=%d\n",
               getauxval(AT_UID), getauxval(AT_EUID), getauxval(AT_GID), getauxval(AT_EGID),
               getauxval(AT_SECURE), prctl(PR_GET_KEEPCAPS), signal);
        credentials_line(argc > 3 ? argv[3] : "exec");
        return 0;
    }
    if (!strcmp(mode, "permissions")) {
        /* Linux's permission checks on files for a thread that is not root
           (the native side runs as root): searching each directory of a
           path from where the walk starts, reading, writing and executing
           by the owner's, group's (also a supplementary one's) or others'
           bits, creating and removing names in a directory (the sticky bit
           keeping others' files), the owner of what the thread makes,
           chmod, chown, utimensat and truncate by the owner, access by the
           real IDs, and exec. */
        static const char hello[] = "hello\n";
        remove_tree(PERMISSIONS);
        if (mkdir(PERMISSIONS, 0755) || chmod(PERMISSIONS, 0755)) return 70;
        int image = open(self, O_RDONLY);
        struct stat image_stat;
        if (image < 0 || fstat(image, &image_stat)) return 71;
        char *program = malloc(image_stat.st_size);
        if (!program || read(image, program, image_stat.st_size) != image_stat.st_size) return 72;
        close(image);
        if (permissions_file("secret", 0600, 0, 0, hello, 6) ||
            permissions_file("public", 0644, 0, 0, hello, 6) ||
            permissions_file("group", 0640, 0, 2000, hello, 6) ||
            permissions_file("supplementary", 0640, 0, 4000, hello, 6) ||
            permissions_file("owned", 0644, 1000, 2000, hello, 6) ||
            permissions_file("noexec", 0644, 0, 0, hello, 6) ||
            permissions_file("rootonly", 0700, 0, 0, hello, 6) ||
            permissions_file("execonly", 0711, 0, 0, program, image_stat.st_size) ||
            permissions_directory("closed", 0700, 0, 0) ||
            permissions_file("closed/inside", 0644, 0, 0, hello, 6) ||
            permissions_directory("closed/open", 0755, 0, 0) ||
            permissions_file("closed/open/f", 0644, 0, 0, hello, 6) ||
            permissions_file("closed/open/prog", 0755, 0, 0, program, image_stat.st_size) ||
            permissions_directory("searchonly", 0711, 0, 0) ||
            permissions_file("searchonly/f", 0644, 0, 0, hello, 6) ||
            permissions_directory("open", 0777, 0, 0) ||
            permissions_file("open/rootfile", 0666, 0, 0, hello, 6) ||
            permissions_file("open/foreign", 0640, 1000, 3000, hello, 6) ||
            permissions_file("open/foreign-sgid", 02640, 1000, 3000, hello, 6) ||
            permissions_directory("open/sub", 0755, 0, 0) ||
            permissions_directory("sticky", 01777, 0, 0) ||
            permissions_file("sticky/rootfile", 0666, 0, 0, hello, 6) ||
            permissions_file("sticky/mine", 0644, 1000, 2000, hello, 6) ||
            symlink("closed/inside", PERMISSIONS "/link-closed"))
            return 73;
        free(program);
        int below_closed = open(PERMISSIONS "/closed/open", O_RDONLY|O_DIRECTORY);
        int closed = open(PERMISSIONS "/closed", O_RDONLY|O_DIRECTORY);
        if (below_closed < 0 || closed < 0) return 74;
        fflush(stdout);
        pid_t pid = child();
        if (pid == 0) {
            gid_t groups[] = {4000};
            if (chdir(PERMISSIONS "/closed/open") || syscall(SYS_setgroups, 1, groups) ||
                syscall(SYS_setresgid, 2000, 2000, 2000) || syscall(SYS_setresuid, 1000, 1000, 1000))
                _exit(75);
            /* Reading and writing by the bits that apply. */
            permitted("open-secret", open(PERMISSIONS "/secret", O_RDONLY));
            permitted("open-public-read", open(PERMISSIONS "/public", O_RDONLY));
            permitted("open-public-write", open(PERMISSIONS "/public", O_WRONLY));
            permitted("open-public-truncate", open(PERMISSIONS "/public", O_RDONLY|O_TRUNC));
            permitted("open-owned", open(PERMISSIONS "/owned", O_RDWR));
            permitted("open-group-read", open(PERMISSIONS "/group", O_RDONLY));
            permitted("open-group-write", open(PERMISSIONS "/group", O_WRONLY));
            permitted("open-supplementary", open(PERMISSIONS "/supplementary", O_RDONLY));
            /* Searching the directories on the way. */
            struct stat st;
            permitted("stat-closed-inside", stat(PERMISSIONS "/closed/inside", &st));
            permitted("open-closed", open(PERMISSIONS "/closed", O_RDONLY|O_DIRECTORY));
            permitted("stat-link-closed", stat(PERMISSIONS "/link-closed", &st));
            permitted("lstat-link-closed", lstat(PERMISSIONS "/link-closed", &st));
            permitted("stat-searchonly", stat(PERMISSIONS "/searchonly/f", &st));
            permitted("open-searchonly", open(PERMISSIONS "/searchonly", O_RDONLY|O_DIRECTORY));
            permitted("openat-below-closed", openat(below_closed, "f", O_RDONLY));
            permitted("open-cwd-below-closed", open("f", O_RDONLY));
            /* So does a program run from there. */
            fflush(stdout);
            pid_t relative = child();
            if (relative == 0) {
                char *relative_args[] = {"process", "permissions-exec", (char *)self, "exec-below-closed", NULL};
                char *no_env[] = {NULL};
                execve("./prog", relative_args, no_env);
                printf("exec-below-closed: %s\n", strerror(errno));
                fflush(stdout);
                _exit(78);
            }
            int relative_status = 0;
            waitpid(relative, &relative_status, 0);
            permitted("stat-dotdot", stat("..", &st));
            permitted("stat-dotdot-inside", stat("../inside", &st));
            permitted("access-closed-inside", access(PERMISSIONS "/closed/inside", F_OK));
            /* Names in a directory the thread may not write. */
            permitted("create-in-base", open(PERMISSIONS "/new", O_CREAT|O_WRONLY, 0644));
            permitted("create-existing", open(PERMISSIONS "/public", O_CREAT|O_RDONLY, 0644));
            permitted("create-exclusive", open(PERMISSIONS "/public", O_CREAT|O_EXCL|O_RDONLY, 0644));
            permitted("mkdir-in-base", mkdir(PERMISSIONS "/d", 0755));
            permitted("mkdir-existing", mkdir(PERMISSIONS "/closed", 0755));
            permitted("unlink-public", unlink(PERMISSIONS "/public"));
            permitted("unlink-missing", unlink(PERMISSIONS "/missing"));
            permitted("rmdir-closed", rmdir(PERMISSIONS "/closed"));
            permitted("rename-public", rename(PERMISSIONS "/public", PERMISSIONS "/open/public"));
            permitted("rename-same", rename(PERMISSIONS "/public", PERMISSIONS "/public"));
            /* Its own file, which fs.protected_hardlinks lets it link. */
            permitted("link-owned", link(PERMISSIONS "/owned", PERMISSIONS "/link"));
            permitted("symlink-in-base", symlink("public", PERMISSIONS "/symlink"));
            /* What the thread makes is its own. */
            int mine = open(PERMISSIONS "/open/mine", O_CREAT|O_RDWR, 0640);
            permitted("create-mine", mine);
            permissions_owner("mine", PERMISSIONS "/open/mine");
            permitted("mkdir-mine", mkdir(PERMISSIONS "/open/mydir", 0750));
            permissions_owner("mydir", PERMISSIONS "/open/mydir");
            permitted("symlink-mine", symlink("mine", PERMISSIONS "/open/mylink"));
            permissions_owner("mylink", PERMISSIONS "/open/mylink");
            /* chmod and chown by the owner. */
            int public = open(PERMISSIONS "/public", O_RDONLY);
            permitted("chmod-public", chmod(PERMISSIONS "/public", 0600));
            permitted("fchmod-public", fchmod(public, 0600));
            permitted("chmod-mine", chmod(PERMISSIONS "/open/mine", 02640));
            permissions_owner("chmod-mine", PERMISSIONS "/open/mine");
            permitted("chmod-foreign", chmod(PERMISSIONS "/open/foreign", 02750));
            permissions_owner("chmod-foreign", PERMISSIONS "/open/foreign");
            permitted("chown-public-unchanged", chown(PERMISSIONS "/public", -1, -1));
            permitted("chown-mine-root", chown(PERMISSIONS "/open/mine", 0, -1));
            permitted("chown-mine-self", chown(PERMISSIONS "/open/mine", 1000, -1));
            permitted("chown-mine-other-group", chown(PERMISSIONS "/open/mine", -1, 3000));
            permitted("chown-mine-supplementary", chown(PERMISSIONS "/open/mine", -1, 4000));
            permissions_owner("chown-mine", PERMISSIONS "/open/mine");
            permitted("fchown-mine", fchown(mine, -1, 2000));
            permitted("chown-foreign-sgid", chown(PERMISSIONS "/open/foreign-sgid", -1, 2000));
            permissions_owner("chown-foreign-sgid", PERMISSIONS "/open/foreign-sgid");
            /* utimensat: setting times by the owner, touching them by a
               writer. */
            struct timespec set[2] = {{1, 0}, {2, 0}};
            struct timespec now_now[2] = {{0, UTIME_NOW}, {0, UTIME_NOW}};
            struct timespec now_omit[2] = {{0, UTIME_NOW}, {0, UTIME_OMIT}};
            permitted("touch-public", utimensat(AT_FDCWD, PERMISSIONS "/public", NULL, 0));
            permitted("set-public", utimensat(AT_FDCWD, PERMISSIONS "/public", set, 0));
            permitted("futimens-public", futimens(public, NULL));
            permitted("touch-rootfile", utimensat(AT_FDCWD, PERMISSIONS "/open/rootfile", NULL, 0));
            permitted("now-rootfile", utimensat(AT_FDCWD, PERMISSIONS "/open/rootfile", now_now, 0));
            permitted("now-omit-rootfile", utimensat(AT_FDCWD, PERMISSIONS "/open/rootfile", now_omit, 0));
            permitted("set-rootfile", utimensat(AT_FDCWD, PERMISSIONS "/open/rootfile", set, 0));
            permitted("set-mine", utimensat(AT_FDCWD, PERMISSIONS "/open/mine", set, 0));
            /* truncate needs write permission. */
            permitted("truncate-public", truncate(PERMISSIONS "/public", 0));
            permitted("truncate-rootfile", truncate(PERMISSIONS "/open/rootfile", 0));
            permitted("truncate-directory", truncate(PERMISSIONS "/open", 0));
            /* The sticky bit keeps others' files, and moving a directory
               to another needs writing it. */
            permitted("unlink-sticky-rootfile", unlink(PERMISSIONS "/sticky/rootfile"));
            permitted("rename-sticky-rootfile", rename(PERMISSIONS "/sticky/rootfile", PERMISSIONS "/sticky/moved"));
            permitted("unlink-sticky-mine", unlink(PERMISSIONS "/sticky/mine"));
            permitted("rename-sub", rename(PERMISSIONS "/open/sub", PERMISSIONS "/sticky/sub"));
            permitted("rename-mydir", rename(PERMISSIONS "/open/mydir", PERMISSIONS "/sticky/mydir"));
            /* access by the real IDs. */
            permitted("access-secret", access(PERMISSIONS "/secret", R_OK));
            permitted("access-public-read", access(PERMISSIONS "/public", R_OK));
            permitted("access-public-write", access(PERMISSIONS "/public", W_OK));
            permitted("access-noexec", access(PERMISSIONS "/noexec", X_OK));
            /* chdir needs searching. */
            permitted("chdir-closed", chdir(PERMISSIONS "/closed"));
            permitted("fchdir-closed", fchdir(closed));
            permitted("chdir-searchonly", chdir(PERMISSIONS "/searchonly"));
            /* exec needs executing a regular file; one the thread may not
               read runs undumpable. */
            char *args[] = {"process", "permissions-exec", (char *)self, NULL};
            char *env[] = {NULL};
            permitted("exec-noexec", execve(PERMISSIONS "/noexec", args, env));
            permitted("exec-rootonly", execve(PERMISSIONS "/rootonly", args, env));
            permitted("exec-directory", execve(PERMISSIONS "/open", args, env));
            fflush(stdout);
            pid_t exec_pid = child();
            if (exec_pid == 0) {
                execve(PERMISSIONS "/execonly", args, env);
                _exit(76);
            }
            int status = 0;
            waitpid(exec_pid, &status, 0);
            printf("exec-only: status=%d\n", status);
            fflush(stdout);
            _exit(0);
        }
        int status = 0;
        waitpid(pid, &status, 0);
        printf("unprivileged: status=%d\n", status);
        /* access takes the real IDs, AT_EACCESS the effective ones. */
        for (int real = 0; real < 2; real++) {
            fflush(stdout);
            pid = child();
            if (pid == 0) {
                if (real ? syscall(SYS_setresuid, 1000, 0, 0) : syscall(SYS_setresuid, 0, 1000, 0)) _exit(77);
                const char *who = real ? "real-user" : "effective-user";
                char name[64];
                snprintf(name, sizeof name, "%s-access", who);
                permitted(name, access(PERMISSIONS "/secret", R_OK));
                snprintf(name, sizeof name, "%s-eaccess", who);
                permitted(name, syscall(SYS_faccessat2, AT_FDCWD, PERMISSIONS "/secret", R_OK, AT_EACCESS));
                snprintf(name, sizeof name, "%s-open", who);
                permitted(name, open(PERMISSIONS "/secret", O_RDONLY));
                fflush(stdout);
                _exit(0);
            }
            waitpid(pid, &status, 0);
            printf("access-ids: status=%d\n", status);
        }
        remove_tree(PERMISSIONS);
        return 0;
    }
    if (!strcmp(mode, "permissions-exec")) {
        int dumpable = prctl(PR_GET_DUMPABLE);
        printf("%s: uid=%u dumpable=%s\n", argc > 3 ? argv[3] : "exec-only", getuid(),
               dumpable == 1 ? "1" : dumpable == suid_dumpable() ? "suid" : "other");
        return 0;
    }
    if (!strcmp(mode, "setuid")) {
        /* exec of set-user-ID and set-group-ID programs (the native side
           runs as root): the owner's user ID, or the group (when the group
           may execute the program), becoming the effective, saved and
           filesystem one; root's capabilities by a root program; AT_SECURE;
           dumpability decided from the IDs before exec and lost when exec
           changes an effective or filesystem ID, which also clears the
           parent-death signal; a secure exec lowering the RLIMIT_STACK soft
           limit to 8 MiB; and PR_SET_NO_NEW_PRIVS ignoring the bits, and
           taking the real IDs as effective when the exec would still change
           the effective ones (an effective group the thread is not in). */
        static const struct {
            const char *name, *program;
            unsigned uid, euid, gid, egid;
            int fsuid, fsgid, no_new_privs;
        } steps[] = {
            {"user-suid", "suid-user", 1000, 1000, 2000, 2000, -1, -1, 0},
            {"user-sgid", "sgid", 1000, 1000, 2000, 2000, -1, -1, 0},
            {"user-sgid-locking", "sgid-locking", 1000, 1000, 2000, 2000, -1, -1, 0},
            {"user-both", "both", 1000, 1000, 2000, 2000, -1, -1, 0},
            {"user-suid-root", "suid-root", 1000, 1000, 2000, 2000, -1, -1, 0},
            {"user-suid-self", "suid-self", 1000, 1000, 2000, 2000, -1, -1, 0},
            {"user-unreadable", "unreadable", 1000, 1000, 2000, 2000, -1, -1, 0},
            {"user-plain", "plain", 1000, 1000, 2000, 2000, -1, -1, 0},
            {"root-suid", "suid-user", 0, 0, 0, 0, -1, -1, 0},
            {"root-plain", "plain", 0, 0, 0, 0, -1, -1, 0},
            {"back-to-real", "suid-self", 1000, 1001, 2000, 2000, -1, -1, 0},
            {"fsuid-plain", "plain", 0, 0, 0, 0, 1000, -1, 0},
            {"nnp-both", "both", 1000, 1000, 2000, 2000, -1, -1, 1},
            {"nnp-effective", "plain", 1000, 1001, 2000, 2000, -1, -1, 1},
            {"nnp-root-effective", "plain", 1000, 0, 2000, 2000, -1, -1, 1},
            {"nnp-fsgid", "plain", 1000, 1001, 2000, 2000, -1, 3000, 1},
        };
        const char *dir = "/tmp/paludarium-setuid";
        remove_tree(dir);
        if (mkdir(dir, 0755) || chmod(dir, 0755)) return 70;
        int image = open(self, O_RDONLY);
        struct stat image_stat;
        if (image < 0 || fstat(image, &image_stat)) return 71;
        char *program = malloc(image_stat.st_size);
        if (!program || read(image, program, image_stat.st_size) != image_stat.st_size) return 72;
        close(image);
        static const struct {
            const char *name;
            mode_t mode;
            uid_t uid;
            gid_t gid;
        } files[] = {
            {"suid-user", 04755, 1001, 0}, {"suid-root", 04755, 0, 0},
            {"suid-self", 04755, 1000, 0}, {"sgid", 02755, 0, 3000},
            {"sgid-locking", 02745, 0, 3000}, {"both", 06755, 1001, 3000},
            {"unreadable", 04711, 1001, 0}, {"plain", 0755, 0, 0},
        };
        for (size_t i = 0; i < sizeof files / sizeof *files; i++) {
            char path[256];
            snprintf(path, sizeof path, "%s/%s", dir, files[i].name);
            int fd = open(path, O_CREAT|O_WRONLY|O_TRUNC, 0600);
            if (fd < 0 || write(fd, program, image_stat.st_size) != image_stat.st_size || close(fd) ||
                chown(path, files[i].uid, files[i].gid) || chmod(path, files[i].mode))
                return 73;
        }
        free(program);
        for (size_t step = 0; step < sizeof steps / sizeof *steps; step++) {
            fflush(stdout);
            pid_t pid = child();
            if (pid == 0) {
                struct rlimit stack = {RLIM_INFINITY, RLIM_INFINITY};
                if (syscall(SYS_setgroups, 0, NULL) || setrlimit(RLIMIT_STACK, &stack) ||
                    syscall(SYS_setresgid, steps[step].gid, steps[step].egid, steps[step].egid))
                    _exit(74);
                if (steps[step].fsgid >= 0) syscall(SYS_setfsgid, steps[step].fsgid);
                if (syscall(SYS_setresuid, steps[step].uid, steps[step].euid, steps[step].euid)) _exit(74);
                if (steps[step].fsuid >= 0) syscall(SYS_setfsuid, steps[step].fsuid);
                if (steps[step].no_new_privs && prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) _exit(75);
                prctl(PR_SET_PDEATHSIG, SIGUSR1);
                char path[256];
                snprintf(path, sizeof path, "%s/%s", dir, steps[step].program);
                char *args[] = {"process", "setuid-exec", path, (char *)steps[step].name, NULL};
                char *env[] = {NULL};
                execve(path, args, env);
                printf("%s: %s\n", steps[step].name, strerror(errno));
                fflush(stdout);
                _exit(76);
            }
            int status = 0;
            waitpid(pid, &status, 0);
            printf("%s: status=%d\n", steps[step].name, status);
        }
        remove_tree(dir);
        return 0;
    }
    if (!strcmp(mode, "setuid-exec")) {
        int signal = -1;
        prctl(PR_GET_PDEATHSIG, &signal);
        struct rlimit stack;
        getrlimit(RLIMIT_STACK, &stack);
        printf("auxv: uid=%lu euid=%lu gid=%lu egid=%lu secure=%lu pdeath=%d stack=%s\n",
               getauxval(AT_UID), getauxval(AT_EUID), getauxval(AT_GID), getauxval(AT_EGID),
               getauxval(AT_SECURE), signal,
               stack.rlim_cur == RLIM_INFINITY ? "unlimited" : stack.rlim_cur == 8 << 20 ? "8M" : "other");
        credentials_line(argc > 3 ? argv[3] : "exec");
        return 0;
    }
    if (!strcmp(mode, "signal-permissions")) {
        /* Who may signal whom (the native side runs as root), as Linux's
           check_kill_permission: the sender's real or effective user ID
           against the target's real or saved one, or CAP_KILL, within a
           process always, and SIGCONT within a session; an invalid signal
           and a missing process before that; groups and -1; the queued and
           pidfd calls; a zombie; each thread's own credentials; and si_uid. */
        prctl(PR_SET_CHILD_SUBREAPER, 1);
        pid_t other = signal_target(3000, 3000, 3000, 0);
        pid_t real = signal_target(2000, 3000, 3000, 0);
        pid_t saved = signal_target(3000, 3000, 2000, 0);
        pid_t effective = signal_target(3000, 2000, 3000, 0);
        pid_t far = signal_target(4000, 4000, 4000, 0);
        pid_t alone = signal_target(3000, 3000, 3000, 1);
        pid_t mixed_other = signal_target(3000, 3000, 3000, 1);
        pid_t mixed_real = signal_target(2000, 2000, 2000, 0);
        setpgid(mixed_real, mixed_other);
        fflush(stdout);
        pid_t zombie = child();
        if (zombie == 0) {
            if (syscall(SYS_setresuid, 3000, 3000, 3000)) _exit(70);
            _exit(0);
        }
        siginfo_t seen;
        waitid(P_PID, zombie, &seen, WEXITED|WNOWAIT);
        pid_t gone = child();
        if (gone == 0) _exit(0);
        int status = 0;
        waitpid(gone, &status, 0);
        int other_fd = syscall(SYS_pidfd_open, other, 0);
        int real_fd = syscall(SYS_pidfd_open, real, 0);
        int zombie_fd = syscall(SYS_pidfd_open, zombie, 0);
        AS_SENDER(2000, 2000, 2000, {
            permitted("uid-other", kill(other, 0));
            permitted("uid-real", kill(real, 0));
            permitted("uid-saved", kill(saved, 0));
            permitted("uid-effective", kill(effective, 0));
            permitted("uid-term-other", kill(other, SIGTERM));
            permitted("invalid-other", kill(other, 65));
            permitted("missing", kill(gone, 0));
            permitted("zombie", kill(zombie, 0));
            permitted("cont-same-session", kill(other, SIGCONT));
            permitted("group-other", kill(-alone, 0));
            permitted("group-mixed", kill(-mixed_other, 0));
            permitted("everyone", kill(-1, 0));
            siginfo_t info;
            signal_queue_info(&info);
            permitted("queue-other", syscall(SYS_rt_sigqueueinfo, other, 0, &info));
            permitted("queue-real", syscall(SYS_rt_sigqueueinfo, real, 0, &info));
            permitted("queue-thread-other", syscall(SYS_rt_tgsigqueueinfo, other, other, 0, &info));
            permitted("queue-thread-real", syscall(SYS_rt_tgsigqueueinfo, real, real, 0, &info));
            permitted("pidfd-other", syscall(SYS_pidfd_send_signal, other_fd, 0, NULL, 0));
            permitted("pidfd-real", syscall(SYS_pidfd_send_signal, real_fd, 0, NULL, 0));
            permitted("pidfd-zombie", syscall(SYS_pidfd_send_signal, zombie_fd, 0, NULL, 0));
            permitted("self", kill(getpid(), 0));
        });
        AS_SENDER(2001, 3000, 2001, {
            permitted("effective-other", kill(other, 0));
            permitted("effective-far", kill(far, 0));
        });
        AS_SENDER(2001, 2001, 3000, {
            permitted("saved-sender-other", kill(other, 0));
        });
        AS_SENDER(0, 3000, 0, {
            permitted("real-root-far", kill(far, 0));
            permitted("real-root-other", kill(other, 0));
        });
        AS_SENDER(2000, 2000, 2000, {
            if (setsid() < 0) _exit(71);
            permitted("cont-other-session", kill(other, SIGCONT));
            permitted("zero-other-session", kill(other, 0));
            permitted("cont-real-other-session", kill(real, SIGCONT));
        });
        permitted("root-far", kill(far, 0));
        /* Refused signals did nothing. */
        permitted("still-there", waitpid(other, &status, WNOHANG) == 0 ? 0 : -1);
        waitpid(zombie, &status, 0);
        pid_t targets[] = {other, real, saved, effective, far, alone, mixed_other, mixed_real};
        for (size_t i = 0; i < sizeof targets / sizeof *targets; i++) signal_kill_reap(targets[i]);
        /* Each thread has its own credentials: a thread's ID is checked
           against that thread, its process's against the leader. */
        if (pipe(signal_thread_pipe)) return 72;
        fflush(stdout);
        pid_t threaded = child();
        if (threaded == 0) {
            pthread_t t;
            if (pthread_create(&t, NULL, signal_thread_with_ids, NULL)) _exit(73);
            pid_t tid;
            if (read(signal_thread_pipe[0], &tid, sizeof tid) != sizeof tid) _exit(74);
            if (syscall(SYS_setresuid, 3000, 3000, 3000)) _exit(75);
            if (write(signal_thread_pipe[1], &tid, sizeof tid) != sizeof tid) _exit(76);
            for (;;) pause();
        }
        pid_t thread_id;
        if (read(signal_thread_pipe[0], &thread_id, sizeof thread_id) != sizeof thread_id) return 77;
        AS_SENDER(2000, 2000, 2000, {
            permitted("thread-id", kill(thread_id, 0));
            permitted("thread-leader", kill(threaded, 0));
            siginfo_t info;
            signal_queue_info(&info);
            permitted("thread-queue", syscall(SYS_rt_tgsigqueueinfo, threaded, thread_id, 0, &info));
            permitted("thread-queue-leader", syscall(SYS_rt_tgsigqueueinfo, threaded, threaded, 0, &info));
        });
        signal_kill_reap(threaded);
        /* si_uid: the sender's real user ID, not its effective one. Each signal
           has been sent before it is looked for, since a wait's timeout does not
           wait for another process on the emulator's virtual clock. */
        sigset_t usr1;
        sigemptyset(&usr1);
        sigaddset(&usr1, SIGUSR1);
        sigaddset(&usr1, SIGCHLD);
        fflush(stdout);
        pid_t receiver = child();
        if (receiver == 0) {
            sigprocmask(SIG_BLOCK, &usr1, NULL);
            if (syscall(SYS_setresuid, 2000, 2000, 2000)) _exit(78);
            fflush(stdout);
            pid_t sender = child();
            if (sender == 0) {
                kill(getppid(), SIGUSR1);
                _exit(0);
            }
            int sender_status = 0;
            waitpid(sender, &sender_status, 0);
            signal_seen("kill-uid", SIGUSR1, sender);
            /* A signal to itself, from the raw call. */
            syscall(SYS_tgkill, getpid(), syscall(SYS_gettid), SIGUSR1);
            signal_seen("tgkill-self-uid", SIGUSR1, getpid());
            fflush(stdout);
            _exit(0);
        }
        waitpid(receiver, &status, 0);
        printf("receiver: status=%d\n", status);
        /* A thread that left root signals its leader, which has not. */
        fflush(stdout);
        pid_t sibling = child();
        if (sibling == 0) {
            sigprocmask(SIG_BLOCK, &usr1, NULL);
            signal_main_thread = syscall(SYS_gettid);
            pthread_t t;
            if (pthread_create(&t, NULL, signal_thread_tkills, NULL)) _exit(80);
            pthread_join(t, NULL);
            signal_seen("tgkill-sibling-uid", SIGUSR1, getpid());
            fflush(stdout);
            _exit(0);
        }
        waitpid(sibling, &status, 0);
        printf("sibling: status=%d\n", status);
        /* A child reports its real user ID, to SIGCHLD and to waitid. */
        sigprocmask(SIG_BLOCK, &usr1, NULL);
        fflush(stdout);
        pid_t leaving = child();
        if (leaving == 0) {
            if (syscall(SYS_setresuid, 2000, 3000, 3000)) _exit(81);
            _exit(0);
        }
        siginfo_t wait_info;
        waitid(P_PID, leaving, &wait_info, WEXITED | WNOWAIT);
        signal_seen("chld-uid", SIGCHLD, leaving);
        memset(&wait_info, 0, sizeof wait_info);
        waitid(P_PID, leaving, &wait_info, WEXITED);
        printf("waitid-uid: uid=%u code=%d\n", wait_info.si_uid, wait_info.si_code);
        /* The child leaves only when told, so that SIGCHLD of its exit does not
           merge with the pending one of its continuing. */
        int leave[2];
        if (pipe(leave)) return 88;
        fflush(stdout);
        pid_t stopping = child();
        if (stopping == 0) {
            close(leave[1]);
            if (syscall(SYS_setresuid, 2000, 2000, 2000)) _exit(82);
            /* Not raise: after the raw fork glibc still has the parent's thread ID. */
            kill(getpid(), SIGSTOP);
            char byte;
            if (read(leave[0], &byte, 1) < 0) _exit(89);
            _exit(0);
        }
        close(leave[0]);
        waitid(P_PID, stopping, &wait_info, WSTOPPED | WNOWAIT);
        signal_seen("chld-stop-uid", SIGCHLD, stopping);
        memset(&wait_info, 0, sizeof wait_info);
        waitid(P_PID, stopping, &wait_info, WSTOPPED);
        printf("waitid-stop-uid: uid=%u code=%d\n", wait_info.si_uid, wait_info.si_code);
        kill(stopping, SIGCONT);
        waitid(P_PID, stopping, &wait_info, WCONTINUED | WNOWAIT);
        signal_seen("chld-cont-uid", SIGCHLD, stopping);
        memset(&wait_info, 0, sizeof wait_info);
        waitid(P_PID, stopping, &wait_info, WCONTINUED);
        printf("waitid-cont-uid: uid=%u code=%d\n", wait_info.si_uid, wait_info.si_code);
        close(leave[1]);
        waitpid(stopping, &status, 0);
        signal_seen("chld-after-cont-uid", SIGCHLD, stopping);
        sigprocmask(SIG_UNBLOCK, &usr1, NULL);
        /* The parent-death signal is sent as the exiting parent, so it needs
           the same permission. */
        for (unsigned parent_uid = 2000; parent_uid <= 3000; parent_uid += 1000) {
            int up[2];
            if (pipe(up)) return 83;
            fflush(stdout);
            pid_t dying = child();
            if (dying == 0) {
                sigset_t mask;
                sigemptyset(&mask);
                sigaddset(&mask, SIGUSR1);
                sigprocmask(SIG_BLOCK, &mask, NULL);
                fflush(stdout);
                pid_t orphan = child();
                if (orphan == 0) {
                    pid_t parent = getppid();
                    if (syscall(SYS_setresuid, 2000, 2000, 2000)) _exit(84);
                    prctl(PR_SET_PDEATHSIG, SIGUSR1);
                    char byte = 1;
                    if (write(up[1], &byte, 1) != 1) _exit(85);
                    close(up[1]);
                    sigset_t wanted;
                    sigemptyset(&wanted);
                    sigaddset(&wanted, SIGUSR1);
                    /* Its parent has gone before the signal is looked for. */
                    while (getppid() == parent) sched_yield();
                    siginfo_t info;
                    struct timespec patience = {1, 0};
                    int got = sigtimedwait(&wanted, &info, &patience);
                    if (got < 0) printf("pdeath-%u: %s\n", parent_uid, strerror(errno));
                    else printf("pdeath-%u: signal=%d code=%d uid=%u sender=%d\n", parent_uid,
                                got, info.si_code, info.si_uid, info.si_pid == parent);
                    fflush(stdout);
                    _exit(0);
                }
                char byte;
                if (read(up[0], &byte, 1) != 1) _exit(86);
                if (syscall(SYS_setresuid, parent_uid, parent_uid, parent_uid)) _exit(87);
                _exit(0);
            }
            close(up[0]);
            close(up[1]);
            /* The parent, then the orphan, which comes to this subreaper. */
            waitpid(dying, &status, 0);
            printf("dying: status=%d\n", status);
            pid_t last = wait(&status);
            printf("orphan: reaped=%d status=%d\n", last > 0, status);
        }
        return 0;
    }
    if (!strcmp(mode, "peer-credentials")) {
        /* SO_PEERCRED: the effective IDs when the socket was made, listened
           or connected (init_peercred, copy_peercred, cred_to_ucred). */
        AS_SENDER(0, 0, 0, {
            int sv[2];
            if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv)) _exit(90);
            peer_ids_leave_root();
            peer_ids_peer("pair-made-as-root", sv[0]);
            if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv)) _exit(90);
            peer_ids_peer("pair-made-as-user", sv[0]);
            peer_ids_peer("pair-made-as-user-other-end", sv[1]);
        });
        AS_SENDER(0, 0, 0, {
            struct sockaddr_un a;
            socklen_t len = unix_abstract(&a, "peer-credentials");
            int ready[2];
            if (pipe(ready)) _exit(90);
            fflush(stdout);
            pid_t client = child();
            if (client == 0) {
                if (syscall(SYS_setresgid, 5100, 5200, 5300)) _exit(91);
                if (syscall(SYS_setresuid, 5000, 5001, 5002)) _exit(91);
                char byte;
                if (read(ready[0], &byte, 1) != 1) _exit(91);
                int c = socket(AF_UNIX, SOCK_STREAM, 0);
                peer_ids_peer("client-before", c);
                if (connect(c, (void *)&a, len)) _exit(91);
                peer_ids_peer("client", c);
                /* A later change does not show on the other end. */
                if (syscall(SYS_setresuid, 5000, 5000, 5002)) _exit(91);
                fflush(stdout);
                if (write(c, "x", 1) != 1) _exit(91);
                _exit(0);
            }
            int l = socket(AF_UNIX, SOCK_STREAM, 0);
            if (l < 0 || bind(l, (void *)&a, len)) _exit(92);
            peer_ids_leave_root();
            if (listen(l, 1)) _exit(92);
            peer_ids_peer("listener", l);
            /* A later change does not show on clients. */
            if (syscall(SYS_setresuid, 1000, 1000, 3000)) _exit(92);
            peer_ids_peer("listener-after-change", l);
            fflush(stdout);
            if (write(ready[1], "x", 1) != 1) _exit(92);
            int accepted = accept(l, NULL, NULL);
            char byte;
            if (accepted < 0 || read(accepted, &byte, 1) != 1) _exit(92);
            peer_ids_peer("accepted", accepted);
            int status = 0;
            waitpid(client, &status, 0);
            printf("client: status=%d\n", status);
        });
        /* A message carries the real IDs when an end passes credentials. */
        AS_SENDER(0, 0, 0, {
            int sv[2], on = 1;
            if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv)) _exit(90);
            if (setsockopt(sv[1], SOL_SOCKET, SO_PASSCRED, &on, sizeof on)) _exit(90);
            peer_ids_leave_root();
            if (write(sv[0], "w", 1) != 1) _exit(90);
            peer_ids_received("write", sv[1]);
            if (send(sv[0], "s", 1, 0) != 1) _exit(90);
            peer_ids_received("send", sv[1]);
            if (sendto(sv[0], "t", 1, 0, NULL, 0) != 1) _exit(90);
            peer_ids_received("sendto", sv[1]);
            struct iovec iov = {"m", 1};
            struct msghdr plain = {.msg_iov = &iov, .msg_iovlen = 1};
            if (sendmsg(sv[0], &plain, 0) != 1) _exit(90);
            peer_ids_received("sendmsg", sv[1]);
        });
        /* A stream read does not join writes of other real IDs. */
        AS_SENDER(0, 0, 0, {
            int sv[2], on = 1;
            if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv)) _exit(90);
            if (setsockopt(sv[1], SOL_SOCKET, SO_PASSCRED, &on, sizeof on)) _exit(90);
            if (write(sv[0], "a", 1) != 1) _exit(90);
            if (write(sv[0], "b", 1) != 1) _exit(90);
            if (syscall(SYS_setresuid, 0, 2000, 0)) _exit(90);
            if (write(sv[0], "c", 1) != 1) _exit(90);
            if (syscall(SYS_setresuid, -1, 0, -1)) _exit(90);
            if (syscall(SYS_setresuid, 1000, 2000, 0)) _exit(90);
            if (write(sv[0], "d", 1) != 1) _exit(90);
            peer_ids_received("stream-root", sv[1]);
            peer_ids_received("stream-user", sv[1]);
        });
        /* SCM_CREDENTIALS without capabilities: the caller's own process
           and any of its real, effective and saved IDs (scm_check_creds). */
        AS_SENDER(0, 0, 0, {
            int sv[2], on = 1;
            if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv)) _exit(90);
            if (setsockopt(sv[1], SOL_SOCKET, SO_PASSCRED, &on, sizeof on)) _exit(90);
            pid_t thread = peer_ids_thread_start();
            peer_ids_leave_root();
            pid_t own = getpid();
            peer_ids_send("real", sv[0], sv[1], own, 1000, 1100);
            peer_ids_send("effective", sv[0], sv[1], own, 2000, 2100);
            peer_ids_send("saved", sv[0], sv[1], own, 3000, 3100);
            peer_ids_send("mixed", sv[0], sv[1], own, 3000, 1100);
            peer_ids_send("other-user", sv[0], sv[1], own, 4000, 1100);
            peer_ids_send("other-group", sv[0], sv[1], own, 1000, 4100);
            peer_ids_send("root-user", sv[0], sv[1], own, 0, 1100);
            peer_ids_send("root-group", sv[0], sv[1], own, 1000, 0);
            peer_ids_send("parent", sv[0], sv[1], getppid(), 1000, 1100);
            peer_ids_send("thread", sv[0], sv[1], thread, 1000, 1100);
            /* Refused before the process is looked up. */
            peer_ids_send("no-process", sv[0], sv[1], 0x3fffff, 1000, 1100);
            peer_ids_send("process-0", sv[0], sv[1], 0, 1000, 1100);
            /* But an ID of -1 comes first. */
            peer_ids_send("user-minus-1", sv[0], sv[1], 0, -1, 1100);
            peer_ids_send("group-minus-1", sv[0], sv[1], 0, 1000, -1);
        });
        /* Root may name any of them, of any process there is. */
        AS_SENDER(0, 0, 0, {
            int sv[2], on = 1;
            if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv)) _exit(90);
            if (setsockopt(sv[1], SOL_SOCKET, SO_PASSCRED, &on, sizeof on)) _exit(90);
            pid_t thread = peer_ids_thread_start();
            peer_ids_send("root-any-ids", sv[0], sv[1], getpid(), 4000, 4100);
            peer_ids_send("root-parent", sv[0], sv[1], getppid(), 0, 0);
            peer_ids_send("root-thread", sv[0], sv[1], thread, 0, 0);
            peer_ids_send("root-no-process", sv[0], sv[1], 0x3fffff, 0, 0);
            peer_ids_send("root-process-0", sv[0], sv[1], 0, 0, 0);
            peer_ids_send("root-minus-1", sv[0], sv[1], getpid(), -1, 0);
        });
        return 0;
    }
    if (!strcmp(mode, "core-credentials")) {
        /* A core is made with the permissions and the filesystem IDs of the
           thread that faulted (do_coredump), and names the real IDs of its
           process's leader (fill_psinfo). */
        char dir[] = "/tmp/core-credentials-XXXXXX";
        if (!mkdtemp(dir) || chdir(dir)) return 80;
        /* sudo leaves root's group among the supplementary ones, which would
           let the group's bits below apply. */
        if (setgroups(0, NULL)) return 80;
        umask(022);
        if (chmod(".", 0777)) return 81;
        core_credentials_report("user", core_credentials_child(0, -1));
        core_credentials_report("fsuid", core_credentials_child(0, 3000));
        core_credentials_report("thread", core_credentials_child(1, -1));
        /* Root's old core in a directory all may write is replaced. */
        int old = open("core", O_CREAT | O_WRONLY, 0644);
        if (old < 0 || write(old, "old", 3) != 3) return 82;
        close(old);
        core_credentials_report("replaced", core_credentials_child(0, -1));
        /* A directory's set-group-ID bit gives the core its group. */
        if (chown(".", 0, 4100) || chmod(".", 02777)) return 83;
        core_credentials_report("set-group-id", core_credentials_child(0, -1));
        if (chown(".", 0, 0)) return 83;
        /* A sticky directory keeps root's old core; a new one goes in. */
        if (chmod(".", 01777)) return 84;
        core_credentials_report("sticky-new", core_credentials_child(0, -1));
        old = open("core", O_CREAT | O_WRONLY, 0644);
        if (old < 0 || write(old, "old", 3) != 3) return 85;
        close(old);
        core_credentials_report("sticky-old", core_credentials_child(0, -1));
        /* No core where the user may not write, or search. */
        if (chmod(".", 0755)) return 86;
        core_credentials_report("no-write", core_credentials_child(0, -1));
        if (chmod(".", 0776)) return 87;
        core_credentials_report("no-search", core_credentials_child(0, -1));
        /* Root writes anywhere, as itself. */
        if (chmod(".", 0)) return 88;
        fflush(stdout);
        pid_t root = fork();
        if (root == 0) {
            core_credentials_limit();
            *(volatile int *)0 = 1;
            _exit(70);
        }
        core_credentials_report("root", root);
        if (chdir("/") || rmdir(dir)) return 89;
        return 0;
    }
    if (!strcmp(mode, "set-id-writes")) {
        /* A change to a regular file takes its set-user-ID bit, and its
           set-group-ID bit with group execution or outside its group, from a
           writer without CAP_FSETID (file_remove_privs, do_truncate). */
        char dir[] = "/tmp/set-id-writes-XXXXXX";
        if (!mkdtemp(dir) || chdir(dir)) return 80;
        umask(022);
        /* sudo leaves root's group among the supplementary ones. */
        if (setgroups(0, NULL)) return 80;
        if (chmod(".", 0777)) return 80;
        int from = open("from", O_CREAT | O_WRONLY, 0666);
        if (from < 0 || write(from, "x", 1) != 1) return 80;
        close(from);
        static const char *const ways[] = {
            "write", "write-empty", "pwrite", "pwrite-empty", "writev", "pwritev", "ftruncate",
            "ftruncate-same", "truncate", "open-trunc", "open-read", "fallocate", "sendfile",
            "copy_file_range", "chown-self", "mmap",
        };
        for (size_t i = 0; i < sizeof ways / sizeof *ways; i++) {
            set_id_case(ways[i], 06755, 2100, 2000);
        }
        set_id_case("write", 04644, 2100, 2000);
        set_id_case("write", 02755, 2100, 2000);
        /* Without group execution the bit stays for a member of the group. */
        set_id_case("write", 02645, 2100, 2000);
        set_id_case("write", 02645, 4100, 2000);
        set_id_case("ftruncate", 02645, 2100, 2000);
        set_id_case("ftruncate", 02645, 4100, 2000);
        set_id_case("write", 0644, 2100, 2000);
        /* Another writer, by the others' bits. */
        set_id_case("write", 06777, 4100, 3000);
        /* Root has CAP_FSETID. */
        set_id_case("write", 06755, 2100, 0);
        set_id_case("ftruncate", 06755, 2100, 0);
        set_id_case("open-trunc", 06755, 2100, 0);
        unlink("f");
        unlink("from");
        if (chdir("/") || rmdir(dir)) return 89;
        return 0;
    }
    if (!strcmp(mode, "socket-owners")) {
        /* A pipe or socket belongs to the thread that made it, by its
           filesystem IDs (get_pipe_inode, sock_alloc); a socket file too, with
           the permissions of mknod, and connecting needs to write what the
           path names (unix_find_bsd). */
        char dir[] = "/tmp/socket-owners-XXXXXX";
        if (!mkdtemp(dir) || chdir(dir)) return 80;
        umask(022);
        /* sudo leaves root's group among the supplementary ones. */
        if (setgroups(0, NULL)) return 80;
        if (chmod(".", 0777)) return 80;
        int fds[2];
        if (pipe(fds)) return 80;
        owner_show("pipe-root", fds[0]);
        if (mkdir("closed", 0700) || mkdir("nosearch", 0776) || chmod("nosearch", 0776)) return 80;
        if (socket_bind(SOCK_STREAM, "closed/s") < 0) return 80;
        struct sockaddr_un a;
        socklen_t len = socket_path(&a, "listening");
        int listener = socket(AF_UNIX, SOCK_STREAM, 0);
        if (listener < 0 || bind(listener, (void *)&a, len) || listen(listener, 8)) return 80;
        path_show("listening", "listening");
        long dgram = socket_bind(SOCK_DGRAM, "dgram");
        if (dgram < 0 || chmod("dgram", 0777)) return 80;
        int plain = open("plain", O_CREAT | O_WRONLY, 0644);
        if (plain < 0) return 80;
        close(plain);
        int writable = open("writable", O_CREAT | O_WRONLY, 0666);
        if (writable < 0 || fchmod(writable, 0666)) return 80;
        close(writable);
        if (mkdir("group-dir", 0777) || chown("group-dir", 0, 4100) || chmod("group-dir", 02777)) return 80;
        if (mkdir("no-write", 0755)) return 80;
        AS_SENDER(0, 0, 0, {
            peer_ids_leave_root();
            int p[2], sv[2];
            if (pipe(p) || socketpair(AF_UNIX, SOCK_STREAM, 0, sv)) _exit(90);
            owner_show("pipe-read", p[0]);
            owner_show("pipe-write", p[1]);
            owner_show("pair", sv[0]);
            owner_show("pair-other", sv[1]);
            owner_show("unix", socket(AF_UNIX, SOCK_DGRAM, 0));
            /* A write takes nothing from what is not a regular file. */
            permitted("pipe-chmod", fchmod(p[1], 04600));
            permitted("pipe-write-set-id", write(p[1], "x", 1));
            owner_show("pipe-set-id", p[0]);
            /* A socket file: the filesystem IDs, the umask, and the rules of
               making a file there. */
            permitted("bind-own", socket_bind(SOCK_STREAM, "own"));
            path_show("own", "own");
            permitted("bind-group-dir", socket_bind(SOCK_STREAM, "group-dir/s"));
            path_show("group-dir/s", "group-dir/s");
            permitted("bind-no-write", socket_bind(SOCK_STREAM, "no-write/s"));
            permitted("bind-no-search", socket_bind(SOCK_STREAM, "closed/other"));
            permitted("bind-nosearch-write", socket_bind(SOCK_STREAM, "nosearch/s"));
            permitted("bind-exists", socket_bind(SOCK_STREAM, "own"));
            permitted("bind-missing-dir", socket_bind(SOCK_STREAM, "missing/s"));
            if (syscall(SYS_setfsuid, 3000) < 0 || syscall(SYS_setfsgid, 3100) < 0) _exit(90);
            if (pipe(p)) _exit(90);
            owner_show("pipe-fsuid", p[0]);
            permitted("bind-fsuid", socket_bind(SOCK_STREAM, "fs"));
            path_show("fs", "fs");
        });
        /* Connecting as another user: the file's bits, before its type. */
        AS_SENDER(0, 0, 0, {
            if (syscall(SYS_setresgid, 5100, 5100, 5100)) _exit(90);
            if (syscall(SYS_setresuid, 5000, 5000, 5000)) _exit(90);
            permitted("connect-not-writable", socket_connect("listening"));
            permitted("connect-plain-not-writable", socket_connect("plain"));
            permitted("connect-plain-writable", socket_connect("writable"));
            permitted("connect-dir", socket_connect("no-write"));
            permitted("connect-no-search", socket_connect("closed/s"));
            permitted("connect-missing", socket_connect("missing"));
            permitted("sendto-writable", socket_sendto("dgram"));
            permitted("sendto-plain", socket_sendto("plain"));
        });
        if (chmod("listening", 0777)) return 80;
        AS_SENDER(0, 0, 0, {
            if (syscall(SYS_setresgid, 5100, 5100, 5100)) _exit(90);
            if (syscall(SYS_setresuid, 5000, 5000, 5000)) _exit(90);
            permitted("connect-writable", socket_connect("listening"));
        });
        /* The owner by the owner's bits; root whatever the bits. */
        if (chmod("listening", 0200) || chown("listening", 5000, 5100)) return 80;
        AS_SENDER(0, 0, 0, {
            if (syscall(SYS_setresgid, 5100, 5100, 5100)) _exit(90);
            if (syscall(SYS_setresuid, 5000, 5000, 5000)) _exit(90);
            permitted("connect-owner", socket_connect("listening"));
        });
        if (chmod("listening", 0)) return 80;
        permitted("connect-root", socket_connect("listening"));
        /* What accept gives belongs to the one who accepts, not who connected. */
        int waiting = accept(listener, NULL, NULL);
        owner_show("accepted-root", waiting);
        if (chmod("listening", 0777)) return 80;
        fflush(stdout);
        pid_t client = child();
        if (client == 0) {
            if (socket_connect("listening")) _exit(91);
            _exit(0);
        }
        int status = 0;
        waitpid(client, &status, 0);
        AS_SENDER(0, 0, 0, {
            peer_ids_leave_root();
            int accepted = accept(listener, NULL, NULL);
            owner_show("accepted-user", accepted);
        });
        fflush(stdout);
        if (!fork()) {
            /* Clean what the cases left, as root, whatever their modes. */
            static const char *const files[] = {
                "closed/s", "closed/other", "listening", "dgram", "plain", "writable", "own", "fs",
                "group-dir/s", "no-write/s", "nosearch/s", "from",
            };
            for (size_t i = 0; i < sizeof files / sizeof *files; i++) unlink(files[i]);
            static const char *const dirs[] = {"closed", "nosearch", "group-dir", "no-write"};
            for (size_t i = 0; i < sizeof dirs / sizeof *dirs; i++) rmdir(dirs[i]);
            _exit(0);
        }
        wait(NULL);
        if (chdir("/") || rmdir(dir)) return 89;
        return 0;
    }
    if (!strcmp(mode, "capabilities-show")) {
        caps_show("after-exec", 0);
        caps_status();
        return 0;
    }
    if (!strcmp(mode, "capabilities")) {
        char dir[] = "/tmp/capabilities-XXXXXX";
        if (!mkdtemp(dir) || chdir(dir)) return 80;
        umask(022);
        /* sudo leaves root's group among the supplementary ones. */
        if (setgroups(0, NULL)) return 80;
        if (chmod(".", 0777)) return 80;
        if (caps_copy(self)) return 80;
        caps_show("start", 0);
        caps_status();
        /* The header: an unknown version is written back, and without data
           only asks for that. */
        AS_SENDER(0, 0, 0, {
            struct caps_header h = {0x1234, 0};
            struct caps_word d[2];
            permitted("version-probe", syscall(SYS_capget, &h, NULL));
            printf("  version=%x\n", h.version);
            h.version = 0x1234;
            permitted("version-with-data", syscall(SYS_capget, &h, d));
            printf("  version=%x\n", h.version);
            h.version = 0x1234;
            permitted("version-capset", syscall(SYS_capset, &h, d));
            printf("  version=%x\n", h.version);
            permitted("header-fault", syscall(SYS_capget, (void *)8, d));
            permitted("header-fault-probe", syscall(SYS_capget, (void *)8, NULL));
            permitted("capset-header-fault", syscall(SYS_capset, (void *)8, d));
            h.version = CAPS_V3;
            permitted("data-fault", syscall(SYS_capget, &h, (void *)8));
            permitted("no-data", syscall(SYS_capget, &h, NULL));
            permitted("capset-data-fault", syscall(SYS_capset, &h, (void *)8));
            /* Each version's size. */
            static const uint32_t versions[] = {CAPS_V1, CAPS_V2, CAPS_V3};
            for (int i = 0; i < 3; i++) {
                memset(d, 0x55, sizeof d);
                permitted("sized", caps_get(versions[i], 0, d));
                printf("  %x %x %x %x\n", d[0].effective, d[0].permitted, d[1].effective, d[1].permitted);
            }
            /* Whom it reads. */
            permitted("pid-negative", caps_get(CAPS_V3, -1, d));
            permitted("pid-none", caps_get(CAPS_V3, 0x3fffff, d));
            caps_show("pid-own", getpid());
            caps_show("pid-parent", getppid());
            /* capset only for the calling thread. */
            h.version = CAPS_V3;
            caps_get(CAPS_V3, 0, d);
            h.pid = getppid();
            permitted("capset-parent", syscall(SYS_capset, &h, d));
            h.pid = -1;
            permitted("capset-negative", syscall(SYS_capset, &h, d));
            h.pid = syscall(SYS_gettid);
            permitted("capset-own", syscall(SYS_capset, &h, d));
            /* Another thread's own sets. */
            pthread_t thread;
            if (pthread_create(&thread, NULL, caps_thread, NULL)) _exit(90);
            while (!caps_thread_id) sched_yield();
            caps_show("thread", caps_thread_id);
            caps_show("leader-after-thread", 0);
            caps_thread_done = 1;
            pthread_join(thread, NULL);
            /* A thread that has ended is gone, once it is joined. */
            while (kill(getpid(), 0) == 0 && syscall(SYS_tgkill, getpid(), caps_thread_id, 0) == 0) sched_yield();
            caps_show("thread-ended", caps_thread_id);
            /* A zombie keeps its sets until it is reaped. */
            fflush(stdout);
            pid_t zombie = child();
            if (zombie == 0) {
                if (caps_set(0x3, 0x7, 0x1)) _exit(1);
                _exit(0);
            }
            siginfo_t info;
            waitid(P_PID, zombie, &info, WEXITED | WNOWAIT);
            caps_show("zombie", zombie);
            waitpid(zombie, NULL, 0);
            caps_show("reaped", zombie);
        });
        /* What capset allows. */
        AS_SENDER(0, 0, 0, {
            permitted("all-again", caps_set(CAPS_ALL, CAPS_ALL, 0));
            permitted("past-the-last", caps_set(~0ULL, ~0ULL, 0));
            caps_show("past-the-last", 0);
            permitted("drop", caps_set(0xf0, 0xff, 0));
            caps_show("dropped", 0);
            permitted("effective-beyond", caps_set(0x1f0, 0xff, 0));
            permitted("effective-beyond-new", caps_set(0xf0, 0x70, 0));
            permitted("permitted-grows", caps_set(0, 0x1ff, 0));
            /* No CAP_SETPCAP: within the old inheritable and permitted. */
            permitted("inherit-within", caps_set(0x10, 0xff, 0x0f));
            caps_show("inherit-within", 0);
            permitted("inherit-beyond", caps_set(0x10, 0xff, 0x100));
            permitted("permitted-less", caps_set(0, 0x1, 0x0f));
            permitted("inherit-kept", caps_set(0, 0x1, 0x0f));
            permitted("inherit-beyond-less", caps_set(0, 0x1, 0x1f));
            caps_show("less", 0);
            caps_status();
        });
        AS_SENDER(0, 0, 0, {
            /* With CAP_SETPCAP, any inheritable capability. */
            permitted("setpcap", caps_set(CAP_BIT(8), CAP_BIT(8), CAP_BIT(21)));
            caps_show("setpcap", 0);
            /* The first version clears the high bits. */
            struct caps_header h = {CAPS_V1, 0};
            struct caps_word one = {CAP_BIT(8), CAP_BIT(8), 0};
            permitted("v1", syscall(SYS_capset, &h, &one));
            caps_show("v1", 0);
        });
        AS_SENDER(0, 0, 0, {
            struct caps_header h = {CAPS_V3, 0};
            struct caps_word d[2];
            caps_get(CAPS_V3, 0, d);
            d[1].effective = 0xffffffff;
            d[1].permitted = 0xffffffff;
            permitted("high-past-the-last", syscall(SYS_capset, &h, d));
            caps_show("high-past-the-last", 0);
            /* A set the first version cannot show is cut, not refused. */
            struct caps_word one;
            permitted("v1-read", caps_get(CAPS_V1, 0, &one));
            printf("  %x\n", one.effective);
        });
        /* What each capability allows. */
        pid_t target = limit_target(2000, 2000, 2000, 2000, 2000, 2000);
        int made = open("theirs", O_CREAT | O_WRONLY, 0666);
        if (made < 0 || fchown(made, 3000, 3100) || fchmod(made, 0)) return 81;
        close(made);
        AS_SENDER(0, 0, 0, {
            caps_only(CAPS_ALL & ~CAP_BIT(5));
            permitted("kill-without", kill(target, 0));
            caps_only(CAP_BIT(5));
            permitted("kill-with", kill(target, 0));
        });
        AS_SENDER(0, 0, 0, {
            if (limit_set(0, RLIMIT_NOFILE, 1024, 4096)) _exit(90);
            caps_only(CAPS_ALL & ~CAP_BIT(24));
            permitted("hard-up-without", limit_set(0, RLIMIT_NOFILE, 1024, 8192));
            caps_only(CAP_BIT(24));
            permitted("hard-up-with", limit_set(0, RLIMIT_NOFILE, 1024, 8192));
        });
        AS_SENDER(0, 0, 0, {
            if (limit_set(0, RLIMIT_NICE, 0, 0)) _exit(90);
            if (setpriority(PRIO_PROCESS, 0, 5)) _exit(90);
            caps_only(CAPS_ALL & ~CAP_BIT(23));
            errno = 0;
            permitted("nice-down-without", setpriority(PRIO_PROCESS, 0, -1));
            permitted("other-nice-without", setpriority(PRIO_PROCESS, target, 5));
            caps_only(CAP_BIT(23));
            permitted("nice-down-with", setpriority(PRIO_PROCESS, 0, -1));
            permitted("other-nice-with", setpriority(PRIO_PROCESS, target, 5));
        });
        AS_SENDER(0, 0, 0, {
            caps_only(CAPS_ALL & ~(CAP_BIT(1) | CAP_BIT(2)));
            permitted("read-without", open("theirs", O_RDONLY));
            permitted("write-without", open("theirs", O_WRONLY));
            caps_only(CAP_BIT(2));
            permitted("read-search", open("theirs", O_RDONLY));
            permitted("write-search", open("theirs", O_WRONLY));
            caps_only(CAP_BIT(1));
            permitted("read-override", open("theirs", O_RDONLY));
            permitted("write-override", open("theirs", O_WRONLY));
        });
        AS_SENDER(0, 0, 0, {
            caps_only(CAPS_ALL & ~CAP_BIT(3));
            permitted("chmod-without", chmod("theirs", 0));
            caps_only(CAP_BIT(3));
            permitted("chmod-with", chmod("theirs", 0));
            caps_only(CAPS_ALL & ~CAP_BIT(0));
            permitted("chown-without", chown("theirs", 3000, 3100));
            caps_only(CAP_BIT(0));
            permitted("chown-with", chown("theirs", 3000, 3100));
        });
        AS_SENDER(0, 0, 0, {
            int fd = open("set-ids", O_CREAT | O_WRONLY, 0666);
            if (fd < 0 || fchown(fd, 3000, 3100) || fchmod(fd, 06755)) _exit(90);
            caps_only(CAPS_ALL & ~CAP_BIT(4));
            permitted("write-without-fsetid", write(fd, "x", 1));
            struct stat st;
            fstat(fd, &st);
            printf("  mode=%o\n", (unsigned)(st.st_mode & 07777));
            caps_only(CAPS_ALL);
            if (fchmod(fd, 06755)) _exit(90);
            permitted("write-with-fsetid", write(fd, "x", 1));
            fstat(fd, &st);
            printf("  mode=%o\n", (unsigned)(st.st_mode & 07777));
            close(fd);
            unlink("set-ids");
        });
        AS_SENDER(0, 0, 0, {
            caps_only(CAPS_ALL & ~CAP_BIT(7));
            permitted("setuid-without", syscall(SYS_setresuid, 2000, 2000, 2000));
            caps_only(CAPS_ALL & ~CAP_BIT(6));
            permitted("setgid-without", syscall(SYS_setresgid, 2000, 2000, 2000));
            gid_t group = 5;
            permitted("setgroups-without", syscall(SYS_setgroups, 1, &group));
        });
        AS_SENDER(0, 0, 0, {
            int sv[2];
            if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv)) _exit(90);
            caps_only(CAPS_ALL & ~CAP_BIT(21));
            permitted("scm-process-without", send_credentials(sv[0], "m", getppid(), 0, 0, CMSG_LEN(sizeof(struct ucred))));
            permitted("scm-ids-still", send_credentials(sv[0], "m", getpid(), 4000, 4100, CMSG_LEN(sizeof(struct ucred))));
            caps_only(CAPS_ALL & ~CAP_BIT(7));
            permitted("scm-user-without", send_credentials(sv[0], "m", getpid(), 4000, 0, CMSG_LEN(sizeof(struct ucred))));
            caps_only(CAPS_ALL & ~CAP_BIT(6));
            permitted("scm-group-without", send_credentials(sv[0], "m", getpid(), 0, 4100, CMSG_LEN(sizeof(struct ucred))));
        });
        kill(target, SIGKILL);
        waitpid(target, NULL, 0);
        /* What leaving root and coming back does to the sets. */
        AS_SENDER(0, 0, 0, {
            if (caps_set(0x3ff, 0x3fff, 0xf)) _exit(90);
            if (syscall(SYS_setresuid, 0, 2000, 0)) _exit(90);
            caps_show("effective-leaves-root", 0);
            permitted("no-effective-setuid", syscall(SYS_setresuid, -1, 0, -1));
            caps_show("effective-back", 0);
        });
        AS_SENDER(0, 0, 0, {
            if (caps_set(0x3ff, 0x3fff, 0xf)) _exit(90);
            permitted("fsuid-away", syscall(SYS_setfsuid, 2000) < 0 ? -1 : 0);
            caps_show("fsuid-away", 0);
            permitted("fsuid-back", syscall(SYS_setfsuid, 0) < 0 ? -1 : 0);
            caps_show("fsuid-back", 0);
        });
        AS_SENDER(0, 0, 0, {
            /* PR_SET_KEEPCAPS keeps permitted, and capset then makes them
               effective for a user other than root. */
            if (caps_set(CAPS_ALL, CAPS_ALL, 0xf)) _exit(90);
            if (prctl(PR_SET_KEEPCAPS, 1)) _exit(90);
            if (syscall(SYS_setresuid, 2000, 2000, 2000)) _exit(90);
            caps_show("kept", 0);
            permitted("kept-effective", caps_set(CAP_BIT(0) | CAP_BIT(1), CAP_BIT(0) | CAP_BIT(1) | CAP_BIT(7), 0xf));
            caps_show("kept-effective", 0);
            permitted("kept-opens", open("theirs", O_RDONLY));
            permitted("kept-chown", chown("theirs", 3000, 3100));
            permitted("kept-chmod", chmod("theirs", 0));
            permitted("kept-gains-setuid", caps_set(CAP_BIT(7), CAP_BIT(7), 0xf));
            permitted("kept-setuid", syscall(SYS_setresuid, 3000, 3000, 3000));
            caps_show("kept-after-setuid", 0);
        });
        /* exec: root takes every capability again, whatever it dropped; the
           inheritable set stays; a user other than root has none. */
        AS_SENDER(0, 0, 0, {
            if (caps_set(0xf0, 0xff, 0x3)) _exit(90);
            caps_exec();
        });
        AS_SENDER(0, 0, 0, {
            if (caps_set(CAPS_ALL, CAPS_ALL, 0x3)) _exit(90);
            if (prctl(PR_SET_KEEPCAPS, 1)) _exit(90);
            if (syscall(SYS_setresuid, 2000, 2000, 2000)) _exit(90);
            caps_exec();
        });
        AS_SENDER(0, 0, 0, {
            if (caps_set(0, 0, 0)) _exit(90);
            caps_exec();
        });
        fflush(stdout);
        unlink("theirs");
        unlink("prog");
        if (chdir("/") || rmdir(dir)) return 89;
        return 0;
    }
    if (!strcmp(mode, "shm")) return shm_case();
    if (!strcmp(mode, "sem")) return sem_case();
    if (!strcmp(mode, "msg")) return msg_case();
    if (!strcmp(mode, "rseq")) return rseq_case();
    if (!strcmp(mode, "pkey")) return pkey_case();
    if (!strcmp(mode, "etxtbsy-run")) {
        /* Says it runs, then runs until its parent closes the pipe. */
        char c;
        if (write(11, "r", 1) != 1) return 8;
        while (read(10, &c, 1) > 0) {}
        return 0;
    }
    if (!strcmp(mode, "etxtbsy")) {
        static const char prog[] = "/tmp/paludarium-etxtbsy";
        static const char script[] = "/tmp/paludarium-etxtbsy.sh";
        static const char line[] = "#!/tmp/paludarium-etxtbsy etxtbsy-run\n";
        char *args[] = {"x", "etxtbsy-run", "x", NULL}, *none[] = {NULL};
        unlink(prog);
        unlink(script);
        /* A program, and a script it interprets. */
        int w = open(prog, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0755);
        result("copied", copy_into(self, w));
        int sw = open(script, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0755);
        result("script", write(sw, line, sizeof line - 1));
        close(sw);
        /* A description open for writing refuses exec of its file, of a
           script it interprets, and of the script itself (ETXTBSY). */
        errno = 0;
        outcome("writer-exec", execve(prog, args, none));
        errno = 0;
        outcome("writer-interpreter", execve(script, args, none));
        close(w);
        sw = open(script, O_WRONLY | O_CLOEXEC);
        errno = 0;
        outcome("writer-script", execve(script, args, none));
        close(sw);
        /* A running program's file: not opened for writing nor truncated,
           read, and writable again once the program ends. */
        pid_t pid = etxtbsy_start(AT_FDCWD, prog, 0);
        etxtbsy_open("running-write", prog, O_WRONLY);
        etxtbsy_open("running-rdwr", prog, O_RDWR);
        etxtbsy_open("running-trunc", prog, O_RDONLY | O_TRUNC);
        errno = 0;
        outcome("running-truncate", truncate(prog, 0));
        etxtbsy_open("running-read", prog, O_RDONLY);
        struct stat st;
        result("size-kept", stat(prog, &st) == 0 && st.st_size > 0);
        etxtbsy_stop(pid);
        etxtbsy_open("after-exit", prog, O_WRONLY);
        /* A running script: its interpreter is the program, and the script
           itself is not held. */
        pid = etxtbsy_start(AT_FDCWD, script, 0);
        etxtbsy_open("script-write", script, O_WRONLY);
        etxtbsy_open("interpreter-write", prog, O_WRONLY);
        etxtbsy_stop(pid);
        /* A memfd: its own descriptor is no writer, so it runs, and writes
           through it go on; opened again for writing, it is refused while
           the program runs, and refuses exec while open. */
        int m = memfd_create("etxtbsy", 0);
        result("memfd-copied", copy_into(self, m));
        char again[64];
        snprintf(again, sizeof again, "/proc/self/fd/%d", m);
        pid = etxtbsy_start(m, "", AT_EMPTY_PATH);
        struct stat ms;
        fstat(m, &ms);
        result("memfd-own-write", pwrite(m, "", 1, ms.st_size));
        etxtbsy_open("memfd-reopen", again, O_RDWR);
        etxtbsy_stop(pid);
        int r = open(again, O_RDWR | O_CLOEXEC);
        result("memfd-reopened", r >= 0);
        errno = 0;
        outcome("memfd-writer-exec", execveat_call(m, "", args, AT_EMPTY_PATH));
        close(r);
        close(m);
        unlink(prog);
        unlink(script);
        return 0;
    }
    if (!strcmp(mode, "execveat-run")) {
        /* What the program execveat ran sees: its name, AT_EXECFN and the
           file /proc/self/exe leads to. */
        char exe[4096];
        long n = readlink("/proc/self/exe", exe, sizeof exe - 1);
        exe[n < 0 ? 0 : n] = 0;
        const char *execfn = (const char *)getauxval(AT_EXECFN);
        printf("%s: argc=%d", argc > 2 ? argv[2] : "?", argc);
        for (int i = 0; i < argc; i++) printf(" [%s]", argv[i]);
        printf(" execfn=%s exe=%s\n", execfn ? execfn : "", exe);
        return 0;
    }
    if (!strcmp(mode, "execveat")) {
        /* execveat and fexecve: by path, from a directory descriptor, a
           descriptor's own file (AT_EMPTY_PATH), a memfd and a removed file,
           and the errors do_open_execat gives. */
        static char copy[] = "/tmp/paludarium-execveat-copy", link_path[] = "/tmp/paludarium-execveat-link";
        char dir[4096];
        strcpy(dir, self);
        char *slash = strrchr(dir, '/');
        if (!slash) return 70;
        *slash = 0;
        const char *base = slash + 1;
        int d = open(*dir ? dir : "/", O_RDONLY | O_DIRECTORY);
        int file = open(self, O_RDONLY), path_only = open(self, O_PATH);
        if (d < 0 || file < 0 || path_only < 0) return 71;
        execveat_child("path", AT_FDCWD, self, 0);
        execveat_child("relative", d, base, 0);
        execveat_child("empty-path", file, "", AT_EMPTY_PATH);
        execveat_child("o-path", path_only, "", AT_EMPTY_PATH);
        int memfd = syscall(SYS_memfd_create, "prog", 0);
        if (memfd < 0 || copy_into(self, memfd)) return 72;
        execveat_child("memfd", memfd, "", AT_EMPTY_PATH);
        char through[64];
        snprintf(through, sizeof through, "/proc/self/fd/%d", memfd);
        execveat_child("fexecve-memfd", AT_FDCWD, through, 0);
        unlink(copy);
        int w = open(copy, O_CREAT | O_WRONLY | O_TRUNC, 0755);
        if (w < 0 || copy_into(self, w) || close(w)) return 73;
        int removed = open(copy, O_RDONLY);
        if (removed < 0 || unlink(copy)) return 74;
        execveat_child("removed", removed, "", AT_EMPTY_PATH);
        snprintf(through, sizeof through, "/proc/self/fd/%d", removed);
        execveat_child("fexecve-removed", AT_FDCWD, through, 0);
        /* A script in a memfd names itself /dev/fd/<n>, which a descriptor
           closed on exec leaves to nothing (ENOENT). */
        char line[4200];
        snprintf(line, sizeof line, "#!%s execveat-run\n", self);
        int script = syscall(SYS_memfd_create, "script", 0);
        int closing = syscall(SYS_memfd_create, "closing", 1);
        if (script < 0 || closing < 0) return 75;
        if (write(script, line, strlen(line)) < 0 || write(closing, line, strlen(line)) < 0) return 75;
        execveat_child("memfd-script", script, "", AT_EMPTY_PATH);
        char *args[] = {"x", "execveat-run", "error", NULL};
        int p[2];
        if (pipe(p)) return 76;
        unlink(link_path);
        if (symlink(self, link_path)) return 77;
        errno = 0;
        outcome("cloexec-script", execveat_call(closing, "", args, AT_EMPTY_PATH));
        outcome("bad-flags", execveat_call(AT_FDCWD, self, args, 0x2));
        outcome("empty-without-flag", execveat_call(file, "", args, 0));
        outcome("closed", execveat_call(900, "", args, AT_EMPTY_PATH));
        outcome("not-a-directory", execveat_call(file, "x", args, 0));
        outcome("nofollow", execveat_call(AT_FDCWD, link_path, args, AT_SYMLINK_NOFOLLOW));
        outcome("directory", execveat_call(d, "", args, AT_EMPTY_PATH));
        outcome("cwd", execveat_call(AT_FDCWD, "", args, AT_EMPTY_PATH));
        outcome("pipe", execveat_call(p[0], "", args, AT_EMPTY_PATH));
        /* A sparse file of no format is ENOEXEC from its first bytes, however
           large it is. */
        int sparse = syscall(SYS_memfd_create, "sparse", 0);
        if (sparse < 0 || ftruncate(sparse, 1L << 32) || fchmod(sparse, 0755)) return 79;
        outcome("sparse", execveat_call(sparse, "", args, AT_EMPTY_PATH));
        if (fchmod(memfd, 0600)) return 78;
        outcome("not-executable", execveat_call(memfd, "", args, AT_EMPTY_PATH));
        unlink(link_path);
        return 0;
    }
    if (!strcmp(mode, "script-exec")) {
        /* load_script: what the first line says, and what exec does with it. */
        char dir[] = "/tmp/script-exec-XXXXXX";
        if (!mkdtemp(dir) || chdir(dir)) return 80;
        umask(022);
        if (chmod(".", 0777)) return 80;
        /* The interpreter is a copy any user may reach, named so it shows. */
        char buffer[65536];
        long n;
        int from = open(self, O_RDONLY), to = open("interp", O_CREAT | O_WRONLY, 0755);
        if (from < 0 || to < 0 || fchmod(to, 0755)) return 80;
        while ((n = read(from, buffer, sizeof buffer)) > 0)
            if (write(to, buffer, n) != n) return 80;
        close(from);
        close(to);
        SCRIPT_LINE("plain", "#!./interp\necho no\n");
        SCRIPT_LINE("argument", "#!./interp one\n");
        SCRIPT_LINE("argument-spaces", "#!./interp one two  three  \t \n");
        SCRIPT_LINE("leading-blanks", "#!  \t./interp\t  one\n");
        SCRIPT_LINE("no-newline", "#!./interp");
        SCRIPT_LINE("no-newline-argument", "#!./interp one");
        SCRIPT_LINE("no-newline-blanks", "#!./interp  ");
        SCRIPT_LINE("carriage-return", "#!./interp\r\n");
        SCRIPT_LINE("nul-after-name", "#!./interp\0 one\n");
        SCRIPT_LINE("nul-in-argument", "#!./interp on\0e\n");
        SCRIPT_LINE("only-bang", "#!\n");
        SCRIPT_LINE("only-blanks", "#!   \t\n");
        SCRIPT_LINE("bang-end", "#!");
        SCRIPT_LINE("bang-nul", "#!\0./interp\n");
        SCRIPT_LINE("one-byte", "#");
        SCRIPT_LINE("empty", "");
        SCRIPT_LINE("not-a-script", "echo no\n");
        char long_line[400];
        memset(long_line, ' ', sizeof long_line);
        memcpy(long_line, "#!", 2);
        script_line("all-blanks", long_line, sizeof long_line);
        memset(long_line, 'x', sizeof long_line);
        memcpy(long_line, "#!", 2);
        script_line("name-too-long", long_line, sizeof long_line);
        memcpy(long_line, "#!./interp ", 11);
        script_line("argument-cut", long_line, sizeof long_line);
        memset(long_line, 'x', sizeof long_line);
        memcpy(long_line, "#!./interp ", 11);
        long_line[254] = '\n';
        script_line("line-at-254", long_line, sizeof long_line);
        long_line[254] = 'x';
        long_line[255] = '\n';
        script_line("line-at-255", long_line, sizeof long_line);
        /* The interpreter. */
        script_file("noexec", "#!./interp\n", 11, 0644);
        script_file("text", "just text\n", 10, 0755);
        script_file("blank", "", 0, 0755);
        if (symlink("interp", "interp-link") || mkdir("dir", 0755)) return 80;
        SCRIPT_LINE("missing", "#!./missing\n");
        SCRIPT_LINE("directory", "#!./dir\n");
        SCRIPT_LINE("interpreter-not-executable", "#!./noexec\n");
        SCRIPT_LINE("interpreter-text", "#!./text\n");
        SCRIPT_LINE("interpreter-empty", "#!./blank\n");
        SCRIPT_LINE("interpreter-link", "#!./interp-link\n");
        SCRIPT_LINE("interpreter-below-file", "#!./interp/x\n");
        /* A script of scripts, how deep it goes and what each adds. */
        script_file("s1", "#!./interp one\n", 15, 0755);
        for (int i = 2; i <= 8; i++) {
            char name[8], line[32], run[8];
            snprintf(name, sizeof name, "s%d", i);
            int len = snprintf(line, sizeof line, "#!./s%d\n", i - 1);
            script_file(name, line, len, 0755);
            snprintf(run, sizeof run, "./s%d", i);
            char *args[] = {run, "a", NULL};
            script_run(name, run, args, 0);
        }
        /* Its arguments. */
        script_file("s", "#!./interp one\n", 15, 0755);
        char *no_args[] = {NULL};
        script_run("no-arguments", "./s", no_args, 0);
        char *only_zero[] = {"zero", NULL};
        script_run("only-zero", "./s", only_zero, 0);
        char *empty_zero[] = {"", "a", NULL};
        script_run("empty-zero", "./s", empty_zero, 0);
        /* The path: as named, and the interpreter's from the working directory. */
        if (mkdir("sub", 0777)) return 80;
        script_file("sub/script-with-a-long-name", "#!./interp\n", 11, 0755);
        char *sub_args[] = {"x", NULL};
        script_run("below", "sub/script-with-a-long-name", sub_args, 0);
        if (symlink("s", "script-link")) return 80;
        script_run("script-link", "./script-link", sub_args, 0);
        script_run("no-such-script", "./nothing", sub_args, 0);
        /* Its permissions and set-ID bits, and the interpreter's. */
        script_file("s", "#!./interp\n", 11, 0644);
        script_run("script-not-executable", "./s", sub_args, 2000);
        script_file("s", "#!./interp\n", 11, 0111);
        script_run("script-only-executable", "./s", sub_args, 2000);
        /* One unreadable file on the way: a script in the middle of the chain,
           and the interpreter at its end, which needs a mode of its own. */
        script_file("inner", "#!./interp\n", 11, 0111);
        script_file("s", "#!./inner\n", 10, 0755);
        script_run("unreadable-in-the-middle", "./s", sub_args, 2000);
        if (chmod("interp", 0111)) return 80;
        script_file("s", "#!./interp\n", 11, 0755);
        script_run("interpreter-not-readable", "./s", sub_args, 2000);
        if (chmod("interp", 0755)) return 80;
        unlink("inner");
        script_file("s", "#!./interp\n", 11, 0755);
        if (chown("s", 3000, 3000) || chmod("s", 06755)) return 80;
        script_run("script-set-id", "./s", sub_args, 2000);
        unlink("s");
        int copy = open("set-id", O_CREAT | O_WRONLY, 0755);
        from = open(self, O_RDONLY);
        if (copy < 0 || from < 0) return 80;
        while ((n = read(from, buffer, sizeof buffer)) > 0)
            if (write(copy, buffer, n) != n) return 80;
        close(copy);
        close(from);
        if (chown("set-id", 3000, 3000) || chmod("set-id", 06755)) return 80;
        script_file("s", "#!./set-id script-exec-set-id\n", 30, 0755);
        script_run("interpreter-set-id", "./s", sub_args, 2000);
        fflush(stdout);
        static const char *const files[] = {
            "s", "noexec", "text", "blank", "interp-link", "script-link", "set-id",
            "s1", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "sub/script-with-a-long-name", "interp",
        };
        for (size_t i = 0; i < sizeof files / sizeof *files; i++) unlink(files[i]);
        if (rmdir("sub") || rmdir("dir")) return 88;
        if (chdir("/") || rmdir(dir)) return 89;
        return 0;
    }
    if (!strcmp(mode, "script-exec-set-id")) {
        printf("  ran: uid=%d euid=%d secure=%lu dumpable=%d\n", (int)getuid(), (int)geteuid(),
               getauxval(AT_SECURE), prctl(PR_GET_DUMPABLE) == 1);
        return 0;
    }
    if (!strcmp(mode, "dynamic-exec")) {
        /* load_elf_binary: the interpreter a program names. A copy of the
           dynamic program is patched in the bytes of its PT_INTERP. Some of
           them crash, which writes no core at Linux's default limit, whatever
           sudo gave the native run. */
        struct rlimit no_core;
        if (getrlimit(RLIMIT_CORE, &no_core)) return 80;
        no_core.rlim_cur = 0;
        if (setrlimit(RLIMIT_CORE, &no_core)) return 80;
        char dir[] = "/tmp/dynamic-exec-XXXXXX";
        if (!mkdtemp(dir)) return 80;
        char path[PATH_MAX];
        snprintf(path, sizeof path, "%s", self);
        char *slash = strrchr(path, '/');
        if (!slash) return 80;
        strcpy(slash + 1, "dynamic");
        static unsigned char image[1 << 20];
        int fd = open(path, O_RDONLY);
        long size = fd < 0 ? -1 : read(fd, image, sizeof image);
        if (size <= 0) return 81;
        close(fd);
        static unsigned char linker[1 << 22];
        fd = open("/lib/ld-musl-x86_64.so.1", O_RDONLY);
        long linker_size = fd < 0 ? -1 : read(fd, linker, sizeof linker);
        if (linker_size <= 0) return 82;
        close(fd);
        if (chdir(dir) || chmod(".", 0777)) return 83;
        umask(022);
        script_file("ld", (char *)linker, linker_size, 0755);
        /* The program headers, and its PT_INTERP. */
        uint64_t phoff;
        uint16_t phnum;
        memcpy(&phoff, image + 32, 8);
        memcpy(&phnum, image + 56, 2);
        unsigned char *interp = NULL;
        for (int i = 0; i < phnum; i++) {
            uint32_t kind;
            memcpy(&kind, image + phoff + 56 * i, 4);
            if (kind == 3) interp = image + phoff + 56 * i;
        }
        if (!interp) return 84;
        uint64_t path_offset, path_size;
        memcpy(&path_offset, interp + 8, 8);
        memcpy(&path_size, interp + 32, 8);
        char *show[] = {"./p", "dynamic-ids", NULL};
#define DYNAMIC_AS(label, name, size_given, offset_given, mode_given, uid) do { \
            static unsigned char patched[1 << 20]; \
            memcpy(patched, image, size); \
            memset(patched + path_offset, 0, path_size); \
            memcpy(patched + path_offset, name, strlen(name)); \
            uint64_t given_size = (size_given), given_offset = (offset_given); \
            memcpy(patched + (interp - image) + 32, &given_size, 8); \
            memcpy(patched + (interp - image) + 40, &given_size, 8); \
            memcpy(patched + (interp - image) + 8, &given_offset, 8); \
            script_file("p", (char *)patched, size, mode_given); \
            script_run(label, "./p", show, uid); \
        } while (0)
#define DYNAMIC(label, name) DYNAMIC_AS(label, name, path_size, path_offset, 0755, 0)
        DYNAMIC("relative", "./ld");
        DYNAMIC("absolute", "/lib/ld-musl-x86_64.so.1");
        /* The path. */
        DYNAMIC("missing", "./none");
        DYNAMIC_AS("too-short", "./ld", 1, path_offset, 0755, 0);
        DYNAMIC_AS("empty-path", "", 2, path_offset, 0755, 0);
        DYNAMIC_AS("too-long", "./ld", 4097, path_offset, 0755, 0);
        DYNAMIC_AS("not-terminated", "./ld", 4, path_offset, 0755, 0);
        DYNAMIC_AS("past-the-file", "./ld", 5, (uint64_t)size + 1000, 0755, 0);
        /* What it names. */
        if (mkdir("d", 0755)) return 85;
        DYNAMIC("directory", "./d");
        script_file("noexec", (char *)linker, linker_size, 0644);
        DYNAMIC_AS("not-executable-user", "./noexec", path_size, path_offset, 0755, 2000);
        DYNAMIC("not-executable-root", "./noexec");
        char text[256];
        memset(text, '#', sizeof text);
        script_file("text", text, sizeof text, 0755);
        DYNAMIC("text", "./text");
        script_file("short", "ab", 2, 0755);
        DYNAMIC("short", "./short");
        script_file("blank", "", 0, 0755);
        DYNAMIC("empty", "./blank");
        script_file("script", "#!./ld\n", 7, 0755);
        DYNAMIC("script", "./script");
        /* A program with an interpreter of its own, which does not count. */
        DYNAMIC("itself", "./p");
        /* Its permissions count, not its set-ID bits. */
        DYNAMIC_AS("user", "./ld", path_size, path_offset, 0755, 2000);
        script_file("no-read", (char *)linker, linker_size, 0111);
        DYNAMIC_AS("not-readable", "./no-read", path_size, path_offset, 0755, 2000);
        script_file("set-id", (char *)linker, linker_size, 0755);
        if (chown("set-id", 3000, 3000) || chmod("set-id", 06755)) return 86;
        DYNAMIC_AS("linker-set-id", "./set-id", path_size, path_offset, 0755, 2000);
        /* The program's do. */
        memcpy(image + path_offset, "./ld", 5);
        for (uint64_t i = 5; i < path_size; i++) image[path_offset + i] = 0;
        script_file("set", (char *)image, size, 0755);
        if (chown("set", 3000, 3000) || chmod("set", 06755)) return 87;
        char *set_args[] = {"./set", "dynamic-ids", NULL};
        script_run("program-set-id", "./set", set_args, 2000);
        script_file("set", (char *)image, size, 0111);
        script_run("program-not-readable", "./set", set_args, 2000);
        /* A script of it, and the linker run as a program. */
        script_file("set", (char *)image, size, 0755);
        script_file("s", "#!./set dynamic-ids\n", 20, 0755);
        char *script_args[] = {"./s", NULL};
        script_run("from-a-script", "./s", script_args, 0);
        char *direct[] = {"./ld", "./set", "dynamic-ids", NULL};
        script_run("linker-directly", "./ld", direct, 0);
        fflush(stdout);
        static const char *const files[] = {
            "ld", "p", "noexec", "text", "short", "blank", "script", "no-read", "set-id", "set", "s",
        };
        for (size_t i = 0; i < sizeof files / sizeof *files; i++) unlink(files[i]);
        if (rmdir("d") || chdir("/") || rmdir(dir)) return 89;
        return 0;
    }
    if (!strcmp(mode, "proc-maps")) return maps_cases(argv[2]);
    if (!strcmp(mode, "proc-maps-after-exec")) return maps_after_exec(argv[2]);
    if (!strcmp(mode, "robust-list")) return robust_list_cases(self);
    if (!strcmp(mode, "fifo")) return fifo_cases();
    if (!strcmp(mode, "proc-own-files")) return proc_own_files_cases(argc, argv);
    if (!strcmp(mode, "proc-other-files")) return proc_other_files_cases(self);
    if (!strcmp(mode, "proc-other-child") && argc >= 5) return proc_other_child(argv);
    if (!strcmp(mode, "late-handler")) return late_handler_cases();
    if (!strcmp(mode, "futex-shared")) return futex_shared_cases();
    if (!strcmp(mode, "robust-list-after-exec")) {
        void *head = (void *)1;
        size_t length = 0;
        long r = syscall(SYS_get_robust_list, 0, &head, &length);
        /* Its libc may have set one up; the case's own is gone either way. */
        return r == 0 && length == 24 ? 0 : 1;
    }
    if (!strcmp(mode, "mincore")) return mincore_cases();
    if (!strcmp(mode, "memory-locks")) return lock_cases();
    if (!strcmp(mode, "x87-arithmetic")) {
        x87_arithmetic_cases();
        return 0;
    }
    if (!strcmp(mode, "x87")) {
        x87_cases();
        /* A handler starts as after a reset, and returning brings it all back. */
        struct sigaction action = {0};
        action.sa_sigaction = x87_signal;
        action.sa_flags = SA_SIGINFO;
        sigaction(SIGUSR1, &action, NULL);
        uint32_t mxcsr = 0x3f80, seen = 0;
        unsigned char value[10];
        uint16_t control = 0x27f, seen_control = 0;
        __asm__ volatile("fninit\n fldcw %0\n ldmxcsr %1\n fld1" : : "m"(control), "m"(mxcsr));
        raise(SIGUSR1);
        __asm__ volatile("fnstcw %0\n stmxcsr %1\n fstpt %2" : "=m"(seen_control), "=m"(seen), "=m"(value));
        printf("returned: cw=%04x mxcsr=%x", seen_control, seen);
        x87_show(" st0", value, 10, x87_status());
        mxcsr = 0x1f80;
        __asm__ volatile("ldmxcsr %0" : : "m"(mxcsr));
        /* A child has it too. */
        __asm__ volatile("fninit\n fld1\n fldz");
        pid_t child = fork();
        if (!child) {
            __asm__ volatile("fstpt %0" : "=m"(value));
            x87_show("child st0", value, 10, x87_status());
            __asm__ volatile("fstpt %0" : "=m"(value));
            x87_show("child st1", value, 10, x87_status());
            fflush(stdout);
            _exit(0);
        }
        waitpid(child, NULL, 0);
        /* A fault changes nothing: the stack still has what could not go. */
        fflush(stdout);
        char *pages = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        struct sigaction faulting = {0};
        faulting.sa_sigaction = x87_fault;
        faulting.sa_flags = SA_SIGINFO;
        sigaction(SIGSEGV, &faulting, NULL);
        for (int k = 0; k < 4; k++) {
            child = fork();
            if (!child) {
                __asm__ volatile("fninit\n fld1\n fldz");
                if (k == 0) __asm__ volatile("fstpl %0" : "=m"(*(double *)pages));
                if (k == 1) __asm__ volatile("fstpt %0" : "=m"(*(unsigned char(*)[10])pages));
                if (k == 2) __asm__ volatile("fistpl %0" : "=m"(*(int *)pages));
                if (k == 3) __asm__ volatile("fldt %0" : : "m"(*(unsigned char(*)[10])(pages - 4096 * 4096)));
                _exit(70);
            }
            int fault_status = 0;
            waitpid(child, &fault_status, 0);
            printf("faulting %d: status=%d\n", k, fault_status);
            fflush(stdout);
        }
        return 0;
    }
    if (!strcmp(mode, "cpu-state")) {
        /* rdtsc and rdtscp: only 32 bits in each register, and it moves on. */
        uint64_t a1 = ~0ULL, d1 = ~0ULL, a2 = ~0ULL, d2 = ~0ULL, c2 = ~0ULL;
        __asm__ volatile("rdtsc" : "=a"(a1), "=d"(d1));
        __asm__ volatile("rdtsc" : "=a"(a2), "=d"(d2));
        printf("rdtsc: clean=%d %d moves=%d\n", a1 >> 32 == 0, d1 >> 32 == 0, (d2 << 32 | a2) > (d1 << 32 | a1));
        __asm__ volatile("rdtscp" : "=a"(a1), "=d"(d1), "=c"(c2));
        printf("rdtscp: clean=%d %d %d moves=%d\n", a1 >> 32 == 0, d1 >> 32 == 0, c2 >> 32 == 0,
               (d1 << 32 | a1) > (d2 << 32 | a2));
        /* rdssp without shadow stacks leaves its register. */
        uint64_t ssp = 0x1234567890abcdefULL;
        __asm__ volatile(".byte 0xf3, 0x48, 0x0f, 0x1e, 0xc8" : "+a"(ssp));
        printf("rdsspq: %llx\n", (unsigned long long)ssp);
        ssp = 0x1234567890abcdefULL;
        __asm__ volatile(".byte 0xf3, 0x0f, 0x1e, 0xc8" : "+a"(ssp));
        printf("rdsspd: %llx\n", (unsigned long long)ssp);
        /* fxsave: the x87 state as nothing has touched it, MXCSR and its mask,
           the XMM registers, and the rest of the area left alone. */
        static unsigned char in[256], out[256];
        static _Alignas(16) unsigned char area[1024];
        for (size_t i = 0; i < sizeof in; i++) in[i] = (unsigned char)(i * 7 + 1);
        for (int wide = 0; wide < 2; wide++) {
            memset(area, 0x55, sizeof area);
            uint32_t mxcsr = 0x1f80 | 0x20 | 0x8000, given = 0;
            __asm__ volatile("ldmxcsr %0" : : "m"(mxcsr));
            fx_save_from(in, area, wide);
            /* MXCSR's mask has bit 17 only where misaligned SSE can be turned
               on (AMD's), which is for CPUID to say; any other bit is compared. */
            unsigned leaf_a, leaf_b, leaf_c = 0, leaf_d;
            if (__get_cpuid(0x80000001, &leaf_a, &leaf_b, &leaf_c, &leaf_d) && (leaf_c & 1 << 7)) area[30] &= ~2;
            memcpy(&given, area + 24, 4);
            printf("fxsave %d: head", wide);
            for (int i = 0; i < 32; i++) printf(" %02x", area[i]);
            int x87 = 0, reserved = 0;
            for (int i = 32; i < 160; i++) x87 += area[i] != 0;
            for (int i = 464; i < 512; i++) reserved += area[i] != 0x55;
            printf("\n  mxcsr=%x x87-set=%d xmm-same=%d available-kept=%d beyond-kept=%d\n", given, x87,
                   !memcmp(area + 160, in, 256), reserved == 0, area[512] == 0x55);
            /* fxrstor: other registers and another MXCSR. */
            uint32_t other = 0x1f80 | 0x2000;
            memcpy(area + 24, &other, 4);
            for (int i = 0; i < 256; i++) area[160 + i] = (unsigned char)(i * 3 + 2);
            fx_restore_to(area, out, wide);
            uint32_t now = 0;
            __asm__ volatile("stmxcsr %0" : "=m"(now));
            int same = 1;
            for (int i = 0; i < 256; i++) same &= out[i] == (unsigned char)(i * 3 + 2);
            printf("fxrstor %d: mxcsr=%x xmm-same=%d\n", wide, now, same);
            mxcsr = 0x1f80;
            __asm__ volatile("ldmxcsr %0" : : "m"(mxcsr));
        }
        /* What it refuses. */
        /* The whole area must be there, though the end of it is not used. */
        char *pages = mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (pages == MAP_FAILED || mprotect(pages + 4096, 4096, PROT_NONE)) return 80;
        char *near_end = pages + 4096 - 416;
        for (int which = 0; which < 7; which++) {
            fflush(stdout);
            pid_t pid = child();
            if (pid == 0) {
                static _Alignas(16) unsigned char bad[1024];
                uint32_t reserved = 0x10000;
                switch (which) {
                case 0: __asm__ volatile("fxsave (%0)" : : "r"(bad + 8) : "memory"); break;
                case 1: __asm__ volatile("fxrstor (%0)" : : "r"(bad + 8)); break;
                case 2:
                    memcpy(bad + 24, &reserved, 4);
                    __asm__ volatile("fxrstor (%0)" : : "r"(bad));
                    break;
                case 3: __asm__ volatile("fxsave (%0)" : : "r"(16L) : "memory"); break;
                case 4: __asm__ volatile("fxsave (%0)" : : "r"(near_end) : "memory"); break;
                case 5: __asm__ volatile("fxrstor (%0)" : : "r"(near_end)); break;
                default: __asm__ volatile("fxrstor (%0)" : : "r"(16L)); break;
                }
                _exit(9);
            }
            int status = 0;
            waitpid(pid, &status, 0);
            printf("refused %d: status=%d\n", which, status);
        }
        return 0;
    }
    if (!strcmp(mode, "time-calls")) {
        /* The raw calls, which a C library would answer from its vDSO. */
        struct timespec before;
        struct { long seconds, micros; } tv = {-1, -1};
        struct { int minutes, dst; } tz = {-1, -1};
        clock_gettime(CLOCK_REALTIME, &before);
        long r = syscall(SYS_gettimeofday, &tv, &tz);
        printf("gettimeofday: %ld close=%d micros-ok=%d tz=%d,%d\n", r, tv.seconds - before.tv_sec <= 1 && tv.seconds >= before.tv_sec,
               tv.micros >= 0 && tv.micros < 1000000, tz.minutes, tz.dst);
        outcome("both-null", syscall(SYS_gettimeofday, NULL, NULL));
        outcome("tv-fault", syscall(SYS_gettimeofday, (void *)8, NULL));
        outcome("tz-fault", syscall(SYS_gettimeofday, NULL, (void *)8));
        long at = -1;
        long now = syscall(SYS_time, &at);
        printf("time: same=%d close=%d\n", now == at, now - before.tv_sec <= 1 && now >= before.tv_sec);
        printf("time-null: close=%d\n", syscall(SYS_time, NULL) - before.tv_sec <= 1);
        outcome("time-fault", syscall(SYS_time, (void *)8));
        return 0;
    }
    if (!strcmp(mode, "limit-permissions")) {
        int status = 0;
        /* A known start: the caller's limits and nice value are not. */
        if (limit_set(0, RLIMIT_NOFILE, 1024, 4096)) return 70;
        if (limit_set(0, RLIMIT_NICE, 0, 40)) return 71;
        if (setpriority(PRIO_PROCESS, 0, 10)) return 72;
        /* A process's own hard limit goes up only with CAP_SYS_RESOURCE. */
        AS_SENDER(2000, 2000, 2000, {
            permitted("hard-lower", limit_set(0, RLIMIT_NOFILE, 512, 2048));
            limit_show("after-lower", 0);
            permitted("soft-to-hard", limit_set(0, RLIMIT_NOFILE, 2048, 2048));
            permitted("hard-same", limit_set(0, RLIMIT_NOFILE, 1024, 2048));
            permitted("hard-raise", limit_set(0, RLIMIT_NOFILE, 1024, 2049));
            permitted("soft-above-hard-first", limit_set(0, RLIMIT_NOFILE, 2050, 2049));
            permitted("nr-open", limit_set(0, RLIMIT_NOFILE, 1024, 1UL << 40));
            limit_show("after-refused", 0);
            permitted("own-bad-resource", limit_read(0, 99));
            permitted("own-pid", limit_read(getpid(), RLIMIT_NOFILE));
        });
        AS_SENDER(0, 0, 0, {
            permitted("root-raise", limit_set(0, RLIMIT_NOFILE, 1024, 8192));
            limit_show("root-raised", 0);
        });
        AS_SENDER(0, 3000, 0, {
            permitted("no-capability-raise", limit_set(0, RLIMIT_NOFILE, 1024, 8192));
        });
        AS_SENDER(3000, 0, 3000, {
            permitted("effective-root-raise", limit_set(0, RLIMIT_NOFILE, 1024, 8192));
        });
        /* Another process's limits, to read or set, need all its IDs. */
        pid_t same = limit_target(2000, 2000, 2000, 0, 0, 0);
        pid_t euid = limit_target(2000, 3000, 2000, 0, 0, 0);
        pid_t suid = limit_target(2000, 2000, 3000, 0, 0, 0);
        pid_t ruid = limit_target(3000, 2000, 2000, 0, 0, 0);
        pid_t rgid = limit_target(2000, 2000, 2000, 3000, 0, 0);
        pid_t egid = limit_target(2000, 2000, 2000, 0, 3000, 0);
        pid_t sgid = limit_target(2000, 2000, 2000, 0, 0, 3000);
        pid_t gone = limit_target(3000, 3000, 3000, 0, 0, 0);
        kill(gone, SIGKILL);
        siginfo_t gone_info;
        waitid(P_PID, gone, &gone_info, WEXITED | WNOWAIT);
        AS_SENDER(2000, 2000, 2000, {
            permitted("read-same", limit_read(same, RLIMIT_NOFILE));
            permitted("read-euid", limit_read(euid, RLIMIT_NOFILE));
            permitted("read-suid", limit_read(suid, RLIMIT_NOFILE));
            permitted("read-ruid", limit_read(ruid, RLIMIT_NOFILE));
            permitted("read-rgid", limit_read(rgid, RLIMIT_NOFILE));
            permitted("read-egid", limit_read(egid, RLIMIT_NOFILE));
            permitted("read-sgid", limit_read(sgid, RLIMIT_NOFILE));
            permitted("read-zombie", limit_read(gone, RLIMIT_NOFILE));
            permitted("set-same", limit_set(same, RLIMIT_NOFILE, 256, 1024));
            permitted("set-same-raise", limit_set(same, RLIMIT_NOFILE, 256, 2048));
            permitted("set-euid", limit_set(euid, RLIMIT_NOFILE, 256, 1024));
            permitted("other-bad-resource", limit_read(euid, 99));
            permitted("same-bad-resource", limit_read(same, 99));
            permitted("missing", limit_read(0x3fffffff, RLIMIT_NOFILE));
            permitted("other-bad-new", syscall(SYS_prlimit64, euid, RLIMIT_NOFILE, (void *)1, NULL));
        });
        limit_show("same-after", same);
        limit_show("euid-after", euid);
        /* The sender's real IDs count, not its effective ones. */
        AS_SENDER(2000, 3000, 3000, {
            permitted("real-matches", limit_read(same, RLIMIT_NOFILE));
        });
        AS_SENDER(3000, 2000, 2000, {
            permitted("effective-matches", limit_read(same, RLIMIT_NOFILE));
        });
        AS_SENDER(0, 3000, 0, {
            permitted("no-capability-read", limit_read(same, RLIMIT_NOFILE));
        });
        permitted("root-zombie", limit_read(gone, RLIMIT_NOFILE));
        permitted("root-other", limit_set(euid, RLIMIT_NOFILE, 128, 8192));
        limit_show("root-set", euid);
        /* A process's own nice value: up freely, down within RLIMIT_NICE. */
        AS_SENDER(2000, 2000, 2000, {
            permitted("raise-own", setpriority(PRIO_PROCESS, 0, 12));
            permitted("same-own", setpriority(PRIO_PROCESS, 0, 12));
            permitted("lower-own", setpriority(PRIO_PROCESS, 0, 11));
            permitted("lower-clamped", setpriority(PRIO_PROCESS, 0, -1000));
            nice_show("own-nice", PRIO_PROCESS, 0);
            permitted("nice-limit", limit_set(0, RLIMIT_NICE, 25, 40));
            permitted("lower-in-limit", setpriority(PRIO_PROCESS, 0, -5));
            permitted("lower-past-limit", setpriority(PRIO_PROCESS, 0, -6));
            nice_show("own-nice-limited", PRIO_PROCESS, 0);
        });
        AS_SENDER(0, 0, 0, {
            permitted("root-lower", setpriority(PRIO_PROCESS, 0, -15));
            nice_show("root-nice", PRIO_PROCESS, 0);
        });
        AS_SENDER(0, 3000, 0, {
            permitted("no-capability-lower", setpriority(PRIO_PROCESS, 0, -15));
        });
        /* Another's: the effective ID against its real or effective one, and
           the limit is the target's. */
        pid_t only_saved = limit_target(3000, 3000, 2000, 0, 0, 0);
        permitted("target-limit", limit_set(same, RLIMIT_NICE, 30, 40));
        AS_SENDER(2000, 2000, 2000, {
            permitted("nice-same", setpriority(PRIO_PROCESS, same, 11));
            nice_show("same-nice", PRIO_PROCESS, same);
            permitted("nice-same-lower", setpriority(PRIO_PROCESS, same, -10));
            permitted("nice-same-past", setpriority(PRIO_PROCESS, same, -11));
            nice_show("same-lowered", PRIO_PROCESS, same);
            permitted("nice-target-real", setpriority(PRIO_PROCESS, euid, 11));
            permitted("nice-target-effective", setpriority(PRIO_PROCESS, ruid, 11));
            permitted("nice-target-saved", setpriority(PRIO_PROCESS, only_saved, 11));
            permitted("nice-refused-first", setpriority(PRIO_PROCESS, only_saved, 5));
            permitted("nice-zombie", setpriority(PRIO_PROCESS, gone, 11));
            nice_show("read-any", PRIO_PROCESS, only_saved);
        });
        AS_SENDER(2000, 3000, 3000, {
            permitted("nice-sender-real", setpriority(PRIO_PROCESS, same, 12));
            permitted("nice-sender-effective", setpriority(PRIO_PROCESS, only_saved, 12));
        });
        permitted("root-nice-other", setpriority(PRIO_PROCESS, only_saved, -5));
        nice_show("root-nice-set", PRIO_PROCESS, only_saved);
        /* PRIO_USER finds the real user ID. */
        pid_t user_a = limit_target(2100, 2100, 2100, 0, 0, 0);
        pid_t user_b = limit_target(2100, 3100, 2100, 0, 0, 0);
        pid_t user_c = limit_target(2200, 2100, 2200, 0, 0, 0);
        permitted("user-set", setpriority(PRIO_USER, 2100, 14));
        nice_show("user-a", PRIO_PROCESS, user_a);
        nice_show("user-b", PRIO_PROCESS, user_b);
        nice_show("user-c", PRIO_PROCESS, user_c);
        permitted("user-b-higher", setpriority(PRIO_PROCESS, user_b, 16));
        nice_show("user-highest", PRIO_USER, 2100);
        nice_show("user-effective-only", PRIO_USER, 3100);
        permitted("user-missing", setpriority(PRIO_USER, 3100, 14));
        AS_SENDER(2100, 2100, 2100, {
            permitted("user-own", setpriority(PRIO_USER, 0, 17));
            nice_show("user-own-nice", PRIO_USER, 0);
            nice_show("user-own-a", PRIO_PROCESS, user_a);
        });
        AS_SENDER(2300, 2300, 2300, {
            permitted("user-other", setpriority(PRIO_USER, 2100, 18));
        });
        /* A group: those it may change change, and the refusal is reported. */
        pid_t member_own = limit_target(2400, 2400, 2400, 0, 0, 0);
        pid_t member_other = limit_target(2500, 2500, 2500, 0, 0, 0);
        if (setpgid(member_own, member_own) || setpgid(member_other, member_own)) return 73;
        AS_SENDER(2400, 2400, 2400, {
            permitted("group-mixed", setpriority(PRIO_PGRP, member_own, 18));
        });
        nice_show("group-own", PRIO_PROCESS, member_own);
        nice_show("group-other", PRIO_PROCESS, member_other);
        AS_SENDER(2600, 2600, 2600, {
            permitted("group-none", setpriority(PRIO_PGRP, member_own, 17));
        });
        /* A thread's ID names its IDs, and the leader's are its own. */
        if (pipe(signal_thread_pipe)) return 74;
        fflush(stdout);
        pid_t threaded = child();
        if (threaded == 0) {
            pthread_t t;
            if (pthread_create(&t, NULL, signal_thread_with_ids, NULL)) _exit(75);
            for (;;) pause();
        }
        pid_t thread_id;
        if (read(signal_thread_pipe[0], &thread_id, sizeof thread_id) != sizeof thread_id) return 78;
        AS_SENDER(2000, 2000, 2000, {
            permitted("thread-id-limit", limit_read(thread_id, RLIMIT_NOFILE));
            permitted("thread-leader-limit", limit_read(threaded, RLIMIT_NOFILE));
            permitted("thread-id-nice", setpriority(PRIO_PROCESS, thread_id, 15));
            permitted("thread-leader-nice", setpriority(PRIO_PROCESS, threaded, 15));
        });
        signal_kill_reap(threaded);
        fflush(stdout);
        pid_t own_thread = child();
        if (own_thread == 0) {
            pthread_t t;
            if (pthread_create(&t, NULL, limit_thread, NULL)) _exit(79);
            pthread_join(t, NULL);
            fflush(stdout);
            _exit(0);
        }
        waitpid(own_thread, &status, 0);
        printf("own-thread: status=%d\n", status);
        pid_t others[] = {same, euid, suid, ruid, rgid, egid, sgid, only_saved, user_a,
                          user_b, user_c, member_own, member_other};
        for (unsigned i = 0; i < sizeof others / sizeof *others; i++) signal_kill_reap(others[i]);
        int gone_status = 0;
        waitpid(gone, &gone_status, 0);
        return 0;
    }
    if (!strcmp(mode, "proc-status")) {
        char value[128], link[32];
        umask(027);
        sigset_t set;
        sigemptyset(&set);
        sigaddset(&set, SIGUSR1);
        sigprocmask(SIG_BLOCK, &set, NULL);
        signal(SIGUSR2, SIG_IGN);
        signal(SIGHUP, interrupted);
        ssize_t n = readlink("/proc/self", link, sizeof link - 1);
        link[n > 0 ? n : 0] = 0;
        result("self-link", atoi(link) == getpid());
        struct stat st;
        result("self-dir", stat("/proc/self", &st) == 0 && S_ISDIR(st.st_mode));
        result("status-file", stat("/proc/self/status", &st) == 0 && S_ISREG(st.st_mode));
        /* Only fields that do not depend on the host user or limits. */
        const char *fields[] = {"Umask", "State", "Threads", "SigBlk", "SigIgn", "SigCgt", "TracerPid"};
        for (size_t i = 0; i < sizeof fields / sizeof *fields; i++) {
            if (status_field(fields[i], value, sizeof value)) strcpy(value, "missing");
            printf("%s=%s\n", fields[i], value);
        }
        status_field("Pid", value, sizeof value);
        result("pid", atoi(value) == getpid());
        status_field("PPid", value, sizeof value);
        result("ppid", atoi(value) == getppid());
        status_field("Tgid", value, sizeof value);
        result("tgid", atoi(value) == getpid());
        struct rusage usage;
        result("rusage-self", getrusage(RUSAGE_SELF, &usage));
        result("rusage-children", getrusage(RUSAGE_CHILDREN, &usage));
        result("rusage-thread", getrusage(1, &usage));
        errno = 0;
        result("rusage-who", getrusage(5, &usage));
        result("errno", errno);
        errno = 0;
        result("rusage-fault", syscall(SYS_getrusage, RUSAGE_SELF, (void *)1));
        result("errno", errno);
        return 0;
    }
    if (!strcmp(mode, "poll")) {
        int pipefd[2];
        pipe(pipefd);
        struct pollfd fds[3] = {{pipefd[0], POLLIN, 0}, {-1, POLLIN, 7}, {99, POLLIN, 0}};
        /* An empty pipe: the timeout passes; the other two entries still count. */
        result("timeout", poll(fds, 1, 20));
        result("revents", fds[0].revents);
        result("ignored-and-invalid", poll(fds + 1, 2, 20));
        result("negative", fds[1].revents);
        result("invalid", fds[2].revents);
        struct pollfd writable = {pipefd[1], POLLOUT, 0};
        result("writable", poll(&writable, 1, -1));
        result("revents", writable.revents);
        /* A child's write wakes a wait without a timeout. */
        pid_t pid = child();
        if (pid == 0) {
            write(pipefd[1], "x", 1);
            _exit(0);
        }
        result("woken", poll(fds, 1, -1));
        result("revents", fds[0].revents);
        finish(pid);
        char byte;
        read(pipefd[0], &byte, 1);
        /* After the writer closes, the read end hangs up. */
        close(pipefd[1]);
        result("hangup", poll(fds, 1, -1));
        result("revents", fds[0].revents);
        /* fd 0 replaced by an empty pipe is not ready. */
        int other[2];
        pipe(other);
        dup2(other[0], 0);
        struct pollfd input = {0, POLLIN, 0};
        result("stdin-pipe", poll(&input, 1, 0));
        /* A signal ends a wait without a timeout. */
        signal(SIGUSR1, interrupted);
        int stop[2];
        pipe(stop);
        pid = child();
        if (pid == 0) {
            close(stop[1]);
            fcntl(stop[0], F_SETFL, O_NONBLOCK);
            char none;
            while (read(stop[0], &none, 1) < 0) {
                kill(getppid(), SIGUSR1);
                sched_yield();
            }
            _exit(0);
        }
        errno = 0;
        result("interrupted", poll(&input, 1, -1));
        result("errno", errno);
        write(stop[1], "x", 1);
        finish(pid);
        return 0;
    }
    if (!strcmp(mode, "pipe-size")) {
        /* brush sizes the pipe of a here-doc to its text. */
        int pipefd[2];
        pipe(pipefd);
        result("default", fcntl(pipefd[0], F_GETPIPE_SZ));
        result("one-page", fcntl(pipefd[1], F_SETPIPE_SZ, 5));
        result("other-end", fcntl(pipefd[0], F_GETPIPE_SZ));
        result("rounded", fcntl(pipefd[0], F_SETPIPE_SZ, 5000));
        fcntl(pipefd[1], F_SETFL, O_NONBLOCK);
        static char bytes[10000];
        result("partial", write(pipefd[1], bytes, sizeof bytes));
        errno = 0;
        result("full", write(pipefd[1], bytes, 1));
        result("errno", errno);
        errno = 0;
        result("busy", fcntl(pipefd[0], F_SETPIPE_SZ, 4096));
        result("errno", errno);
        result("drain", read(pipefd[0], bytes, sizeof bytes));
        result("shrink", fcntl(pipefd[0], F_SETPIPE_SZ, 4096));
        result("grow", fcntl(pipefd[0], F_SETPIPE_SZ, 1 << 20));
        errno = 0;
        result("too-large", fcntl(pipefd[0], F_SETPIPE_SZ, (1U << 31) + 1));
        result("errno", errno);
        int null = open("/dev/null", O_RDONLY);
        errno = 0;
        result("not-a-pipe", fcntl(null, F_GETPIPE_SZ));
        result("errno", errno);
        return 0;
    }
    if (!strcmp(mode, "cpu-clocks")) {
        /* CPU time itself differs from host to host; its rules do not. */
        struct timespec a, b, res;
        result("thread", clock_gettime(CLOCK_THREAD_CPUTIME_ID, &a));
        result("process", clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &b));
        result("ordered", b.tv_sec > a.tv_sec || (b.tv_sec == a.tv_sec && b.tv_nsec >= a.tv_nsec));
        result("valid", a.tv_nsec >= 0 && a.tv_nsec < 1000000000 && b.tv_nsec < 1000000000);
        result("monotone", clock_gettime(CLOCK_THREAD_CPUTIME_ID, &b) == 0
            && (b.tv_sec > a.tv_sec || (b.tv_sec == a.tv_sec && b.tv_nsec >= a.tv_nsec)));
        for (int id = 2; id <= 3; id++) {
            result("res", clock_getres(id, &res));
            result("res-ns", res.tv_sec * 1000000000L + res.tv_nsec);
        }
        int clocks[] = {CLOCK_MONOTONIC_RAW, CLOCK_REALTIME_COARSE, CLOCK_MONOTONIC_COARSE, CLOCK_BOOTTIME};
        for (size_t i = 0; i < sizeof clocks / sizeof *clocks; i++)
            result("other-clock", clock_gettime(clocks[i], &a));
        errno = 0;
        result("unknown", clock_gettime(10, &a));
        result("errno", errno);
        errno = 0;
        /* 10 was CLOCK_SGI_CYCLE: no kernel has it; 16 on are auxiliary clocks now. */
        result("unknown-res", clock_getres(10, &res));
        result("errno", errno);
        result("res-null", clock_getres(CLOCK_PROCESS_CPUTIME_ID, NULL));
        struct rusage usage;
        result("rusage", getrusage(RUSAGE_SELF, &usage));
        result("rusage-valid", usage.ru_utime.tv_usec < 1000000 && usage.ru_stime.tv_usec < 1000000);
        /* A child's time joins the children's once it is waited for. */
        pid_t pid = child();
        if (pid == 0) _exit(0);
        int status;
        struct rusage reaped;
        result("wait4", wait4(pid, &status, 0, &reaped) == pid);
        result("wait4-valid", reaped.ru_utime.tv_usec < 1000000);
        result("children", getrusage(RUSAGE_CHILDREN, &usage));
        struct tms tms;
        result("times", times(&tms) != (clock_t)-1);
        result("times-null", times(NULL) != (clock_t)-1);
        errno = 0;
        result("times-fault", syscall(SYS_times, (void *)1));
        result("errno", errno);
        return 0;
    }
    if (!strcmp(mode, "pdeathsig")) {
        /* A grandchild asks for SIGUSR1 when its parent exits, then waits. */
        int report[2];
        if (pipe(report)) return 81;
        pid_t middle = child();
        if (middle == 0) {
            int ready[2];
            if (pipe(ready)) _exit(82);
            fflush(stdout);
            pid_t grandchild = child();
            if (grandchild == 0) {
                sigset_t set;
                sigemptyset(&set);
                sigaddset(&set, SIGUSR1);
                sigprocmask(SIG_BLOCK, &set, NULL);
                prctl(PR_SET_PDEATHSIG, SIGUSR1);
                char byte = 'r';
                if (write(ready[1], &byte, 1) != 1) _exit(83);
                /* No timeout: the emulated harness runs a virtual clock, so a
                   bounded wait could end before the parent exits. The
                   harness's own watchdog bounds the run instead. */
                byte = sigwaitinfo(&set, NULL) == SIGUSR1 ? 'y' : 'n';
                if (write(report[1], &byte, 1) != 1) _exit(84);
                _exit(0);
            }
            char byte;
            if (read(ready[0], &byte, 1) != 1) _exit(85);
            _exit(0);
        }
        finish(middle);
        close(report[1]);
        char byte = 0;
        result("report", read(report[0], &byte, 1));
        result("signalled", byte == 'y');
        return 0;
    }
    if (!strcmp(mode, "statfs")) {
        /* Native /tmp is some real filesystem and the emulated one a tmpfs:
           only relations every filesystem keeps are compared. */
        struct statfs by_path, by_fd;
        result("statfs", statfs("/tmp", &by_path));
        result("block-size", by_path.f_bsize > 0);
        result("ordered", by_path.f_blocks >= by_path.f_bfree && by_path.f_bfree >= by_path.f_bavail);
        result("name-max", by_path.f_namelen);
        int fd = open("/tmp", O_RDONLY | O_DIRECTORY);
        result("fstatfs", fstatfs(fd, &by_fd));
        result("same-fs", by_fd.f_type == by_path.f_type && by_fd.f_bsize == by_path.f_bsize);
        close(fd);
        int pair[2];
        if (pipe(pair)) return 81;
        result("pipe", fstatfs(pair[0], &by_fd) == 0 && by_fd.f_type == 0x50495045);
        errno = 0;
        result("missing", statfs("/tmp/paludarium-processes-missing", &by_path));
        result("errno", errno);
        errno = 0;
        result("fault", syscall(SYS_statfs, "/tmp", (void *)1));
        result("errno", errno);
        errno = 0;
        result("bad-fd", fstatfs(99, &by_fd));
        result("errno", errno);
        /* The mount tables list the root, as regular files nobody may write. */
        const char *tables[] = {"/proc/self/mountinfo", "/proc/self/mounts", "/proc/mounts"};
        for (int t = 0; t < 3; t++) {
            FILE *table = fopen(tables[t], "r");
            char line[1024], first[256], second[256], third[256], fourth[256], fifth[256];
            int root = 0;
            while (table && fgets(line, sizeof line, table)) {
                if (t == 0 && sscanf(line, "%255s %255s %255s %255s %255s", first, second, third, fourth, fifth) == 5)
                    root |= !strcmp(fifth, "/");
                if (t > 0 && sscanf(line, "%255s %255s", first, second) == 2)
                    root |= !strcmp(second, "/");
            }
            if (table) fclose(table);
            result("root-listed", root);
            struct stat st;
            /* Opening one for writing is EACCES for a user and allowed for
               root, so it is not compared. */
            result("regular", stat(tables[t], &st) == 0 && S_ISREG(st.st_mode) && (st.st_mode & 07777) == 0444);
        }
        return 0;
    }
    if (!strcmp(mode, "no-child")) {
        int status;
        errno = 0;
        result("wait", waitpid(-1, &status, 0));
        result("errno", errno);
        return 0;
    }
    if (!strcmp(mode, "invalid-clone")) {
        errno = 0;
        result("clone", syscall(SYS_clone, 0x10000|SIGCHLD, 0, 0, 0, 0));
        result("errno", errno);
        return 0;
    }
    if (!strcmp(mode, "invalid-wait")) {
        errno = 0;
        result("wait", syscall(SYS_wait4, -1, 0, 0x10, 0));
        result("errno", errno);
        return 0;
    }
    int sync[2];
    if (pipe(sync)) return 97;
    volatile int private_value = 11;
    int *shared = mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
    if (shared == MAP_FAILED) return 96;
    *shared = 13;
    int fd = -1;
    if (!strcmp(mode, "offset") || !strcmp(mode, "cloexec")) {
        fd = open("/tmp/paludarium-offset", O_CREAT|O_TRUNC|O_RDWR, 0600);
        if (fd < 0 || write(fd, "abc", 3) != 3 || lseek(fd, 0, SEEK_SET)) return 95;
        unlink("/tmp/paludarium-offset");
        if (!strcmp(mode, "cloexec")) {
            if (dup2(fd, 9) != 9 || dup2(fd, 10) != 10 || fcntl(9, F_SETFD, FD_CLOEXEC)) return 94;
        }
    }
    fflush(NULL);
    pid_t parent = getpid();
    if (!strcmp(mode, "wait-interrupt") || !strcmp(mode, "wait-restart")) {
        int restart = !strcmp(mode, "wait-restart");
        struct sigaction action = {0};
        action.sa_handler = restart ? wait_signalled : interrupted;
        action.sa_flags = restart ? SA_RESTART : 0;
        sigaction(SIGUSR1, &action, NULL);
        /* The child signals until the parent answers, so that a signal
           finds the parent waiting however the two are scheduled: without
           SA_RESTART the parent answers once waitpid fails, with it the
           handler answers once the parent waits, and the child exits. */
        int answer[2];
        if (pipe(answer)) return 79;
        fcntl(answer[0], F_SETFL, O_NONBLOCK);
        wait_answer = answer[1];
        pid_t pid = child();
        if (pid < 0) return 78;
        if (!pid) {
            char b;
            while (read(answer[0], &b, 1) != 1) {
                kill(parent, SIGUSR1);
                usleep(10000);
            }
            _exit(5);
        }
        int status = 0;
        errno = 0;
        wait_started = 1;
        pid_t waited = waitpid(pid, &status, 0);
        int error = errno;
        if (!restart && write(answer[1], "a", 1) != 1) return 77;
        result("signal", received >= 1);
        result("interrupted", waited == -1 && error == EINTR);
        /* A signal the child sent before it read the answer may still
           come. */
        while (waited == -1 && (waited = waitpid(pid, &status, 0)) == -1 && errno == EINTR) {}
        result("wait", waited == pid);
        result("status", status);
        return 0;
    }
    int vf = !strcmp(mode, "vfork-exec") || !strcmp(mode, "vfork-exit");
    pid_t pid = vf ? vfork() : child();
    if (pid < 0) return 93;
    if (!pid) {
        if (!strcmp(mode, "vfork-exit")) _exit(9);
        if (!strcmp(mode, "exec") || !strcmp(mode, "vfork-exec") || !strcmp(mode, "cloexec")) {
            char *args[] = { "process", !strcmp(mode, "cloexec") ? "fd-child" : "child", (char *)self, "argument", NULL };
            char *env[] = { "PROCESSES_VALUE=value", NULL };
            execve(self, args, env);
            _exit(92);
        }
        if (!strcmp(mode, "signal")) { kill(getpid(), SIGTERM); _exit(91); }
        if (!strcmp(mode, "fork")) {
            char ok = getpid() != parent && getppid() == parent;
            if (write(sync[1], &ok, 1) != 1) _exit(90);
        } else if (!strcmp(mode, "offset")) {
            char b;
            if (read(fd, &b, 1) != 1 || b != 'a') _exit(89);
        } else if (!strcmp(mode, "wnohang")) {
            char b;
            if (read(sync[0], &b, 1) != 1) _exit(88);
        }
        private_value = 17;
        *shared = 19;
        _exit(3);
    }
    if (!strcmp(mode, "fork")) {
        char ok = 0;
        if (read(sync[0], &ok, 1) != 1) return 87;
        result("relations", ok);
    }
    if (!strcmp(mode, "wnohang")) {
        int status = 0x1234;
        result("pending", waitpid(pid, &status, WNOHANG));
        result("unchanged", status == 0x1234);
        if (write(sync[1], "x", 1) != 1) return 86;
    }
    if (!strcmp(mode, "wait-fault")) {
        errno = 0;
        result("wait-fault", syscall(SYS_wait4, pid, (void *)1, 0, 0));
        result("errno", errno);
        errno = 0;
        result("after-fault", waitpid(pid, NULL, 0));
        result("after-errno", errno);
    } else if (!strcmp(mode, "usage")) {
        int status;
        struct rusage usage;
        memset(&usage, 0xff, sizeof usage);
        result("wait", wait4(pid, &status, 0, &usage) == pid);
        result("status", status);
        result("usage", usage.ru_utime.tv_sec >= 0 && usage.ru_utime.tv_usec >= 0 && usage.ru_utime.tv_usec < 1000000 && usage.ru_stime.tv_sec >= 0 && usage.ru_stime.tv_usec >= 0 && usage.ru_stime.tv_usec < 1000000);
    } else if (!strcmp(mode, "wait-any")) {
        int status;
        result("wait", waitpid(-1, &status, 0) == pid);
        result("status", status);
    } else finish(pid);
    if (!strcmp(mode, "private")) result("private", private_value == 11);
    if (!strcmp(mode, "shared")) result("shared", *shared == 19);
    if (!strcmp(mode, "offset")) {
        char b;
        result("offset", read(fd, &b, 1) == 1 && b == 'b');
    }
    if (!strcmp(mode, "double-reap")) {
        errno = 0;
        result("again", waitpid(pid, NULL, 0));
        result("errno", errno);
    }
    return 0;
}
