#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
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
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/vfs.h>
#include <sys/prctl.h>
#include <sys/time.h>
#include <time.h>
#include <sys/socket.h>
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
/* The return value of a call and its errno. */
static void outcome(const char *name, long value) {
    printf("%s=%ld errno=%d\n", name, value, value < 0 ? errno : 0);
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
/* socket-timestamp: the option numbers, as x86-64 Linux has them. */
#define TS_OLD 29
#define TS_NS_OLD 35
#define TS_NEW 63
#define TS_NS_NEW 64
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
/* signal-io-wait: takes the pending signals of a stream whose peer shut
   its sending down or closed while its reader waited, and says only
   whether they are at most one signal of `code` and `band` for `fd`.
   Linux's unix_shutdown and unix_release_sock wake the reader
   (sk_state_change) before they look at SOCKWQ_ASYNC_WAITDATA
   (sk_wake_async), so a reader that runs at once has cleared it and is
   signalled, and one that does not is not: either is Linux, and nothing
   else is. */
static void io_at_most_one(const char *name, int fd, const char *what, int code, long band) {
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGIO);
    sigaddset(&set, SIGURG);
    sigaddset(&set, IO_RT);
    struct timespec zero = {0, 0};
    siginfo_t info;
    int number, count = 0, other = 0;
    while ((number = sigtimedwait(&set, &info, &zero)) > 0) {
        count++;
        other |= number != IO_RT || info.si_code != code || info.si_band != band || info.si_fd != fd;
    }
    printf("  %s: at-most-one-%s=%d\n", name, what, count <= 1 && !other);
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
static void finish(pid_t pid) {
    int status = 0;
    result("wait", waitpid(pid, &status, 0) == pid);
    result("status", status);
}
int main(int argc, char **argv) {
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
    if (!strcmp(mode, "session")) {
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
           gets none for the data that ends the wait (Linux's
           SOCKWQ_ASYNC_WAITDATA), and at most one POLL_IN for the peer's
           shutdown and one POLL_HUP for its close (io_at_most_one), where
           a datagram or packet socket still signals. A send that found
           the buffer full signals POLL_OUT only once three quarters of it
           is free. A pipe write signals its reader before each wait. A
           reader's child acts after a while (io_pause). */
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
                   and the signal is due, so the attempt is taken again. */
                struct pollfd ready = {sv[1], POLLIN | POLLRDHUP, 0};
                int early = poll(&ready, 1, 0) != 0;
                long r = recv(sv[1], buf, sizeof buf, 0);
                char name[32];
                snprintf(name, sizeof name, "%s-%s=%ld", type_names[t], actions[a], r);
                if (a == 2) waitpid(forked, &status, 0);
                else if (read(acted[0], buf, 1) != 1) return 72;
                if (early && ++tries < 10) io_count(0);
                else if (types[t] == SOCK_STREAM && a == 1) io_at_most_one(name, sv[1], "in", POLL_IN, 0x41);
                else if (types[t] == SOCK_STREAM && a == 2) io_at_most_one(name, sv[1], "hang-up", POLL_HUP, 0x18);
                else io_taken(name);
                close(sv[1]);
                if (a != 2) {
                    if (write(go[1], "g", 1) != 1) return 78;
                    waitpid(forked, &status, 0);
                }
                if (status) return 73;
                if (a != 2) close(sv[0]);
                close(go[0]); close(go[1]); close(acted[0]); close(acted[1]);
                if (early && tries < 10) a--;
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
           waits for the hang-up. */
        signal(SIGPIPE, SIG_IGN);
        int s[2], u[2], pipe_fds[2];
        char byte;
        socketpair(AF_UNIX, SOCK_STREAM, 0, s);
        printf("send-self=%ld\n", send_fds(s[0], "x", 1, &s[1], 1));
        close(s[1]);
        usleep(200000);
        gc_state("self-closed", s[0]);
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
        gc_state("cycle-a", s[0]);
        gc_state("cycle-pipe", pipe_fds[0]);
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
