/* TCP client sockets against the differential test's local server, and
 * the guest's own servers on the loopback (the "listen" modes).
 *
 *   network <mode> <open-port> <closed-port> [<own-path>]
 *
 * The server (crates/paludarium-harness/tests/diff_network.rs) listens on
 * 127.0.0.1:<open-port> and reads one command byte per connection:
 *   'e' echoes everything until the end of input, then closes;
 *   'c' closes at once;
 *   'b' sends 1 MiB of a pattern, then closes;
 *   'w' reads until the end of input, sends "bye", then closes.
 * Nothing listens on <closed-port>; <own-path> is where the program is, for
 * the modes that run it again. Only what native Linux and the
 * emulator share is printed: never the client's own port, nor the ports
 * the guest's servers take. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef SIOCOUTQ
#define SIOCOUTQ TIOCOUTQ
#endif

static int open_port, closed_port;

static struct sockaddr_in to(int port) {
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(port)};
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    return a;
}
static int tcp(int flags) { return socket(AF_INET, SOCK_STREAM | flags, 0); }
static int connected(char command) {
    int fd = tcp(0);
    if (fd < 0) {
        printf("socket failed errno=%d\n", errno);
        exit(71);
    }
    struct sockaddr_in a = to(open_port);
    if (connect(fd, (void *)&a, sizeof a)) {
        printf("connect failed errno=%d\n", errno);
        exit(70);
    }
    if (command) send(fd, &command, 1, 0);
    return fd;
}
/* The events among `events` poll reports for `fd`, waiting up to 5 s. */
static void polled(const char *name, int fd, short events) {
    struct pollfd p = {.fd = fd, .events = events};
    int n = poll(&p, 1, 5000);
    printf("  %s poll=%d revents=%#x\n", name, n, (unsigned)p.revents);
}
/* Waits for the end of input, which the peer's close or shutdown sends. */
static void await_end(int fd) {
    struct pollfd p = {.fd = fd, .events = POLLRDHUP};
    poll(&p, 1, 5000);
}
static void option(const char *name, int fd, int level, int opt) {
    int value = -7;
    socklen_t len = sizeof value;
    errno = 0;
    int r = getsockopt(fd, level, opt, &value, &len);
    printf("  %s=%d errno=%d value=%d len=%u\n", name, r, errno, value, (unsigned)len);
}
static void set_option(const char *name, int fd, int level, int opt, int value) {
    errno = 0;
    int r = setsockopt(fd, level, opt, &value, sizeof value);
    int e = errno;
    int got = -7;
    socklen_t len = sizeof got;
    getsockopt(fd, level, opt, &got, &len);
    printf("  set %s=%d errno=%d got=%d\n", name, r, e, got);
}
static void call(const char *name, int r) { printf("  %s=%d errno=%d\n", name, r, r < 0 ? errno : 0); }
static void print_bytes(const char *name, const char *buf, long n) {
    printf("  %s=%ld \"%.*s\"\n", name, n, n > 0 ? (int)n : 0, buf);
}
/* async: takes the signal-driven I/O signals of a step, and prints each
   different one as it comes (data may come in several pieces). */
static void signals(const char *step) {
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, 40);
    siginfo_t info;
    int last_code = 0;
    long last_band = 0;
    /* Linux wakes a poll before it sends the signal (tcp_fin calls
       sk_state_change, then sk_wake_async), so a signal may follow the
       poll that saw its event. Every step has one: the first is awaited
       for up to 5 s, the rest until none comes for 200 ms. */
    struct timespec first = {5, 0}, settle = {0, 200000000};
    printf("  %s:", step);
    for (const struct timespec *wait = &first; sigtimedwait(&set, &info, wait) == 40; wait = &settle) {
        if (info.si_code == last_code && info.si_band == last_band) continue;
        last_code = info.si_code;
        last_band = info.si_band;
        printf(" code=%d band=%#lx fd-ok=%d", info.si_code, info.si_band, info.si_fd >= 3);
    }
    putchar('\n');
}
static int async_socket(void) {
    int fd = tcp(SOCK_NONBLOCK);
    fcntl(fd, F_SETOWN, getpid());
    fcntl(fd, F_SETSIG, 40);
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_ASYNC);
    return fd;
}
/* The events among `events` poll reports for `fd` now. */
static void ready(const char *name, int fd, short events) {
    struct pollfd p = {.fd = fd, .events = events};
    int n = poll(&p, 1, 0);
    printf("  %s poll=%d revents=%#x\n", name, n, (unsigned)p.revents);
}
/* A TCP socket listening with `backlog` on 127.0.0.1, at a port it takes,
   which `port` gets. */
static int listener(int backlog, int *port) {
    int fd = tcp(0);
    struct sockaddr_in a = to(0);
    if (bind(fd, (void *)&a, sizeof a) || listen(fd, backlog)) {
        printf("listen failed errno=%d\n", errno);
        exit(69);
    }
    socklen_t len = sizeof a;
    getsockname(fd, (void *)&a, &len);
    *port = ntohs(a.sin_port);
    return fd;
}
/* A TCP socket connecting to `port` on 127.0.0.1; its connect's result goes
   to `result`. */
static int client(int port, int flags, int *result) {
    int fd = tcp(flags);
    struct sockaddr_in a = to(port);
    errno = 0;
    *result = connect(fd, (void *)&a, sizeof a) ? errno : 0;
    return fd;
}
static void bind_to(const char *name, int fd, in_addr_t addr, int port) {
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(port)};
    a.sin_addr.s_addr = addr;
    call(name, bind(fd, (void *)&a, sizeof a));
}
static int port_of(int fd) {
    struct sockaddr_in6 a;
    socklen_t len = sizeof a;
    getsockname(fd, (void *)&a, &len);
    return ntohs(a.sin6_port);
}
/* Milliseconds on the monotonic clock. */
static long now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000 + t.tv_nsec / 1000000;
}
/* Waits up to `limit` ms for `fd` to finish connecting, and prints how it
   ended and the nearest whole second after `start` (Linux's timers run a
   little late). */
static void finished(const char *name, int fd, long start, int limit) {
    struct pollfd p = {.fd = fd, .events = POLLOUT};
    int n = poll(&p, 1, limit);
    int error = 0;
    socklen_t len = sizeof error;
    getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len);
    printf("  %s poll=%d revents=%#x error=%d second=%ld\n", name, n, (unsigned)p.revents, error,
           (now_ms() - start + 500) / 1000);
}
static volatile sig_atomic_t pipes;
static void on_pipe(int signal) { (void)signal; pipes++; }
static volatile sig_atomic_t urgs;
static void on_urg(int signal) { (void)signal; urgs++; }
/* A loopback connection to `port`, accepted from `l`: the server's side is
   nonblocking and owned by this process, for SIGURG. */
static void urgent_pair(int l, int port, int *c, int *s) {
    int result;
    *c = client(port, 0, &result);
    *s = accept(l, NULL, NULL);
    fcntl(*s, F_SETFL, O_NONBLOCK);
    fcntl(*s, F_SETOWN, getpid());
}
/* What an urgent byte shows: POLLIN and POLLPRI, SIOCATMARK, FIONREAD and
   the SIGURGs so far. */
static void urgent_state(const char *name, int fd) {
    struct pollfd p = {.fd = fd, .events = POLLIN | POLLPRI};
    poll(&p, 1, 0);
    int mark = -1, inq = -1;
    ioctl(fd, SIOCATMARK, &mark);
    ioctl(fd, FIONREAD, &inq);
    printf("  %s revents=%#x atmark=%d inq=%d urgs=%d\n", name, (unsigned)p.revents, mark, inq,
           (int)urgs);
}
static void urgent_read(const char *name, int fd, int len, int flags) {
    char b[64];
    errno = 0;
    long r = recv(fd, b, len, flags);
    printf("  %s r=%ld errno=%d data=%.*s\n", name, r, r < 0 ? errno : 0, r > 0 ? (int)r : 0, b);
}
/* Sends from `fd` until neither its buffer nor the peer's takes more, looking
   again after a pause, as the loopback's acknowledgments can trail the send
   that found no room. Returns how many bytes went. */
static long fill(int fd) {
    static char chunk[65536];
    long total = 0, n;
    for (;;) {
        long sent = 0;
        while ((n = send(fd, chunk, sizeof chunk, MSG_DONTWAIT)) > 0) sent += n;
        if (!sent && total) return total;
        total += sent;
        usleep(50000);
    }
}
/* Reads `fd` to its end, waiting up to 5 seconds for each part. Returns how
   many bytes came. */
static long drain(int fd) {
    static char chunk[65536];
    struct pollfd p = {.fd = fd, .events = POLLIN};
    long total = 0, n;
    while (poll(&p, 1, 5000) > 0 && (n = recv(fd, chunk, sizeof chunk, 0)) > 0) total += n;
    return total;
}
/* The whole seconds since `start`, to the nearest. */
static long seconds_since(long start) { return (now_ms() - start + 500) / 1000; }
/* The peer a thread drains after 300 ms, with the bytes it is to get. */
static int drained_fd;
static long drained_expected;
static void *drain_later(void *arg) {
    (void)arg;
    usleep(300000);
    return (void *)(long)(drain(drained_fd) == drained_expected);
}
static volatile sig_atomic_t alarms;
static void on_alarm(int signal) { (void)signal; alarms++; }

int main(int argc, char **argv) {
    if (argc < 4) return 99;
    const char *mode = argv[1];
    open_port = atoi(argv[2]);
    closed_port = atoi(argv[3]);
    setvbuf(stdout, NULL, _IONBF, 0);
    char buf[256];
    long n;

    if (!strcmp(mode, "unconnected")) {
        /* A TCP socket that never connected, and its options. */
        int fd = tcp(0);
        call("recv", recv(fd, buf, sizeof buf, MSG_DONTWAIT));
        call("send", send(fd, "x", 1, MSG_NOSIGNAL));
        polled("fresh", fd, POLLIN | POLLOUT | POLLRDHUP);
        struct sockaddr_in a;
        socklen_t len = sizeof a;
        call("getpeername", getpeername(fd, (void *)&a, &len));
        memset(&a, 0x55, sizeof a);
        len = sizeof a;
        call("getsockname", getsockname(fd, (void *)&a, &len));
        printf("  family=%d port=%d addr=%#x len=%u\n", a.sin_family, ntohs(a.sin_port),
               ntohl(a.sin_addr.s_addr), (unsigned)len);
        call("shutdown", shutdown(fd, SHUT_WR));
        call("shutdown-bad", shutdown(fd, 7));
        call("accept", accept(fd, NULL, NULL));
        struct sockaddr_in any = {.sin_family = AF_INET};
        call("bind-0", bind(fd, (void *)&any, sizeof any));
        option("type", fd, SOL_SOCKET, SO_TYPE);
        option("domain", fd, SOL_SOCKET, SO_DOMAIN);
        option("protocol", fd, SOL_SOCKET, SO_PROTOCOL);
        option("error", fd, SOL_SOCKET, SO_ERROR);
        option("acceptconn", fd, SOL_SOCKET, SO_ACCEPTCONN);
        option("nodelay", fd, IPPROTO_TCP, TCP_NODELAY);
        set_option("nodelay", fd, IPPROTO_TCP, TCP_NODELAY, 1);
        option("keepalive", fd, SOL_SOCKET, SO_KEEPALIVE);
        set_option("keepalive", fd, SOL_SOCKET, SO_KEEPALIVE, 5);
        set_option("reuseaddr", fd, SOL_SOCKET, SO_REUSEADDR, 1);
        option("keepidle", fd, IPPROTO_TCP, TCP_KEEPIDLE);
        option("keepintvl", fd, IPPROTO_TCP, TCP_KEEPINTVL);
        option("keepcnt", fd, IPPROTO_TCP, TCP_KEEPCNT);
        set_option("keepidle", fd, IPPROTO_TCP, TCP_KEEPIDLE, 60);
        set_option("keepidle-0", fd, IPPROTO_TCP, TCP_KEEPIDLE, 0);
        set_option("keepintvl", fd, IPPROTO_TCP, TCP_KEEPINTVL, 10);
        set_option("keepcnt", fd, IPPROTO_TCP, TCP_KEEPCNT, 3);
        set_option("keepcnt-200", fd, IPPROTO_TCP, TCP_KEEPCNT, 200);
        option("unknown", fd, SOL_SOCKET, 9999);
        option("tcp-unknown", fd, IPPROTO_TCP, 9999);
        char small = 0;
        errno = 0;
        n = setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &small, 1);
        printf("  short-option=%ld errno=%d\n", n, errno);
        struct sockaddr_in6 six = {.sin6_family = AF_INET6};
        call("connect-family", connect(fd, (void *)&six, sizeof six));
        a = to(open_port);
        call("connect-short", connect(fd, (void *)&a, 8));
        close(fd);
        puts("kinds");
        call("udp-as-tcp", socket(AF_INET, SOCK_STREAM, IPPROTO_UDP));
        call("bad-flags", socket(AF_INET, SOCK_STREAM | 0x100000, 0));
        int u = socket(AF_INET, SOCK_DGRAM, 0);
        option("udp-type", u, SOL_SOCKET, SO_TYPE);
        option("udp-protocol", u, SOL_SOCKET, SO_PROTOCOL);
        option("udp-nodelay", u, IPPROTO_TCP, TCP_NODELAY);
        set_option("udp-nodelay", u, IPPROTO_TCP, TCP_NODELAY, 1);
        option("udp-unknown", u, IPPROTO_UDP, 9999);
        int six_fd = socket(AF_INET6, SOCK_STREAM, 0);
        option("v6-domain", six_fd, SOL_SOCKET, SO_DOMAIN);
        option("v6only", six_fd, IPPROTO_IPV6, IPV6_V6ONLY);
        set_option("v6-tos", six_fd, IPPROTO_IP, IP_TOS, 0x10);
        option("v4-v6only", u, IPPROTO_IPV6, IPV6_V6ONLY);
        close(six_fd);
        close(u);
        return 0;
    }
    if (!strcmp(mode, "stream")) {
        /* A blocking connection: addresses, echo, half-close, end. */
        int fd = connected('e');
        struct sockaddr_in a;
        socklen_t len = sizeof a;
        call("getpeername", getpeername(fd, (void *)&a, &len));
        printf("  family=%d port-ok=%d addr=%#x len=%u\n", a.sin_family,
               ntohs(a.sin_port) == open_port, ntohl(a.sin_addr.s_addr), (unsigned)len);
        len = sizeof a;
        call("getsockname", getsockname(fd, (void *)&a, &len));
        printf("  family=%d addr=%#x has-port=%d len=%u\n", a.sin_family, ntohl(a.sin_addr.s_addr),
               a.sin_port != 0, (unsigned)len);
        a = to(open_port);
        call("connect-again", connect(fd, (void *)&a, sizeof a));
        polled("writable", fd, POLLOUT);
        call("send", send(fd, "hello", 5, 0));
        call("write", write(fd, " world", 6));
        call("shutdown", shutdown(fd, SHUT_WR));
        await_end(fd);
        int queued = -1;
        call("fionread", ioctl(fd, FIONREAD, &queued));
        printf("  queued=%d\n", queued);
        n = recv(fd, buf, 2, MSG_PEEK);
        print_bytes("peek", buf, n);
        n = recv(fd, buf, 11, MSG_WAITALL);
        print_bytes("waitall", buf, n);
        call("end", recv(fd, buf, sizeof buf, 0));
        polled("ended", fd, POLLIN | POLLOUT | POLLRDHUP);
        signal(SIGPIPE, on_pipe);
        call("send-after-shutdown", send(fd, "x", 1, 0));
        printf("  sigpipes=%d\n", (int)pipes);
        call("send-nosignal", send(fd, "x", 1, MSG_NOSIGNAL));
        printf("  sigpipes=%d\n", (int)pipes);
        close(fd);
        return 0;
    }
    if (!strcmp(mode, "nonblocking")) {
        /* connect with O_NONBLOCK: EINPROGRESS, POLLOUT, SO_ERROR, then
           EALREADY's successor 0 and EISCONN. */
        int fd = tcp(SOCK_NONBLOCK);
        struct sockaddr_in a = to(open_port);
        call("connect", connect(fd, (void *)&a, sizeof a));
        polled("connecting", fd, POLLOUT);
        option("error", fd, SOL_SOCKET, SO_ERROR);
        call("connect-2", connect(fd, (void *)&a, sizeof a));
        call("connect-3", connect(fd, (void *)&a, sizeof a));
        call("recv-empty", recv(fd, buf, sizeof buf, 0));
        call("send-command", send(fd, "c", 1, 0));
        await_end(fd);
        polled("closed-by-peer", fd, POLLIN | POLLOUT | POLLRDHUP);
        call("recv-end", recv(fd, buf, sizeof buf, 0));
        close(fd);
        /* select and epoll see a connection become writable, then
           readable. */
        fd = tcp(SOCK_NONBLOCK);
        connect(fd, (void *)&a, sizeof a);
        fd_set writable;
        FD_ZERO(&writable);
        FD_SET(fd, &writable);
        struct timeval wait = {5, 0};
        n = select(fd + 1, NULL, &writable, NULL, &wait);
        printf("  select=%ld writable=%d\n", n, FD_ISSET(fd, &writable));
        int ep = epoll_create1(0);
        struct epoll_event e = {.events = EPOLLIN, .data.fd = fd}, got;
        epoll_ctl(ep, EPOLL_CTL_ADD, fd, &e);
        call("epoll-idle", epoll_wait(ep, &got, 1, 0));
        send(fd, "e", 1, 0);
        send(fd, "ping", 4, 0);
        n = epoll_wait(ep, &got, 1, 5000);
        printf("  epoll=%ld events=%#x\n", n, got.events);
        n = recv(fd, buf, sizeof buf, 0);
        print_bytes("recv", buf, n);
        call("recv-again", recv(fd, buf, sizeof buf, 0));
        close(ep);
        close(fd);
        return 0;
    }
    if (!strcmp(mode, "refused")) {
        /* Nothing listens: a blocking connect fails at once; a nonblocking
           one reports the error through poll and SO_ERROR, once. */
        int fd = tcp(0);
        struct sockaddr_in a = to(closed_port);
        call("connect", connect(fd, (void *)&a, sizeof a));
        option("error", fd, SOL_SOCKET, SO_ERROR);
        polled("after", fd, POLLIN | POLLOUT | POLLRDHUP);
        call("recv", recv(fd, buf, sizeof buf, MSG_DONTWAIT));
        close(fd);
        fd = tcp(SOCK_NONBLOCK);
        call("connect-nonblocking", connect(fd, (void *)&a, sizeof a));
        polled("failed", fd, POLLIN | POLLOUT | POLLRDHUP);
        option("error", fd, SOL_SOCKET, SO_ERROR);
        option("error-again", fd, SOL_SOCKET, SO_ERROR);
        polled("taken", fd, POLLIN | POLLOUT | POLLRDHUP);
        call("connect-again", connect(fd, (void *)&a, sizeof a));
        call("recv", recv(fd, buf, sizeof buf, 0));
        call("send", send(fd, "x", 1, MSG_NOSIGNAL));
        close(fd);
        return 0;
    }
    if (!strcmp(mode, "bulk")) {
        /* 1 MiB from the server, more than either side buffers, read in
           pieces of every size. */
        int fd = connected('b');
        unsigned long total = 0, sum = 0, wrong = 0;
        static char big[70000];
        size_t want = 1;
        while ((n = read(fd, big, want)) > 0) {
            for (long i = 0; i < n; i++, total++) {
                unsigned char expected = (unsigned char)(total * 7 + 3);
                if ((unsigned char)big[i] != expected) wrong++;
                sum += (unsigned char)big[i];
            }
            want = want * 3 % sizeof big + 1;
        }
        printf("  read=%ld total=%lu sum=%lu wrong=%lu\n", n, total, sum, wrong);
        close(fd);
        /* And 1 MiB to an echoing server, written while it echoes back. */
        fd = connected('e');
        int flags = fcntl(fd, F_GETFL);
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
        unsigned long sent = 0, back = 0;
        int shut = 0;
        while (back < 1 << 20) {
            struct pollfd p = {.fd = fd, .events = POLLIN | (sent < 1 << 20 ? POLLOUT : 0)};
            if (poll(&p, 1, 5000) <= 0) break;
            if (p.revents & POLLOUT) {
                size_t len = sizeof big;
                if (len > (1 << 20) - sent) len = (1 << 20) - sent;
                for (size_t i = 0; i < len; i++) big[i] = (char)(sent + i);
                n = send(fd, big, len, 0);
                if (n > 0) sent += n;
            }
            if (sent == 1 << 20 && !shut) shut = !shutdown(fd, SHUT_WR);
            if (p.revents & POLLIN) {
                char in[4096];
                n = recv(fd, in, sizeof in, 0);
                if (n <= 0) break;
                for (long i = 0; i < n; i++, back++)
                    if (in[i] != (char)back) wrong++;
            }
        }
        printf("  sent=%lu back=%lu wrong=%lu shut=%d\n", sent, back, wrong, shut);
        close(fd);
        return 0;
    }
    if (!strcmp(mode, "half")) {
        /* The server answers only once this side shuts its sending down. */
        int fd = connected('w');
        call("send", send(fd, "abc", 3, 0));
        call("shutdown", shutdown(fd, SHUT_WR));
        await_end(fd);
        n = read(fd, buf, sizeof buf);
        print_bytes("read", buf, n);
        call("end", read(fd, buf, sizeof buf));
        polled("both-shut", fd, POLLIN | POLLOUT | POLLRDHUP);
        call("shutdown-read", shutdown(fd, SHUT_RD));
        close(fd);
        /* SHUT_RD: what came stays readable, then reads end. */
        fd = connected('e');
        send(fd, "xy", 2, 0);
        polled("echoed", fd, POLLIN);
        call("shutdown-read", shutdown(fd, SHUT_RD));
        polled("read-shut", fd, POLLIN | POLLRDHUP);
        call("read-after", read(fd, buf, sizeof buf));
        close(fd);
        return 0;
    }
    if (!strcmp(mode, "mapped")) {
        /* An IPv6 socket reaches 127.0.0.1 as ::ffff:127.0.0.1. */
        int fd = socket(AF_INET6, SOCK_STREAM, 0);
        struct sockaddr_in6 a = {.sin6_family = AF_INET6, .sin6_port = htons(open_port)};
        inet_pton(AF_INET6, "::ffff:127.0.0.1", &a.sin6_addr);
        call("connect", connect(fd, (void *)&a, sizeof a));
        struct sockaddr_in6 peer;
        socklen_t len = sizeof peer;
        call("getpeername", getpeername(fd, (void *)&peer, &len));
        char text[64];
        inet_ntop(AF_INET6, &peer.sin6_addr, text, sizeof text);
        printf("  family=%d addr=%s port-ok=%d len=%u\n", peer.sin6_family, text,
               ntohs(peer.sin6_port) == open_port, (unsigned)len);
        len = sizeof peer;
        getsockname(fd, (void *)&peer, &len);
        inet_ntop(AF_INET6, &peer.sin6_addr, text, sizeof text);
        printf("  local family=%d addr=%s len=%u\n", peer.sin6_family, text, (unsigned)len);
        send(fd, "e", 1, 0);
        struct msghdr m = {0};
        struct iovec parts[2] = {{"ab", 2}, {"cd", 2}};
        m.msg_iov = parts;
        m.msg_iovlen = 2;
        call("sendmsg", sendmsg(fd, &m, 0));
        shutdown(fd, SHUT_WR);
        await_end(fd);
        char first[4] = {0}, second[8] = {0};
        struct iovec into[2] = {{first, 3}, {second, sizeof second - 1}};
        struct sockaddr_in6 from;
        memset(&from, 0x55, sizeof from);
        m.msg_iov = into;
        m.msg_name = &from;
        m.msg_namelen = sizeof from;
        call("recvmsg", recvmsg(fd, &m, 0));
        printf("  first=%s second=%s namelen=%u flags=%#x\n", first, second, (unsigned)m.msg_namelen,
               (unsigned)m.msg_flags);
        socklen_t fromlen = sizeof from;
        call("recvfrom-end", recvfrom(fd, buf, sizeof buf, 0, (void *)&from, &fromlen));
        printf("  fromlen=%u\n", (unsigned)fromlen);
        close(fd);
        return 0;
    }
    if (!strcmp(mode, "async")) {
        /* O_ASYNC with F_SETSIG: POLL_OUT once connected, POLL_IN for
           data, POLL_HUP for the peer's end after this side's, POLL_ERR
           for a refused connection. */
        sigset_t set;
        sigemptyset(&set);
        sigaddset(&set, 40);
        sigprocmask(SIG_BLOCK, &set, NULL);
        int fd = async_socket();
        printf("  async=%d\n", !!(fcntl(fd, F_GETFL) & O_ASYNC));
        struct sockaddr_in a = to(open_port);
        call("connect", connect(fd, (void *)&a, sizeof a));
        polled("connected", fd, POLLOUT);
        signals("connected");
        send(fd, "eping", 5, 0);
        polled("echoed", fd, POLLIN);
        signals("echoed");
        n = recv(fd, buf, sizeof buf, 0);
        print_bytes("recv", buf, n);
        shutdown(fd, SHUT_WR);
        await_end(fd);
        signals("ended");
        close(fd);
        fd = async_socket();
        a = to(closed_port);
        call("connect-refused", connect(fd, (void *)&a, sizeof a));
        polled("refused", fd, POLLOUT);
        signals("refused");
        close(fd);
        return 0;
    }
    if (!strcmp(mode, "dns-tcp")) {
        /* DNS over TCP, as a resolver asks after a truncated answer: a
           query for localhost's A record, framed with its length, to port
           53. Run under the emulator only, as resolve is. */
        int fd = tcp(0);
        struct sockaddr_in a = to(53);
        call("connect", connect(fd, (void *)&a, sizeof a));
        unsigned char q[64] = {0, 0, 0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 9};
        memcpy(q + 15, "localhost", 9);
        unsigned char tail[] = {0, 0, 1, 0, 1};
        memcpy(q + 24, tail, sizeof tail);
        int len = 24 + (int)sizeof tail;
        q[1] = (unsigned char)(len - 2);
        call("send", send(fd, q, len, 0));
        unsigned char reply[512];
        n = recv(fd, reply, 2, MSG_WAITALL);
        int size = n == 2 ? reply[0] << 8 | reply[1] : -1;
        n = size > 0 ? recv(fd, reply, size, MSG_WAITALL) : -1;
        printf("  answer=%d whole=%d id=%d rcode=%d answers=%d last=%d.%d.%d.%d\n", n > 0, n == size,
               n > 3 && reply[0] == 0x12 && reply[1] == 0x34, n > 3 ? reply[3] & 15 : -1, n > 7 ? reply[7] : -1,
               n > 3 ? reply[n - 4] : -1, n > 3 ? reply[n - 3] : -1, n > 3 ? reply[n - 2] : -1,
               n > 3 ? reply[n - 1] : -1);
        call("shutdown", shutdown(fd, SHUT_WR));
        call("end", recv(fd, reply, sizeof reply, 0));
        close(fd);
        return 0;
    }
    if (!strcmp(mode, "listen")) {
        /* A server on the loopback: bind, listen, a blocking connect the
           queue takes before accept, accept's address, bytes both ways and
           the ends, and what a listener answers. */
        int l = tcp(0);
        option("acceptconn", l, SOL_SOCKET, SO_ACCEPTCONN);
        struct sockaddr_in a = to(0);
        call("bind", bind(l, (void *)&a, sizeof a));
        socklen_t len = sizeof a;
        getsockname(l, (void *)&a, &len);
        int port = ntohs(a.sin_port);
        printf("  bound family=%d addr=%#x port-ok=%d\n", a.sin_family, ntohl(a.sin_addr.s_addr), port != 0);
        call("listen", listen(l, 4));
        option("acceptconn", l, SOL_SOCKET, SO_ACCEPTCONN);
        ready("idle", l, POLLIN | POLLOUT | POLLRDHUP);
        fcntl(l, F_SETOWN, getpid());
        fcntl(l, F_SETSIG, 40);
        fcntl(l, F_SETFL, fcntl(l, F_GETFL) | O_ASYNC);
        int ep = epoll_create1(0);
        struct epoll_event ev = {.events = EPOLLIN | EPOLLET};
        epoll_ctl(ep, EPOLL_CTL_ADD, l, &ev);
        sigset_t set;
        sigemptyset(&set);
        sigaddset(&set, 40);
        sigprocmask(SIG_BLOCK, &set, NULL);
        int result;
        int c = client(port, 0, &result);
        printf("  connect errno=%d\n", result);
        signals("arrival");
        printf("  epoll=%d\n", epoll_wait(ep, &ev, 1, 5000));
        printf("  epoll-again=%d\n", epoll_wait(ep, &ev, 1, 0));
        ready("queued", l, POLLIN | POLLOUT | POLLRDHUP);
        struct sockaddr_in peer, mine;
        len = sizeof peer;
        int s = accept4(l, (void *)&peer, &len, SOCK_CLOEXEC);
        printf("  accept-ok=%d len=%u cloexec=%d nonblock=%d\n", s >= 0, (unsigned)len,
               fcntl(s, F_GETFD) & FD_CLOEXEC, (fcntl(s, F_GETFL) & O_NONBLOCK) != 0);
        len = sizeof mine;
        getsockname(c, (void *)&mine, &len);
        printf("  peer-is-client=%d family=%d addr=%#x\n",
               peer.sin_port == mine.sin_port && peer.sin_addr.s_addr == mine.sin_addr.s_addr,
               peer.sin_family, ntohl(peer.sin_addr.s_addr));
        len = sizeof mine;
        getsockname(s, (void *)&mine, &len);
        printf("  server port-ok=%d addr=%#x\n", ntohs(mine.sin_port) == port, ntohl(mine.sin_addr.s_addr));
        len = sizeof peer;
        call("client-getpeername", getpeername(c, (void *)&peer, &len));
        printf("  client peer port-ok=%d addr=%#x\n", ntohs(peer.sin_port) == port, ntohl(peer.sin_addr.s_addr));
        option("server-acceptconn", s, SOL_SOCKET, SO_ACCEPTCONN);
        option("server-error", s, SOL_SOCKET, SO_ERROR);
        ready("drained", l, POLLIN);
        ready("server", s, POLLIN | POLLOUT | POLLRDHUP);
        call("send", send(c, "hello", 5, 0));
        polled("server-data", s, POLLIN | POLLOUT | POLLRDHUP);
        int queued = -1;
        ioctl(s, FIONREAD, &queued);
        printf("  fionread=%d\n", queued);
        n = recv(s, buf, sizeof buf, 0);
        print_bytes("recv", buf, n);
        call("send-back", send(s, "world!", 6, 0));
        polled("client-data", c, POLLIN);
        n = recv(c, buf, sizeof buf, 0);
        print_bytes("client-recv", buf, n);
        call("shutdown", shutdown(c, SHUT_WR));
        await_end(s);
        ready("server-end", s, POLLIN | POLLOUT | POLLRDHUP);
        call("server-eof", recv(s, buf, sizeof buf, 0));
        call("server-send-after", send(s, "late", 4, 0));
        polled("client-late", c, POLLIN);
        n = recv(c, buf, sizeof buf, 0);
        print_bytes("client-late", buf, n);
        close(s);
        await_end(c);
        call("client-eof", recv(c, buf, sizeof buf, 0));
        ready("client-closed", c, POLLIN | POLLOUT | POLLRDHUP);
        len = sizeof peer;
        call("client-getpeername-closed", getpeername(c, (void *)&peer, &len));
        close(c);
        call("listener-fionread", ioctl(l, FIONREAD, &queued));
        call("listener-recv", recv(l, buf, 1, MSG_DONTWAIT));
        call("listener-send", send(l, "x", 1, MSG_NOSIGNAL));
        call("listener-connect", connect(l, (void *)&a, sizeof a));
        len = sizeof peer;
        call("listener-getpeername", getpeername(l, (void *)&peer, &len));
        call("listen-again", listen(l, 8));
        call("shutdown-wr", shutdown(l, SHUT_WR));
        option("still-listening", l, SOL_SOCKET, SO_ACCEPTCONN);
        call("shutdown-rd", shutdown(l, SHUT_RD));
        option("after-shutdown", l, SOL_SOCKET, SO_ACCEPTCONN);
        call("accept-after", accept(l, NULL, NULL));
        c = client(port, 0, &result);
        printf("  connect-after errno=%d\n", result);
        close(c);
        call("listen-anew", listen(l, 1));
        printf("  anew port-ok=%d\n", port_of(l) != 0);
        close(l);
        close(ep);
        return 0;
    }
    if (!strcmp(mode, "listen-errors")) {
        /* What bind, listen and accept refuse, as Linux checks them. */
        int port;
        int l = listener(1, &port);
        int b = tcp(0);
        bind_to("bind-in-use", b, htonl(INADDR_LOOPBACK), port);
        bind_to("bind-any-in-use", b, htonl(INADDR_ANY), port);
        set_option("reuseaddr", b, SOL_SOCKET, SO_REUSEADDR, 1);
        bind_to("bind-reuse-beside-listener", b, htonl(INADDR_LOOPBACK), port);
        bind_to("bind-foreign", b, inet_addr("192.0.2.1"), 0);
        struct sockaddr_in a = to(0);
        call("bind-short", bind(b, (void *)&a, 8));
        struct sockaddr_in6 six = {.sin6_family = AF_INET6};
        call("bind-family", bind(b, (void *)&six, sizeof six));
        struct sockaddr_in unspec = {.sin_family = AF_UNSPEC};
        call("bind-unspec-any", bind(b, (void *)&unspec, sizeof unspec));
        printf("  unspec port-ok=%d\n", port_of(b) != 0);
        call("bind-twice", bind(b, (void *)&a, sizeof a));
        int other = tcp(0);
        unspec.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        call("bind-unspec-address", bind(other, (void *)&unspec, sizeof unspec));
        /* Two sockets with SO_REUSEADDR share a port until one listens. */
        int r1 = tcp(0), r2 = tcp(0), r3 = tcp(0);
        set_option("reuse-1", r1, SOL_SOCKET, SO_REUSEADDR, 1);
        set_option("reuse-2", r2, SOL_SOCKET, SO_REUSEADDR, 1);
        bind_to("reuse-bind-1", r1, htonl(INADDR_LOOPBACK), 0);
        int shared = port_of(r1);
        bind_to("reuse-bind-2", r2, htonl(INADDR_LOOPBACK), shared);
        bind_to("no-reuse-bind", r3, htonl(INADDR_LOOPBACK), shared);
        call("reuse-listen-1", listen(r1, 1));
        call("reuse-listen-2", listen(r2, 1));
        /* Another loopback address is another place for the same port. */
        bind_to("other-address", r3, inet_addr("127.0.0.2"), port);
        call("accept-not-listening", accept(r3, NULL, NULL));
        call("accept4-flags", accept4(l, NULL, NULL, 1));
        /* The port of a socket bound but not listening refuses. */
        int result;
        int refused = client(port_of(b), 0, &result);
        printf("  connect-bound-only errno=%d\n", result);
        close(refused);
        refused = client(port_of(b), SOCK_NONBLOCK, &result);
        printf("  connect-bound-only-nonblocking errno=%d\n", result);
        polled("refused", refused, POLLIN | POLLOUT | POLLRDHUP);
        option("refused-error", refused, SOL_SOCKET, SO_ERROR);
        call("refused-connect-again", connect(refused, (void *)&a, sizeof a));
        close(refused);
        /* A connected socket does not listen; a listener's accept waits
           for SO_RCVTIMEO, and a nonblocking one does not wait. */
        int c = client(port, 0, &result);
        printf("  connect errno=%d\n", result);
        call("listen-connected", listen(c, 1));
        int s = accept(l, NULL, NULL);
        printf("  accept-ok=%d\n", s >= 0);
        struct timeval tv = {0, 100000};
        setsockopt(l, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        call("accept-timeout", accept(l, NULL, NULL));
        fcntl(l, F_SETFL, O_NONBLOCK);
        call("accept-nonblocking", accept(l, NULL, NULL));
        /* A full queue (backlog 1 holds two): the next connection is
           dropped and tried again, after accept makes room. (Backlog
           0 would leave Linux's first one to SYN cookies.) */
        int q;
        int full = listener(1, &q);
        int first = client(q, SOCK_NONBLOCK, &result);
        printf("  first errno=%d\n", result);
        polled("first", first, POLLOUT);
        int second = client(q, SOCK_NONBLOCK, &result);
        printf("  second errno=%d\n", result);
        polled("second", second, POLLOUT);
        int third = client(q, SOCK_NONBLOCK, &result);
        printf("  third errno=%d\n", result);
        ready("third-waiting", third, POLLIN | POLLOUT);
        call("third-again", connect(third, (void *)&a, sizeof a) ? -1 : 0);
        int got = accept(full, NULL, NULL);
        printf("  accept-first-ok=%d\n", got >= 0);
        polled("third-after-accept", third, POLLOUT);
        option("third-error", third, SOL_SOCKET, SO_ERROR);
        for (int i = 0; i < 2; i++) {
            got = accept(full, NULL, NULL);
            printf("  accept-next-ok=%d\n", got >= 0);
        }
        /* UDP neither listens nor accepts. */
        int u = socket(AF_INET, SOCK_DGRAM, 0);
        call("udp-listen", listen(u, 1));
        call("udp-accept", accept(u, NULL, NULL));
        return 0;
    }
    if (!strcmp(mode, "listen-full")) {
        /* A full queue (backlog 1 holds two) drops the handshake, and the
           client sends it again 1, 2, 3, 4, 5, 7… seconds later
           (tcp_syn_linear_timeouts): room made in between takes it only at
           the next try, a listener gone by then refuses it, and another
           listening there by then takes it. */
        int port, result;
        int l = listener(1, &port);
        client(port, SOCK_NONBLOCK, &result);
        client(port, SOCK_NONBLOCK, &result);
        long start = now_ms();
        int c = client(port, SOCK_NONBLOCK, &result);
        printf("  dropped errno=%d\n", result);
        ready("dropped", c, POLLOUT);
        poll(NULL, 0, 300);
        printf("  accept-ok=%d\n", accept(l, NULL, NULL) >= 0);
        ready("room-made", c, POLLOUT);
        finished("first-try", c, start, 3000);
        ready("listener", l, POLLIN);
        close(l);
        l = listener(1, &port);
        client(port, SOCK_NONBLOCK, &result);
        client(port, SOCK_NONBLOCK, &result);
        start = now_ms();
        c = client(port, SOCK_NONBLOCK, &result);
        poll(NULL, 0, 1500);
        accept(l, NULL, NULL);
        finished("second-try", c, start, 3000);
        close(l);
        l = listener(1, &port);
        client(port, SOCK_NONBLOCK, &result);
        client(port, SOCK_NONBLOCK, &result);
        start = now_ms();
        c = client(port, SOCK_NONBLOCK, &result);
        poll(NULL, 0, 200);
        close(l);
        ready("listener-gone", c, POLLOUT);
        finished("refused", c, start, 3000);
        l = listener(1, &port);
        client(port, SOCK_NONBLOCK, &result);
        client(port, SOCK_NONBLOCK, &result);
        start = now_ms();
        c = client(port, SOCK_NONBLOCK, &result);
        poll(NULL, 0, 200);
        close(l);
        int again = tcp(0), one = 1;
        setsockopt(again, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
        bind_to("listen-again", again, htonl(INADDR_LOOPBACK), port);
        call("listen-again", listen(again, 4));
        finished("taken-by-another", c, start, 3000);
        /* A blocking connect waits only as long as SO_SNDTIMEO, then is in
           progress. */
        close(again);
        l = listener(1, &port);
        client(port, SOCK_NONBLOCK, &result);
        client(port, SOCK_NONBLOCK, &result);
        c = tcp(0);
        struct timeval tv = {0, 300000};
        setsockopt(c, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
        struct sockaddr_in a = to(port);
        call("blocking", connect(c, (void *)&a, sizeof a));
        call("blocking-again", connect(c, (void *)&a, sizeof a));
        return 0;
    }
    if (!strcmp(mode, "listen-time-wait")) {
        /* The side that closes a loopback connection first keeps its port in
           TIME_WAIT: a bind there is EADDRINUSE, with SO_REUSEADDR too
           unless the closed socket had it, while the side that closed
           second keeps nothing. A reset leaves nothing held. */
        int port, result, one = 1;
        int l = listener(8, &port);
        int c = client(port, 0, &result);
        int s = accept(l, NULL, NULL);
        int client_port = port_of(c);
        close(c);
        await_end(s);
        close(s);
        int t = tcp(0);
        bind_to("client-first", t, htonl(INADDR_LOOPBACK), client_port);
        close(t);
        t = tcp(0);
        setsockopt(t, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
        bind_to("client-first-reuse", t, htonl(INADDR_LOOPBACK), client_port);
        close(t);
        t = tcp(0);
        bind_to("client-first-any", t, htonl(INADDR_ANY), client_port);
        close(t);
        /* The client closes first while the server stays open: held too,
           until the server's send is answered with a reset. */
        c = client(port, 0, &result);
        s = accept(l, NULL, NULL);
        int open_port = port_of(c);
        close(c);
        await_end(s);
        t = tcp(0);
        bind_to("peer-open", t, htonl(INADDR_LOOPBACK), open_port);
        call("send-to-closed", send(s, "x", 1, MSG_NOSIGNAL));
        polled("answered", s, POLLERR);
        bind_to("after-reset", t, htonl(INADDR_LOOPBACK), open_port);
        close(t);
        close(s);
        /* Closed with bytes the server has no room for yet: held while they
           go, then in TIME_WAIT once read to the end; or freed by the reset
           of a server that closes with them unread. */
        static char lots[4096];
        for (int drained = 1; drained >= 0; drained--) {
            c = client(port, 0, &result);
            s = accept(l, NULL, NULL);
            int full_port = port_of(c);
            while (send(c, lots, sizeof lots, MSG_DONTWAIT) > 0) {}
            close(c);
            t = tcp(0);
            bind_to(drained ? "pending" : "pending-again", t, htonl(INADDR_LOOPBACK), full_port);
            if (drained)
                while (recv(s, lots, sizeof lots, 0) > 0) {}
            close(s);
            poll(NULL, 0, 100);
            if (drained) {
                bind_to("drained", t, htonl(INADDR_LOOPBACK), full_port);
            } else {
                /* Linux's loopback hands the reset to the client in its own
                   time, which a busy machine can put off past 100 ms: look
                   again for up to 5 seconds before the port counts as held. */
                struct sockaddr_in a = to(full_port);
                int r;
                for (int tries = 0; (r = bind(t, (void *)&a, sizeof a)) && tries < 50; tries++)
                    poll(NULL, 0, 100);
                call("unread-reset", r);
            }
            close(t);
        }
        /* Closed with input unread: a reset, and nothing held. */
        c = client(port, 0, &result);
        s = accept(l, NULL, NULL);
        int unread_port = port_of(c);
        send(s, "x", 1, 0);
        polled("unread", c, POLLIN);
        close(c);
        polled("reset", s, POLLERR);
        close(s);
        t = tcp(0);
        bind_to("after-unread", t, htonl(INADDR_LOOPBACK), unread_port);
        close(t);
        close(l);
        /* The server closes first: the listener's port is held, and only a
           socket with SO_REUSEADDR shares it, as the closed one had it. */
        l = tcp(0);
        setsockopt(l, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
        struct sockaddr_in any = to(0);
        bind(l, (void *)&any, sizeof any);
        listen(l, 8);
        port = port_of(l);
        c = client(port, 0, &result);
        s = accept(l, NULL, NULL);
        close(s);
        await_end(c);
        close(c);
        close(l);
        t = tcp(0);
        bind_to("server-first", t, htonl(INADDR_LOOPBACK), port);
        close(t);
        t = tcp(0);
        setsockopt(t, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
        bind_to("server-first-reuse", t, htonl(INADDR_LOOPBACK), port);
        call("server-first-listen", listen(t, 1));
        close(t);
        return 0;
    }
    if (!strcmp(mode, "listen-reuseport")) {
        /* Sockets sharing a port with SO_REUSEPORT share its connections
           and datagrams by a hash of the addresses (reuseport_select_sock).
           Which one gets each hangs on Linux's secret, so only the counts
           are printed: each takes some of 64, and none once it leaves. */
        int one = 1, result, port = 0;
        int l[2], u[2];
        for (int i = 0; i < 2; i++) {
            l[i] = tcp(SOCK_NONBLOCK);
            setsockopt(l[i], SOL_SOCKET, SO_REUSEPORT, &one, sizeof one);
            bind_to("bind", l[i], htonl(INADDR_LOOPBACK), port);
            call("listen", listen(l[i], 128));
            port = port_of(l[i]);
        }
        int counts[2] = {0, 0};
        for (int i = 0; i < 64; i++) {
            close(client(port, 0, &result));
            if (result) printf("  connect errno=%d\n", result);
        }
        for (int i = 0; i < 2; i++) {
            int s;
            while ((s = accept(l[i], NULL, NULL)) >= 0) {
                counts[i]++;
                close(s);
            }
        }
        printf("  tcp total=%d shared=%d\n", counts[0] + counts[1], counts[0] > 0 && counts[1] > 0);
        close(l[0]);
        counts[1] = 0;
        for (int i = 0; i < 16; i++) close(client(port, 0, &result));
        for (int s; (s = accept(l[1], NULL, NULL)) >= 0; counts[1]++) close(s);
        printf("  tcp after-close=%d\n", counts[1]);
        close(l[1]);

        port = 0;
        for (int i = 0; i < 2; i++) {
            u[i] = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
            setsockopt(u[i], SOL_SOCKET, SO_REUSEPORT, &one, sizeof one);
            bind_to("bind-udp", u[i], htonl(INADDR_LOOPBACK), port);
            port = port_of(u[i]);
        }
        struct sockaddr_in at = to(port);
        int senders[64];
        for (int i = 0; i < 64; i++) {
            senders[i] = socket(AF_INET, SOCK_DGRAM, 0);
            sendto(senders[i], "x", 1, 0, (void *)&at, sizeof at);
        }
        counts[0] = counts[1] = 0;
        for (int i = 0; i < 2; i++)
            while (recv(u[i], buf, sizeof buf, 0) >= 0) counts[i]++;
        printf("  udp total=%d shared=%d\n", counts[0] + counts[1], counts[0] > 0 && counts[1] > 0);
        /* A connected one takes only its peer's: the rest go to the other. */
        struct sockaddr_in peer = to(port_of(senders[0]));
        call("connect-udp", connect(u[0], (void *)&peer, sizeof peer));
        for (int i = 1; i < 64; i++) sendto(senders[i], "x", 1, 0, (void *)&at, sizeof at);
        sendto(senders[0], "x", 1, 0, (void *)&at, sizeof at);
        counts[0] = counts[1] = 0;
        for (int i = 0; i < 2; i++)
            while (recv(u[i], buf, sizeof buf, 0) >= 0) counts[i]++;
        printf("  udp connected=%d other=%d\n", counts[0], counts[1]);
        return 0;
    }
    if (!strcmp(mode, "listen-fin-wait")) {
        /* The side that closes first waits for the peer's end up to 60
           seconds from its close (FIN_WAIT2, tcp_fin_timeout), then keeps
           its port in TIME_WAIT for 60 seconds from that end. The checks
           sit 10 seconds or more from each change, as Linux's timers run a
           few seconds late. A socket that stays open gives the port it took
           up with that TIME_WAIT (tcp_done), but keeps one it bound itself
           (SOCK_BINDPORT_LOCK) until it closes. */
        int port, result;
        int l = listener(8, &port);
        int c[5], s[5], at[5];
        for (int i = 0; i < 5; i++) {
            if (i == 4) {
                /* A port free now, which the client binds itself. */
                int t = tcp(0);
                bind_to("bind-free", t, htonl(INADDR_LOOPBACK), 0);
                int own = port_of(t);
                close(t);
                c[i] = tcp(0);
                bind_to("bind-own", c[i], htonl(INADDR_LOOPBACK), own);
                struct sockaddr_in a = to(port);
                call("connect-own", connect(c[i], (void *)&a, sizeof a));
            } else {
                c[i] = client(port, 0, &result);
            }
            s[i] = accept(l, NULL, NULL);
            at[i] = port_of(c[i]);
        }
        long start = now_ms();
        /* 0: the peer stays open. 1: the peer closes at 30 seconds. 2: shut
           down at once, closed at 30 seconds, the peer staying open. 3 and
           4: shut down at once, the peer closing at once, and kept open. */
        close(c[0]);
        close(c[1]);
        shutdown(c[2], SHUT_WR);
        for (int i = 3; i < 5; i++) {
            shutdown(c[i], SHUT_WR);
            close(s[i]);
        }
        static const struct {
            int second, which;
            const char *name;
        } checks[] = {{50, 0, "open-50"},  {50, 3, "kept-50"},   {50, 4, "own-50"},
                      {70, 0, "open-70"},  {70, 1, "late-70"},   {70, 3, "kept-70"},
                      {70, 4, "own-70"},   {80, 1, "late-80"},   {80, 2, "shut-80"},
                      {100, 1, "late-100"}, {100, 2, "shut-100"}};
        int closed = 0;
        for (unsigned i = 0; i < sizeof checks / sizeof *checks; i++) {
            if (!closed && checks[i].second > 30) {
                long wait = start + 30000 - now_ms();
                if (wait > 0) usleep(wait * 1000);
                close(s[1]);
                close(c[2]);
                closed = 1;
            }
            long wait = start + checks[i].second * 1000L - now_ms();
            if (wait > 0) usleep(wait * 1000);
            int t = tcp(0);
            bind_to(checks[i].name, t, htonl(INADDR_LOOPBACK), at[checks[i].which]);
            close(t);
        }
        close(c[4]);
        int t = tcp(0);
        bind_to("own-closed", t, htonl(INADDR_LOOPBACK), at[4]);
        return 0;
    }
    if (!strcmp(mode, "listen-urgent")) {
        /* MSG_OOB's urgent byte on the loopback (tcp_check_urg, tcp_urg,
           tcp_recvmsg, tcp_recv_urg): reads stop before its mark, one that
           starts there passes over it, losing it unless MSG_OOB took it,
           a later one makes it ordinary, and SO_OOBINLINE reads it as data.
           Each one sends the owner SIGURG. The waits after each send let
           Linux's loopback deliver it. */
        signal(SIGURG, on_urg);
        int port, c, s, one = 1;
        int l = listener(8, &port);
        puts("urgent");
        urgent_pair(l, port, &c, &s);
        urgent_state("before", s);
        call("send", send(c, "abc", 3, MSG_OOB));
        usleep(10000);
        urgent_state("sent", s);
        urgent_read("read", s, 16, 0);
        urgent_state("at-mark", s);
        urgent_read("peek-oob", s, 16, MSG_OOB | MSG_PEEK);
        urgent_read("oob", s, 16, MSG_OOB);
        urgent_state("taken", s);
        urgent_read("read-past", s, 16, 0);
        urgent_read("oob-again", s, 16, MSG_OOB);
        puts("passed");
        urgent_pair(l, port, &c, &s);
        send(c, "abc", 3, MSG_OOB);
        send(c, "de", 2, 0);
        usleep(10000);
        urgent_read("read", s, 16, 0);
        urgent_state("at-mark", s);
        urgent_read("peek", s, 16, MSG_PEEK);
        urgent_read("peek-oob", s, 16, MSG_OOB | MSG_PEEK);
        urgent_read("read", s, 16, 0);
        urgent_state("past", s);
        urgent_read("oob", s, 16, MSG_OOB);
        puts("two");
        urgent_pair(l, port, &c, &s);
        send(c, "ab", 2, MSG_OOB);
        send(c, "cd", 2, MSG_OOB);
        usleep(10000);
        urgent_state("two", s);
        urgent_read("read", s, 16, 0);
        urgent_read("read", s, 16, 0);
        urgent_read("oob", s, 16, MSG_OOB);
        puts("single");
        urgent_pair(l, port, &c, &s);
        send(c, "abc", 3, MSG_OOB);
        usleep(10000);
        urgent_read("read1", s, 1, 0);
        urgent_read("read1", s, 1, 0);
        urgent_read("read1", s, 1, 0);
        urgent_read("oob0", s, 0, MSG_OOB);
        puts("only");
        urgent_pair(l, port, &c, &s);
        send(c, "x", 1, MSG_OOB);
        usleep(10000);
        urgent_state("only", s);
        urgent_read("read", s, 16, 0);
        urgent_read("oob", s, 16, MSG_OOB);
        urgent_state("lost", s);
        puts("truncated");
        urgent_pair(l, port, &c, &s);
        send(c, "ab", 2, MSG_OOB);
        usleep(10000);
        {
            char b[1];
            struct iovec v = {.iov_base = b, .iov_len = 0};
            struct msghdr m = {.msg_iov = &v, .msg_iovlen = 1};
            long r = recvmsg(s, &m, MSG_OOB);
            printf("  recvmsg0 r=%ld flags=%#x\n", r, (unsigned)m.msg_flags);
            v.iov_len = 1;
            m.msg_flags = 0;
            r = recvmsg(s, &m, MSG_OOB);
            printf("  recvmsg1 r=%ld flags=%#x byte=%c\n", r, (unsigned)m.msg_flags, b[0]);
        }
        puts("waitall");
        urgent_pair(l, port, &c, &s);
        send(c, "ab", 2, MSG_OOB);
        close(c);
        usleep(10000);
        urgent_state("closed", s);
        urgent_read("read", s, 16, MSG_WAITALL);
        urgent_read("read", s, 16, 0);
        urgent_read("oob", s, 16, MSG_OOB);
        puts("inline");
        urgent_pair(l, port, &c, &s);
        setsockopt(s, SOL_SOCKET, SO_OOBINLINE, &one, sizeof one);
        send(c, "abc", 3, MSG_OOB);
        send(c, "de", 2, 0);
        usleep(10000);
        urgent_state("inline", s);
        urgent_read("oob", s, 16, MSG_OOB);
        urgent_read("read", s, 16, 0);
        urgent_state("at-mark", s);
        urgent_read("read", s, 16, 0);
        urgent_state("past", s);
        puts("inline-later");
        urgent_pair(l, port, &c, &s);
        send(c, "abc", 3, MSG_OOB);
        usleep(10000);
        setsockopt(s, SOL_SOCKET, SO_OOBINLINE, &one, sizeof one);
        urgent_read("read", s, 16, 0);
        urgent_read("read", s, 16, 0);
        urgent_read("oob", s, 16, MSG_OOB);
        puts("others");
        urgent_pair(l, port, &c, &s);
        call("send-empty", send(c, "", 0, MSG_OOB));
        usleep(10000);
        urgent_state("empty", s);
        urgent_read("oob-none", s, 16, MSG_OOB);
        urgent_read("oob-listener", l, 16, MSG_OOB);
        int fresh = tcp(0);
        urgent_read("oob-unconnected", fresh, 16, MSG_OOB);
        int u = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
        urgent_read("udp-oob", u, 16, MSG_OOB);
        struct sockaddr_in to_u = to(9);
        call("udp-send-oob", sendto(u, "x", 1, MSG_OOB, (void *)&to_u, sizeof to_u));
        return 0;
    }
    if (!strcmp(mode, "listen-reset")) {
        /* What ends a loopback connection with a reset. */
        int port, result;
        int l = listener(8, &port);
        /* Closed with input unread: the peer reads what it had, then the
           reset, then the end. */
        int c = client(port, 0, &result);
        int s = accept(l, NULL, NULL);
        send(s, "abc", 3, 0);
        send(c, "xyz", 3, 0);
        polled("unread", s, POLLIN);
        polled("client-data", c, POLLIN);
        close(s);
        polled("reset", c, POLLIN | POLLOUT | POLLRDHUP);
        n = recv(c, buf, sizeof buf, 0);
        print_bytes("before-reset", buf, n);
        call("recv-reset", recv(c, buf, sizeof buf, 0));
        call("recv-after", recv(c, buf, sizeof buf, 0));
        call("send-after", send(c, "x", 1, MSG_NOSIGNAL));
        close(c);
        /* Closed cleanly, then written to: the write goes, the reset comes
           back, and the next write is EPIPE. */
        c = client(port, 0, &result);
        s = accept(l, NULL, NULL);
        close(s);
        await_end(c);
        call("eof", recv(c, buf, sizeof buf, 0));
        call("send-to-closed", send(c, "x", 1, MSG_NOSIGNAL));
        polled("answered", c, POLLERR);
        call("send-again", send(c, "x", 1, MSG_NOSIGNAL));
        option("error-after", c, SOL_SOCKET, SO_ERROR);
        call("recv-closed", recv(c, buf, sizeof buf, 0));
        close(c);
        /* A zero linger time resets. */
        c = client(port, 0, &result);
        s = accept(l, NULL, NULL);
        struct linger linger = {1, 0};
        setsockopt(s, SOL_SOCKET, SO_LINGER, &linger, sizeof linger);
        close(s);
        polled("lingered", c, POLLIN);
        call("recv-lingered", recv(c, buf, sizeof buf, 0));
        close(c);
        /* AF_UNSPEC disconnects with a reset, and the socket connects anew. */
        c = client(port, 0, &result);
        s = accept(l, NULL, NULL);
        struct sockaddr unspec = {.sa_family = AF_UNSPEC};
        call("disconnect", connect(c, &unspec, sizeof unspec));
        polled("disconnected", s, POLLIN);
        call("recv-disconnected", recv(s, buf, sizeof buf, 0));
        struct sockaddr_in a = to(port);
        call("reconnect", connect(c, (void *)&a, sizeof a));
        close(s);
        s = accept(l, NULL, NULL);
        printf("  accept-again-ok=%d\n", s >= 0);
        close(s);
        close(c);
        /* A listener that closes resets what it has not handed out. */
        int queued = client(port, 0, &result);
        printf("  queued errno=%d\n", result);
        close(l);
        polled("listener-gone", queued, POLLIN);
        call("recv-queued", recv(queued, buf, sizeof buf, 0));
        close(queued);
        return 0;
    }
    if (!strcmp(mode, "listen-buffers")) {
        /* SO_SNDBUF on the sender and SO_RCVBUF on the listener, set
           before the connection, bound what a sender that nobody reads
           fits in. Linux's exact counts hang on its window and per-segment
           accounting, so only their range shows, and that the two queues
           (SIOCOUTQ, FIONREAD) hold all that was sent. */
        static const struct {
            int bytes;
            long above, at_most;
        } sizes[] = {{4096, 0, 16384}, {16384, 16384, 65536}, {65536, 65536, 300000}, {0, 400000, 1L << 30}};
        for (unsigned i = 0; i < sizeof sizes / sizeof *sizes; i++) {
            int bytes = sizes[i].bytes, port, result;
            int l = tcp(0);
            if (bytes) setsockopt(l, SOL_SOCKET, SO_RCVBUF, &bytes, sizeof bytes);
            struct sockaddr_in a = to(0);
            bind(l, (void *)&a, sizeof a);
            listen(l, 1);
            port = port_of(l);
            int c = tcp(0);
            if (bytes) setsockopt(c, SOL_SOCKET, SO_SNDBUF, &bytes, sizeof bytes);
            a = to(port);
            result = connect(c, (void *)&a, sizeof a);
            int s = accept(l, NULL, NULL);
            long sent = fill(c);
            int outq = -1, inq = -1;
            ioctl(c, SIOCOUTQ, &outq);
            ioctl(s, FIONREAD, &inq);
            printf("  buffers=%d connect=%d in-range=%d queues-hold-all=%d\n", bytes, result,
                   sent > sizes[i].above && sent <= sizes[i].at_most, outq + inq == sent);
            /* A reader moves it all along: a blocking 1 MiB send through
               the smallest buffers ends once a thread has read it. */
            if (bytes == 4096) {
                static char big[1 << 20];
                drained_fd = s;
                drained_expected = sent + (long)sizeof big;
                pthread_t reader;
                if (pthread_create(&reader, NULL, drain_later, NULL)) return 70;
                long wrote = send(c, big, sizeof big, 0);
                shutdown(c, SHUT_WR);
                void *all;
                pthread_join(reader, &all);
                printf("  wrote-all=%d read-all=%d\n", wrote == (long)sizeof big, all != NULL);
            }
            close(s);
            close(c);
            close(l);
        }
        return 0;
    }
    if (!strcmp(mode, "listen-linger")) {
        /* A nonzero linger time holds the close of a socket's last
           descriptor while what it sent waits for room in the peer, up to
           that time (tcp_close's sk_stream_wait_close); the bytes still go
           after it. */
        int port, result, status;
        int l = listener(8, &port);
        struct linger one = {1, 1}, five = {1, 5};
        /* The peer never reads: the close waits out the second, nonblocking
           as it is, and the peer has every byte after it. */
        int c = client(port, 0, &result);
        int s = accept(l, NULL, NULL);
        fcntl(s, F_SETFL, O_NONBLOCK);
        long sent = fill(s);
        call("linger", setsockopt(s, SOL_SOCKET, SO_LINGER, &one, sizeof one));
        long start = now_ms();
        call("close-full", close(s));
        printf("  held=%ld\n", seconds_since(start));
        printf("  all-received=%d\n", drain(c) == sent);
        close(c);
        /* Another descriptor keeps the socket open: only the last close
           waits. */
        c = client(port, 0, &result);
        s = accept(l, NULL, NULL);
        sent = fill(s);
        setsockopt(s, SOL_SOCKET, SO_LINGER, &one, sizeof one);
        int d = dup(s);
        start = now_ms();
        close(s);
        printf("  held-dup=%ld\n", seconds_since(start));
        start = now_ms();
        close(d);
        printf("  held-last=%ld\n", seconds_since(start));
        printf("  all-received-last=%d\n", drain(c) == sent);
        close(c);
        /* The peer reads it all in another thread after 300 ms: the close
           ends then, well before its five seconds. How long it waited is not
           compared with the 300 ms: the emulated side runs on a virtual
           clock, which the reader's sleep moves for the closing thread too,
           maybe before the close looks at it (docs/design/quality.md). */
        c = client(port, 0, &result);
        s = accept(l, NULL, NULL);
        sent = fill(s);
        setsockopt(s, SOL_SOCKET, SO_LINGER, &five, sizeof five);
        drained_fd = c;
        drained_expected = sent;
        pthread_t reader;
        if (pthread_create(&reader, NULL, drain_later, NULL)) return 70;
        start = now_ms();
        call("close-read", close(s));
        long held = now_ms() - start;
        printf("  ended-before-time=%d\n", held < 2000);
        void *all;
        pthread_join(reader, &all);
        printf("  reader-received-all=%d\n", all != NULL);
        close(c);
        /* A signal ends the wait, and the close still succeeds. */
        struct sigaction sa = {.sa_handler = on_alarm};
        sigaction(SIGALRM, &sa, NULL);
        c = client(port, 0, &result);
        s = accept(l, NULL, NULL);
        sent = fill(s);
        setsockopt(s, SOL_SOCKET, SO_LINGER, &five, sizeof five);
        struct itimerval timer = {.it_value = {0, 300000}};
        setitimer(ITIMER_REAL, &timer, NULL);
        start = now_ms();
        call("close-signal", close(s));
        held = now_ms() - start;
        printf("  held-until-signal=%d alarms=%d\n", held >= 200 && held < 2000, (int)alarms);
        printf("  all-received-signal=%d\n", drain(c) == sent);
        close(c);
        /* Unread input resets the connection instead, with no wait. */
        c = client(port, 0, &result);
        s = accept(l, NULL, NULL);
        sent = fill(s);
        send(c, "x", 1, 0);
        polled("unread", s, POLLIN);
        setsockopt(s, SOL_SOCKET, SO_LINGER, &five, sizeof five);
        start = now_ms();
        call("close-unread", close(s));
        printf("  held-unread=%ld\n", seconds_since(start));
        close(c);
        /* Nothing left to send: no wait. */
        c = client(port, 0, &result);
        s = accept(l, NULL, NULL);
        send(s, "abc", 3, 0);
        polled("sent", c, POLLIN);
        setsockopt(s, SOL_SOCKET, SO_LINGER, &five, sizeof five);
        start = now_ms();
        call("close-sent", close(s));
        printf("  held-sent=%ld\n", seconds_since(start));
        close(c);
        /* dup2 over the last descriptor closes it with the same wait. */
        c = client(port, 0, &result);
        s = accept(l, NULL, NULL);
        sent = fill(s);
        setsockopt(s, SOL_SOCKET, SO_LINGER, &one, sizeof one);
        int other = tcp(0);
        start = now_ms();
        call("dup2", dup2(other, s) == s ? 0 : -1);
        printf("  held-dup2=%ld\n", seconds_since(start));
        printf("  all-received-dup2=%d\n", drain(c) == sent);
        close(other);
        close(s);
        close(c);
        /* A process that exits does not wait (PF_EXITING). */
        int sync[2];
        if (pipe(sync)) return 71;
        c = client(port, 0, &result);
        s = accept(l, NULL, NULL);
        sent = fill(s);
        setsockopt(s, SOL_SOCKET, SO_LINGER, &five, sizeof five);
        pid_t child = fork();
        if (!child) {
            if (read(sync[0], buf, 1) != 1) _exit(2);
            _exit(0);
        }
        close(s);
        start = now_ms();
        if (write(sync[1], "x", 1) != 1) return 72;
        waitpid(child, &status, 0);
        printf("  held-exit=%ld\n", seconds_since(start));
        printf("  all-received-exit=%d\n", drain(c) == sent);
        close(c);
        /* execve closes a close-on-exec socket as close does, waiting
           before the new program starts, which drains the peer. */
        if (argc < 5) return 98;
        c = client(port, 0, &result);
        s = accept(l, NULL, NULL);
        sent = fill(s);
        setsockopt(s, SOL_SOCKET, SO_LINGER, &one, sizeof one);
        fcntl(s, F_SETFD, FD_CLOEXEC);
        char peer[16], bytes[32], since[32];
        snprintf(peer, sizeof peer, "%d", c);
        snprintf(bytes, sizeof bytes, "%ld", sent);
        snprintf(since, sizeof since, "%ld", now_ms());
        char *again[] = {"network", "linger-exec", argv[2], argv[3], argv[4], peer, bytes, since, NULL};
        execv(argv[4], again);
        printf("  exec errno=%d\n", errno);
        return 1;
    }
    if (!strcmp(mode, "linger-exec")) {
        /* After listen-linger's execve: the peer, the bytes sent and when. */
        if (argc < 8) return 98;
        int c = atoi(argv[5]);
        long sent = atol(argv[6]);
        printf("  held-exec=%ld\n", seconds_since(atol(argv[7])));
        printf("  all-received-exec=%d\n", drain(c) == sent);
        return 0;
    }
    if (!strcmp(mode, "listen-fork")) {
        /* A child connects to its parent's listener, which a blocking
           accept waits on. */
        int port;
        int l = listener(1, &port);
        pid_t child = fork();
        if (child == 0) {
            usleep(100000);
            int result;
            int c = client(port, 0, &result);
            if (result) _exit(1);
            send(c, "from child", 10, 0);
            shutdown(c, SHUT_WR);
            n = recv(c, buf, 5, MSG_WAITALL);
            _exit(n == 5 && !memcmp(buf, "reply", 5) ? 0 : 2);
        }
        int s = accept(l, NULL, NULL);
        printf("  accept-ok=%d\n", s >= 0);
        n = recv(s, buf, sizeof buf, MSG_WAITALL);
        print_bytes("recv", buf, n);
        call("reply", send(s, "reply", 5, 0));
        int status;
        waitpid(child, &status, 0);
        printf("  child exited=%d status=%d\n", WIFEXITED(status), WEXITSTATUS(status));
        close(s);
        close(l);
        return 0;
    }
    if (!strcmp(mode, "listen-v6")) {
        /* IPv6 listeners: one on every address takes IPv4 connections too,
           with IPv4-mapped addresses; an IPv6-only one does not. */
        int l = socket(AF_INET6, SOCK_STREAM, 0);
        struct sockaddr_in6 any = {.sin6_family = AF_INET6};
        call("bind", bind(l, (void *)&any, sizeof any));
        call("listen", listen(l, 4));
        int port = port_of(l);
        int result;
        int c4 = client(port, 0, &result);
        printf("  v4 connect errno=%d\n", result);
        struct sockaddr_in6 peer;
        socklen_t len = sizeof peer;
        int s = accept(l, (void *)&peer, &len);
        printf("  accept family=%d len=%u mapped=%d\n", peer.sin6_family, (unsigned)len,
               IN6_IS_ADDR_V4MAPPED(&peer.sin6_addr));
        struct sockaddr_in6 mine;
        len = sizeof mine;
        getsockname(s, (void *)&mine, &len);
        printf("  server mapped=%d last=%#x port-ok=%d\n", IN6_IS_ADDR_V4MAPPED(&mine.sin6_addr),
               ntohl(mine.sin6_addr.s6_addr32[3]), ntohs(mine.sin6_port) == port);
        close(s);
        close(c4);
        int c6 = socket(AF_INET6, SOCK_STREAM, 0);
        struct sockaddr_in6 one = {.sin6_family = AF_INET6, .sin6_port = htons(port), .sin6_addr = in6addr_loopback};
        call("v6 connect", connect(c6, (void *)&one, sizeof one));
        len = sizeof peer;
        s = accept(l, (void *)&peer, &len);
        printf("  accept family=%d loopback=%d\n", peer.sin6_family, IN6_IS_ADDR_LOOPBACK(&peer.sin6_addr));
        len = sizeof mine;
        getsockname(c6, (void *)&mine, &len);
        printf("  client loopback=%d same-port=%d\n", IN6_IS_ADDR_LOOPBACK(&mine.sin6_addr),
               mine.sin6_port == peer.sin6_port);
        close(s);
        close(c6);
        /* The port on every address covers IPv4 binds too. */
        int b4 = tcp(0);
        bind_to("v4-beside-dual", b4, htonl(INADDR_LOOPBACK), port);
        close(b4);
        close(l);
        int only = socket(AF_INET6, SOCK_STREAM, 0);
        set_option("v6only", only, IPPROTO_IPV6, IPV6_V6ONLY, 1);
        call("only-bind", bind(only, (void *)&any, sizeof any));
        set_option("v6only-bound", only, IPPROTO_IPV6, IPV6_V6ONLY, 0);
        call("only-listen", listen(only, 4));
        int only_port = port_of(only);
        c4 = client(only_port, 0, &result);
        printf("  v4 to v6-only errno=%d\n", result);
        close(c4);
        b4 = tcp(0);
        bind_to("v4-beside-v6-only", b4, htonl(INADDR_LOOPBACK), only_port);
        close(b4);
        close(only);
        int m = socket(AF_INET6, SOCK_STREAM, 0);
        struct sockaddr_in6 mapped = {.sin6_family = AF_INET6};
        mapped.sin6_addr.s6_addr[10] = 0xff;
        mapped.sin6_addr.s6_addr[11] = 0xff;
        mapped.sin6_addr.s6_addr32[3] = htonl(INADDR_LOOPBACK);
        call("bind-mapped", bind(m, (void *)&mapped, sizeof mapped));
        close(m);
        m = socket(AF_INET6, SOCK_STREAM, 0);
        set_option("v6only", m, IPPROTO_IPV6, IPV6_V6ONLY, 1);
        call("bind-mapped-v6-only", bind(m, (void *)&mapped, sizeof mapped));
        struct sockaddr_in6 foreign = {.sin6_family = AF_INET6};
        inet_pton(AF_INET6, "2001:db8::1", &foreign.sin6_addr);
        call("bind-foreign", bind(m, (void *)&foreign, sizeof foreign));
        call("bind-short", bind(m, (void *)&any, 16));
        struct sockaddr_in four = to(0);
        call("bind-v4-family", bind(m, (void *)&four, sizeof mapped));
        close(m);
        return 0;
    }
    if (!strcmp(mode, "udp")) {
        /* UDP on the loopback: datagrams and their senders, truncation and
           peeking, a connected socket's filter and the loopback's ICMP
           answer to it, the size limit, SO_REUSEADDR and a dual-stack
           receiver. */
        int a = socket(AF_INET, SOCK_DGRAM, 0);
        struct sockaddr_in addr = to(0);
        call("bind", bind(a, (void *)&addr, sizeof addr));
        int port = port_of(a);
        printf("  port-ok=%d\n", port != 0);
        ready("idle", a, POLLIN | POLLOUT);
        int b = socket(AF_INET, SOCK_DGRAM, 0);
        struct sockaddr_in dst = to(port);
        call("sendto", sendto(b, "hello", 5, 0, (void *)&dst, sizeof dst));
        struct sockaddr_in bn;
        socklen_t len = sizeof bn;
        getsockname(b, (void *)&bn, &len);
        printf("  sender family=%d addr=%#x port-ok=%d\n", bn.sin_family, ntohl(bn.sin_addr.s_addr),
               ntohs(bn.sin_port) != 0);
        ready("arrived", a, POLLIN | POLLOUT);
        call("send-empty", sendto(b, "", 0, 0, (void *)&dst, sizeof dst));
        call("send-ten", sendto(b, "0123456789", 10, 0, (void *)&dst, sizeof dst));
        int queued = -1;
        ioctl(a, FIONREAD, &queued);
        printf("  fionread=%d\n", queued);
        struct sockaddr_in from;
        len = sizeof from;
        n = recvfrom(a, buf, sizeof buf, 0, (void *)&from, &len);
        print_bytes("recvfrom", buf, n);
        printf("  from-is-sender=%d len=%u addr=%#x\n", from.sin_port == bn.sin_port, (unsigned)len,
               ntohl(from.sin_addr.s_addr));
        call("recv-empty", recv(a, buf, sizeof buf, 0));
        call("recv-trunc", recv(a, buf, 4, MSG_TRUNC));
        call("recv-dontwait", recv(a, buf, 1, MSG_DONTWAIT));
        sendto(b, "abcdef", 6, 0, (void *)&dst, sizeof dst);
        struct iovec iov = {buf, 3};
        struct msghdr mh = {.msg_iov = &iov, .msg_iovlen = 1};
        n = recvmsg(a, &mh, 0);
        printf("  recvmsg=%ld trunc=%d\n", n, (mh.msg_flags & MSG_TRUNC) != 0);
        sendto(b, "peek", 4, 0, (void *)&dst, sizeof dst);
        n = recv(a, buf, sizeof buf, MSG_PEEK);
        print_bytes("peeked", buf, n);
        n = recv(a, buf, sizeof buf, 0);
        print_bytes("taken", buf, n);
        /* Connected, a socket takes datagrams only from its peer, and sends
           to it without an address. */
        struct sockaddr_in peer = to(ntohs(bn.sin_port));
        call("connect", connect(a, (void *)&peer, sizeof peer));
        len = sizeof peer;
        call("getpeername", getpeername(a, (void *)&peer, &len));
        printf("  peer-is-sender=%d addr=%#x\n", peer.sin_port == bn.sin_port, ntohl(peer.sin_addr.s_addr));
        int c = socket(AF_INET, SOCK_DGRAM, 0);
        call("stranger", sendto(c, "stranger", 8, 0, (void *)&dst, sizeof dst));
        call("friend", sendto(b, "friend", 6, 0, (void *)&dst, sizeof dst));
        n = recv(a, buf, sizeof buf, 0);
        print_bytes("connected-recv", buf, n);
        call("recv-none", recv(a, buf, sizeof buf, MSG_DONTWAIT));
        call("send-to-peer", send(a, "back", 4, 0));
        n = recv(b, buf, sizeof buf, 0);
        print_bytes("sender-recv", buf, n);
        call("send-unconnected", send(c, "x", 1, 0));
        /* A port nothing takes: the loopback answers a connected socket's
           datagram with ICMP, which its next call gives, once. */
        int gone = socket(AF_INET, SOCK_DGRAM, 0);
        bind(gone, (void *)&addr, sizeof addr);
        int gone_port = port_of(gone);
        close(gone);
        int d = socket(AF_INET, SOCK_DGRAM, 0);
        struct sockaddr_in closed = to(gone_port);
        call("connect-closed", connect(d, (void *)&closed, sizeof closed));
        len = sizeof bn;
        getsockname(d, (void *)&bn, &len);
        printf("  closed source=%#x port-ok=%d\n", ntohl(bn.sin_addr.s_addr), ntohs(bn.sin_port) != 0);
        call("send-closed", send(d, "x", 1, 0));
        ready("refused", d, POLLIN | POLLOUT);
        /* A send too big fails before it would take the error. */
        static char huge[65508];
        call("send-too-big-refused", send(d, huge, sizeof huge, 0));
        call("send-refused", send(d, "x", 1, 0));
        call("send-again", send(d, "x", 1, 0));
        call("recv-refused", recv(d, buf, sizeof buf, MSG_DONTWAIT));
        call("recv-after", recv(d, buf, sizeof buf, MSG_DONTWAIT));
        call("unconnected-closed", sendto(c, "x", 1, 0, (void *)&closed, sizeof closed));
        option("unconnected-error", c, SOL_SOCKET, SO_ERROR);
        /* The most a datagram holds over IPv4. */
        static char big[65508];
        call("send-most", sendto(b, big, 65507, 0, (void *)&dst, sizeof dst));
        call("send-too-big", sendto(b, big, 65508, 0, (void *)&dst, sizeof dst));
        call("recv-most", recv(a, big, sizeof big, 0));
        /* AF_UNSPEC disconnects: the address the guest named stays, but
           the port it let bind choose goes, so nothing reaches it there. */
        struct sockaddr unspec = {.sa_family = AF_UNSPEC};
        call("disconnect", connect(a, &unspec, sizeof unspec));
        len = sizeof peer;
        call("getpeername-after", getpeername(a, (void *)&peer, &len));
        len = sizeof bn;
        getsockname(a, (void *)&bn, &len);
        printf("  after-disconnect addr=%#x port=%d\n", ntohl(bn.sin_addr.s_addr), ntohs(bn.sin_port));
        call("stranger-again", sendto(c, "now", 3, 0, (void *)&dst, sizeof dst));
        call("recv-unbound", recv(a, buf, sizeof buf, MSG_DONTWAIT));
        /* Its next send binds a port on that address. */
        call("send-rebinds", sendto(a, "re", 2, 0, (void *)&dst, sizeof dst));
        len = sizeof bn;
        getsockname(a, (void *)&bn, &len);
        printf("  rebound addr=%#x port-ok=%d\n", ntohl(bn.sin_addr.s_addr), ntohs(bn.sin_port) != 0);
        /* SO_REUSEADDR shares a port; the last to bind takes the datagram. */
        int r1 = socket(AF_INET, SOCK_DGRAM, 0), r2 = socket(AF_INET, SOCK_DGRAM, 0),
            r3 = socket(AF_INET, SOCK_DGRAM, 0);
        set_option("reuse-1", r1, SOL_SOCKET, SO_REUSEADDR, 1);
        set_option("reuse-2", r2, SOL_SOCKET, SO_REUSEADDR, 1);
        bind_to("reuse-bind-1", r1, htonl(INADDR_LOOPBACK), 0);
        int shared = port_of(r1);
        bind_to("reuse-bind-2", r2, htonl(INADDR_LOOPBACK), shared);
        bind_to("no-reuse-bind", r3, htonl(INADDR_LOOPBACK), shared);
        struct sockaddr_in to_shared = to(shared);
        sendto(c, "who", 3, 0, (void *)&to_shared, sizeof to_shared);
        ready("first-bound", r1, POLLIN);
        ready("last-bound", r2, POLLIN);
        /* A TCP port is not a UDP one. */
        int t;
        int l = listener(1, &t);
        bind_to("udp-on-tcp-port", r3, htonl(INADDR_LOOPBACK), t);
        close(l);
        /* An IPv6 socket on every address takes IPv4 datagrams, with the
           sender IPv4-mapped. */
        int s6 = socket(AF_INET6, SOCK_DGRAM, 0);
        struct sockaddr_in6 any6 = {.sin6_family = AF_INET6};
        call("bind-v6", bind(s6, (void *)&any6, sizeof any6));
        struct sockaddr_in to6 = to(port_of(s6));
        call("send-v6", sendto(c, "v4", 2, 0, (void *)&to6, sizeof to6));
        struct sockaddr_in6 f6;
        len = sizeof f6;
        n = recvfrom(s6, buf, sizeof buf, 0, (void *)&f6, &len);
        printf("  v6 recv=%ld family=%d len=%u mapped=%d\n", n, f6.sin6_family, (unsigned)len,
               IN6_IS_ADDR_V4MAPPED(&f6.sin6_addr));
        return 0;
    }
    if (!strcmp(mode, "udp-elsewhere")) {
        /* connect of a UDP socket to an address off the loopback binds a
           port first (inet_autobind), which then moves to the route's source
           address (ip_route_connect), takes no datagram from the loopback,
           and is held until AF_UNSPEC gives it back. The address itself is
           the machine's, so only how it compares is printed. */
        int u = socket(AF_INET, SOCK_DGRAM, 0);
        struct sockaddr_in far = {.sin_family = AF_INET, .sin_port = htons(9)};
        far.sin_addr.s_addr = htonl(0xc0000201);
        call("connect", connect(u, (void *)&far, sizeof far));
        int port = port_of(u);
        printf("  port-ok=%d\n", port != 0);
        struct sockaddr_in source, again;
        socklen_t source_len = sizeof source;
        getsockname(u, (void *)&source, &source_len);
        in_addr_t ip = ntohl(source.sin_addr.s_addr);
        printf("  source-specific=%d\n", ip != 0 && ip >> 24 != 127);
        int probe = socket(AF_INET, SOCK_DGRAM, 0);
        connect(probe, (void *)&far, sizeof far);
        source_len = sizeof again;
        getsockname(probe, (void *)&again, &source_len);
        printf("  same-source=%d\n", again.sin_addr.s_addr == source.sin_addr.s_addr);
        close(probe);
        /* The port is held on that address only. */
        int beside = socket(AF_INET, SOCK_DGRAM, 0);
        bind_to("bind-loopback", beside, htonl(INADDR_LOOPBACK), port);
        close(beside);
        struct sockaddr_in peer;
        socklen_t len = sizeof peer;
        call("getpeername", getpeername(u, (void *)&peer, &len));
        printf("  peer addr=%#x port=%d\n", ntohl(peer.sin_addr.s_addr), ntohs(peer.sin_port));
        int other = socket(AF_INET, SOCK_DGRAM, 0);
        struct sockaddr_in here = to(port);
        call("send-loopback", sendto(other, "x", 1, 0, (void *)&here, sizeof here));
        call("recv-none", recv(u, buf, sizeof buf, MSG_DONTWAIT));
        int taker = socket(AF_INET, SOCK_DGRAM, 0);
        bind_to("bind-held", taker, htonl(INADDR_ANY), port);
        struct sockaddr unspec = {.sa_family = AF_UNSPEC};
        call("disconnect", connect(u, &unspec, sizeof unspec));
        printf("  after-disconnect port=%d\n", port_of(u));
        bind_to("bind-freed", taker, htonl(INADDR_ANY), port);
        /* An IPv6-only socket has no route to an IPv4-mapped address, but
           took its port first. */
        int v6 = socket(AF_INET6, SOCK_DGRAM, 0);
        set_option("v6only", v6, IPPROTO_IPV6, IPV6_V6ONLY, 1);
        struct sockaddr_in6 mapped = {.sin6_family = AF_INET6, .sin6_port = htons(9)};
        mapped.sin6_addr.s6_addr[10] = mapped.sin6_addr.s6_addr[11] = 0xff;
        memcpy(&mapped.sin6_addr.s6_addr[12], "\xc0\x00\x02\x01", 4);
        call("connect-mapped", connect(v6, (void *)&mapped, sizeof mapped));
        printf("  mapped port-ok=%d\n", port_of(v6) != 0);
        return 0;
    }
    if (!strcmp(mode, "udp-rcvbuf")) {
        /* How many datagrams a UDP socket's receive buffer takes: each
           counts its sk_buff's truesize, and one that would take the buffer
           past SO_RCVBUF while another waits is dropped
           (__udp_enqueue_schedule_skb). SO_RCVBUF is doubled, and at least
           2304; past rmem_max, which a machine may raise, it is not tried. */
        static char data[65536];
        int asked[] = {0, 1024, 4096, 10000, 100000};
        for (unsigned i = 0; i < sizeof asked / sizeof *asked; i++) {
            int u = socket(AF_INET, SOCK_DGRAM, 0), got;
            socklen_t len = sizeof got;
            setsockopt(u, SOL_SOCKET, SO_RCVBUF, &asked[i], sizeof asked[i]);
            getsockopt(u, SOL_SOCKET, SO_RCVBUF, &got, &len);
            printf("  rcvbuf %d -> %d\n", asked[i], got);
            close(u);
        }
        /* 100000, doubled to 200000: three 65500-byte datagrams over IPv4,
           two over IPv6, which sends them as two fragments. */
        int buffers[] = {1024, 2048, 4096, 10000, 100000};
        int sizes[] = {0, 100, 261, 262, 645, 646, 1000, 3000, 9000, 16004, 16005, 30000, 65500};
        for (int v6 = 0; v6 < 2; v6++)
            for (unsigned b = 0; b < sizeof buffers / sizeof *buffers; b++)
                for (unsigned k = 0; k < sizeof sizes / sizeof *sizes; k++) {
                    int family = v6 ? AF_INET6 : AF_INET;
                    int r = socket(family, SOCK_DGRAM | SOCK_NONBLOCK, 0);
                    int s = socket(family, SOCK_DGRAM, 0);
                    setsockopt(r, SOL_SOCKET, SO_RCVBUF, &buffers[b], sizeof buffers[b]);
                    struct sockaddr_storage at = {0};
                    socklen_t len;
                    if (v6) {
                        struct sockaddr_in6 *a = (void *)&at;
                        a->sin6_family = AF_INET6;
                        a->sin6_addr = in6addr_loopback;
                        len = sizeof *a;
                    } else {
                        struct sockaddr_in *a = (void *)&at;
                        a->sin_family = AF_INET;
                        a->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
                        len = sizeof *a;
                    }
                    bind(r, (void *)&at, len);
                    getsockname(r, (void *)&at, &len);
                    for (int n = 0; n < 64; n++) sendto(s, data, sizes[k], 0, (void *)&at, len);
                    usleep(2000);
                    int fit = 0;
                    while (recv(r, data, sizeof data, 0) >= 0) fit++;
                    printf("  v6=%d rcvbuf=%d size=%d fit=%d\n", v6, buffers[b], sizes[k], fit);
                    close(r);
                    close(s);
                }
        return 0;
    }
    if (!strcmp(mode, "udp-shutdown")) {
        /* shutdown of a UDP socket: ENOTCONN unless it is connected, but
           shut all the same. A receive that would wait then ends with 0,
           datagrams still come, a send is EPIPE with no SIGPIPE, and poll
           shows the ends. Another process's shutdown ends a waiting
           receive. */
        signal(SIGPIPE, on_pipe);
        int a = socket(AF_INET, SOCK_DGRAM, 0);
        struct sockaddr_in addr = to(0);
        bind(a, (void *)&addr, sizeof addr);
        int port = port_of(a);
        call("shutdown-rd", shutdown(a, SHUT_RD));
        ready("read-shut", a, POLLIN | POLLOUT | POLLRDHUP);
        call("recv", recv(a, buf, sizeof buf, 0));
        call("recv-dontwait", recv(a, buf, sizeof buf, MSG_DONTWAIT));
        struct sockaddr_in from;
        memset(&from, 0x55, sizeof from);
        socklen_t len = sizeof from;
        call("recvfrom", recvfrom(a, buf, sizeof buf, 0, (void *)&from, &len));
        printf("  len=%u\n", (unsigned)len);
        int b = socket(AF_INET, SOCK_DGRAM, 0);
        struct sockaddr_in dst = to(port);
        call("sendto", sendto(b, "still", 5, 0, (void *)&dst, sizeof dst));
        n = recv(a, buf, sizeof buf, 0);
        print_bytes("arrived", buf, n);
        call("read", read(a, buf, sizeof buf));
        call("shutdown-wr", shutdown(a, SHUT_WR));
        ready("both-shut", a, POLLIN | POLLOUT | POLLRDHUP);
        struct sockaddr_in to_b = to(port_of(b));
        static char big[65508];
        call("send-shut", sendto(a, "x", 1, 0, (void *)&to_b, sizeof to_b));
        call("send-empty-shut", sendto(a, "", 0, 0, (void *)&to_b, sizeof to_b));
        call("send-too-big-shut", sendto(a, big, sizeof big, 0, (void *)&to_b, sizeof to_b));
        call("send-nosignal", sendto(a, "x", 1, MSG_NOSIGNAL, (void *)&to_b, sizeof to_b));
        call("write-unconnected", write(a, "x", 1));
        printf("  sigpipes=%d\n", (int)pipes);
        call("recv-b", recv(b, buf, sizeof buf, MSG_DONTWAIT));
        int c = socket(AF_INET, SOCK_DGRAM, 0);
        call("connect", connect(c, (void *)&to_b, sizeof to_b));
        call("connected-shutdown", shutdown(c, SHUT_WR));
        call("connected-send", send(c, "x", 1, 0));
        ready("connected", c, POLLIN | POLLOUT | POLLRDHUP);
        call("shutdown-bad", shutdown(c, 3));
        printf("  sigpipes=%d\n", (int)pipes);
        int w = socket(AF_INET, SOCK_DGRAM, 0);
        bind(w, (void *)&addr, sizeof addr);
        pid_t child = fork();
        if (child == 0) {
            usleep(200000);
            shutdown(w, SHUT_RD);
            _exit(0);
        }
        call("woken", recv(w, buf, sizeof buf, 0));
        int status;
        waitpid(child, &status, 0);
        return 0;
    }
    if (!strcmp(mode, "resolve")) {
        /* Name resolution through the guest's own resolver; run under the
           emulator only, with localhost allowed and nothing else. */
        struct addrinfo hints = {.ai_family = AF_INET, .ai_socktype = SOCK_STREAM}, *found;
        int r = getaddrinfo("localhost", argv[2], &hints, &found);
        printf("  localhost=%d\n", r);
        if (r == 0) {
            struct sockaddr_in *a = (void *)found->ai_addr;
            printf("  addr=%#x port-ok=%d\n", ntohl(a->sin_addr.s_addr), ntohs(a->sin_port) == open_port);
            int fd = socket(found->ai_family, found->ai_socktype, 0);
            call("connect", connect(fd, found->ai_addr, found->ai_addrlen));
            send(fd, "eok", 3, 0);
            shutdown(fd, SHUT_WR);
            await_end(fd);
            n = read(fd, buf, sizeof buf);
            print_bytes("echo", buf, n);
            close(fd);
            freeaddrinfo(found);
        }
        printf("  blocked=%d\n", getaddrinfo("blocked.example", "80", &hints, &found) == EAI_NONAME);
        /* A loopback port the policy does not allow, where no guest socket
           listens, is refused. */
        int fd = tcp(0);
        struct sockaddr_in a = to(closed_port);
        call("connect-other-port", connect(fd, (void *)&a, sizeof a));
        close(fd);
        return 0;
    }
    return 98;
}
