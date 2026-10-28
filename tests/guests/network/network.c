/* TCP client sockets against the differential test's local server.
 *
 *   network <mode> <open-port> <closed-port>
 *
 * The server (crates/paludarium-harness/tests/diff_network.rs) listens on
 * 127.0.0.1:<open-port> and reads one command byte per connection:
 *   'e' echoes everything until the end of input, then closes;
 *   'c' closes at once;
 *   'b' sends 1 MiB of a pattern, then closes;
 *   'w' reads until the end of input, sends "bye", then closes.
 * Nothing listens on <closed-port>. Only what native Linux and the
 * emulator share is printed: never the client's own port. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

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
/* async: takes the signal-driven I/O signals pending now, and prints
   each different one as it comes (data may come in several pieces). */
static void signals(const char *step) {
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, 40);
    siginfo_t info;
    int last_code = 0;
    long last_band = 0;
    struct timespec now = {0, 0};
    printf("  %s:", step);
    while (sigtimedwait(&set, &info, &now) == 40) {
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
static volatile sig_atomic_t pipes;
static void on_pipe(int signal) { (void)signal; pipes++; }

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
        /* An address the policy does not allow cannot be reached. */
        int fd = tcp(0);
        struct sockaddr_in a = to(closed_port);
        call("connect-other-port", connect(fd, (void *)&a, sizeof a));
        close(fd);
        return 0;
    }
    return 98;
}
