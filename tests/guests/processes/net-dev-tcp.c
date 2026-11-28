/* What a device's counters take of TCP (so as root): the packets and
   bytes of /proc/net/dev and of a link's IFLA_STATS64 and IFLA_STATS, as
   each segment counts once as it leaves, with its IP header, and on a
   veth pair its Ethernet header, its TCP header with the SYN's options or
   the timestamps (tcp_options_write), and its data. The process makes a
   network namespace, A, and connects through its loopback, of IPv4 and
   of IPv6: the handshake, a write the peer acknowledges, and each side's
   end; a connection to a closed port, which a reset refuses; and one the
   client resets as it closes, whose reset has the timestamps. Then,
   with IPv6 off in A and in another namespace, B, a pair, va (1000,
   10.0.0.1/24) in A and vb (1001, 10.0.0.2/24) in B, carries the same,
   after the ARP request and answer. What is waited for is polled: the
   connection's TCP_INFO until nothing is unacknowledged, or a side is
   in the state it waits for; the case ends before ARP's timers (5 s)
   would probe again. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define NLM_F_REQUEST 1
#define NLM_F_ACK 4
#define NLM_F_DUMP 0x300
#define NLM_F_CREATE 0x400
#define NLMSG_ERROR 2
#define NLMSG_DONE 3
#define RTM_NEWLINK 16
#define RTM_GETLINK 18
#define RTM_NEWADDR 20
#define IFLA_IFNAME 3
#define IFLA_STATS 7
#define IFLA_LINKINFO 18
#define IFLA_STATS64 23
#define IFLA_NET_NS_FD 28
#define IFLA_INFO_KIND 1
#define IFLA_INFO_DATA 2
#define VETH_INFO_PEER 1
#define IFA_LOCAL 2
#define IFA_ADDRESS 1
#define VA 1000
#define VB 1001

struct body {
    unsigned char bytes[512];
    size_t len;
};
static unsigned seq;

static long result(long r) { return r < 0 ? -errno : r; }
static void raw(struct body *b, const void *value, size_t len) {
    memcpy(b->bytes + b->len, value, len);
    b->len += (len + 3) & ~3u;
}
static void put(struct body *b, unsigned short type, const void *value, size_t len) {
    unsigned short attribute[2] = {(unsigned short)(4 + len), type};
    memcpy(b->bytes + b->len, attribute, 4);
    memcpy(b->bytes + b->len + 4, value, len);
    b->len += (4 + len + 3) & ~3u;
}
static size_t begin(struct body *b, unsigned short type) {
    size_t at = b->len;
    put(b, type, NULL, 0);
    return at;
}
static void end(struct body *b, size_t at) {
    unsigned short len = (unsigned short)(b->len - at);
    memcpy(b->bytes + at, &len, 2);
}
/* Sends a request on `fd` and prints its acknowledgement's error. */
static void request(int fd, unsigned short type, const struct body *b, const char *label) {
    unsigned char buf[4096] = {0};
    const unsigned head[4] = {(unsigned)(16 + b->len), type | (NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE) << 16, ++seq, 0};
    memcpy(buf, head, 16);
    memcpy(buf + 16, b->bytes, b->len);
    send(fd, buf, head[0], 0);
    struct pollfd ready = {.fd = fd, .events = POLLIN};
    if (poll(&ready, 1, 2000) <= 0 || recv(fd, buf, sizeof buf, 0) < 20) {
        printf("%s: no answer\n", label);
        return;
    }
    int error;
    memcpy(&error, buf + 16, 4);
    printf("%s: error=%d\n", label, error);
}
static void up(int fd, int index, const char *label) {
    struct body b = {0};
    const unsigned m[4] = {0, (unsigned)index, IFF_UP, IFF_UP};
    raw(&b, m, 16);
    request(fd, RTM_NEWLINK, &b, label);
}
static void address(int fd, int index, const char *ip, const char *label) {
    struct body b = {0};
    const unsigned char m[8] = {AF_INET, 24, 0, 0, (unsigned char)index, (unsigned char)(index >> 8), 0, 0};
    unsigned char in[4];
    inet_pton(AF_INET, ip, in);
    raw(&b, m, 8);
    put(&b, IFA_LOCAL, in, 4);
    put(&b, IFA_ADDRESS, in, 4);
    request(fd, RTM_NEWADDR, &b, label);
}
static void write_file(const char *path, const char *text) {
    int fd = open(path, O_WRONLY);
    long n = fd < 0 ? -errno : result(write(fd, text, strlen(text)));
    if (fd >= 0) close(fd);
    printf("%s <- %s: %ld\n", path, text, n);
}

/* The lines of lo, va and vb in /proc/net/dev of the namespace the
   process is in, and each link's IFLA_STATS64 and IFLA_STATS, their first
   eight fields (packets, bytes, errors and drops), as the dump of `fd`
   gives them. */
static void counters(int fd, const char *label) {
    printf("-- %s\n", label);
    char text[8192];
    int f = open("/proc/net/dev", O_RDONLY);
    long n = f < 0 ? 0 : read(f, text, sizeof text - 1);
    if (f >= 0) close(f);
    text[n > 0 ? n : 0] = 0;
    for (char *line = text, *next; *line; line = next) {
        next = strchr(line, '\n');
        if (!next) break;
        *next++ = 0;
        if (strstr(line, " lo:") || strstr(line, " va:") || strstr(line, " vb:")) printf("%s\n", line);
    }
    unsigned char buf[16384];
    const unsigned char m[16] = {AF_UNSPEC};
    unsigned head[4] = {32, RTM_GETLINK | (NLM_F_REQUEST | NLM_F_DUMP) << 16, ++seq, 0};
    memcpy(buf, head, 16);
    memcpy(buf + 16, m, 16);
    send(fd, buf, 32, 0);
    for (;;) {
        struct pollfd ready = {.fd = fd, .events = POLLIN};
        if (poll(&ready, 1, 2000) <= 0) {
            printf("no end\n");
            return;
        }
        long got = recv(fd, buf, sizeof buf, 0);
        for (long at = 0; at + 16 <= got;) {
            unsigned len;
            unsigned short kind;
            memcpy(&len, buf + at, 4);
            memcpy(&kind, buf + at + 4, 2);
            if (len < 16 || at + len > got) break;
            if (kind == NLMSG_DONE || kind == NLMSG_ERROR) return;
            const unsigned char *msg = buf + at;
            char name[16] = "?";
            unsigned long long wide[8] = {0};
            unsigned narrow[8] = {0};
            for (unsigned a = 32; a + 4 <= len;) {
                unsigned short alen, type;
                memcpy(&alen, msg + a, 2);
                memcpy(&type, msg + a + 2, 2);
                if (alen < 4) break;
                if (type == IFLA_IFNAME) snprintf(name, sizeof name, "%s", (const char *)msg + a + 4);
                if (type == IFLA_STATS64 && alen >= 4 + 64) memcpy(wide, msg + a + 4, 64);
                if (type == IFLA_STATS && alen >= 4 + 32) memcpy(narrow, msg + a + 4, 32);
                a += (alen + 3) & ~3u;
            }
            at += (len + 3) & ~3u;
            if (strcmp(name, "lo") && strcmp(name, "va") && strcmp(name, "vb")) continue;
            printf("%s stats64", name);
            for (int i = 0; i < 8; i++) printf(" %llu", wide[i]);
            printf(" stats");
            for (int i = 0; i < 8; i++) printf(" %u", narrow[i]);
            printf("\n");
        }
    }
}

static int route_socket(void) { return socket(AF_NETLINK, SOCK_RAW, 0); }
/* Whether the link `index` that `fd` asks of is running (IFF_RUNNING),
   which Linux's link watch makes it a little after its carrier comes, as
   it gives it its queueing discipline (linkwatch_do_dev): waited for up
   to 2 s, so that nothing it sends is dropped before. */
static int running(int fd, int index) {
    for (int tries = 0; tries < 200; tries++) {
        unsigned char buf[4096];
        unsigned head[4] = {32, RTM_GETLINK | NLM_F_REQUEST << 16, ++seq, 0};
        const unsigned m[4] = {0, (unsigned)index, 0, 0};
        memcpy(buf, head, 16);
        memcpy(buf + 16, m, 16);
        send(fd, buf, 32, 0);
        struct pollfd ready = {.fd = fd, .events = POLLIN};
        if (poll(&ready, 1, 2000) <= 0) return 0;
        long got = recv(fd, buf, sizeof buf, 0);
        unsigned flags = 0;
        if (got >= 32) memcpy(&flags, buf + 24, 4);
        if (flags & IFF_RUNNING) return 1;
        struct timespec pause = {0, 10 * 1000 * 1000};
        nanosleep(&pause, NULL);
    }
    return 0;
}

/* The TCP_INFO state of `fd`, and how many of its segments are
   unacknowledged. */
static void info_of(int fd, int *state, int *unacked) {
    struct tcp_info i;
    socklen_t size = sizeof i;
    memset(&i, 0, sizeof i);
    getsockopt(fd, IPPROTO_TCP, TCP_INFO, &i, &size);
    *state = i.tcpi_state;
    *unacked = (int)i.tcpi_unacked;
}
/* Polls `fd` for up to 2 s until it has nothing unacknowledged, or, with
   `state`, until it is in that state; whether it waited in vain. */
static int settle(int fd, int state) {
    for (int tries = 0; tries < 200; tries++) {
        int now, unacked;
        info_of(fd, &now, &unacked);
        if (state ? now == state : unacked == 0) return 0;
        struct timespec pause = {0, 10 * 1000 * 1000};
        nanosleep(&pause, NULL);
    }
    return 1;
}
/* A connection from `family`'s `ip` to the listener `l` at `port`: the
   handshake, 5 bytes each way in turn, and each side's end, the client's
   first; then a connection to `port` + 1, where nothing listens. Each
   step is counted in the namespace of `fd`'s dump. */
static void tcp(int fd, int family, const char *ip, int port, int l, const char *label) {
    struct sockaddr_storage to = {0};
    socklen_t size;
    if (family == AF_INET) {
        struct sockaddr_in *a = (void *)&to;
        a->sin_family = AF_INET;
        a->sin_port = htons((unsigned short)port);
        inet_pton(AF_INET, ip, &a->sin_addr);
        size = sizeof *a;
    } else {
        struct sockaddr_in6 *a = (void *)&to;
        a->sin6_family = AF_INET6;
        a->sin6_port = htons((unsigned short)port);
        inet_pton(AF_INET6, ip, &a->sin6_addr);
        size = sizeof *a;
    }
    char text[200], buf[16];
    int c = socket(family, SOCK_STREAM, 0);
    printf("%s: connect=%ld", label, result(connect(c, (void *)&to, size)));
    int x = accept(l, NULL, NULL);
    printf(" accept=%d settled=%d\n", x >= 0, settle(c, 0));
    snprintf(text, sizeof text, "%s, connected", label);
    counters(fd, text);
    printf("write=%ld", result(write(c, "hello", 5)));
    long got = result(read(x, buf, sizeof buf));
    printf(" read=%ld settled=%d", got, settle(c, 0));
    printf(" write=%ld", result(write(x, "world", 5)));
    got = result(read(c, buf, sizeof buf));
    printf(" read=%ld settled=%d\n", got, settle(x, 0));
    snprintf(text, sizeof text, "%s, 5 bytes each way", label);
    counters(fd, text);
    /* The client's end is acknowledged once it is in FIN_WAIT2: its FIN
       does not count as unacknowledged. */
    printf("shutdown=%ld", result(shutdown(c, SHUT_WR)));
    long eof = result(read(x, buf, sizeof buf));
    printf(" eof=%ld settled=%d", eof, settle(c, TCP_FIN_WAIT2));
    printf(" shutdown=%ld", result(shutdown(x, SHUT_WR)));
    eof = result(read(c, buf, sizeof buf));
    printf(" eof=%ld closed=%d\n", eof, settle(x, TCP_CLOSE));
    close(c);
    close(x);
    snprintf(text, sizeof text, "%s, ended", label);
    counters(fd, text);
    int r = socket(family, SOCK_STREAM, 0);
    if (family == AF_INET)
        ((struct sockaddr_in *)&to)->sin_port = htons((unsigned short)(port + 1));
    else
        ((struct sockaddr_in6 *)&to)->sin6_port = htons((unsigned short)(port + 1));
    printf("connect to a closed port=%ld\n", result(connect(r, (void *)&to, size)));
    close(r);
    snprintf(text, sizeof text, "%s, refused", label);
    counters(fd, text);
    /* A connection the client resets, closing with a linger time of 0
       (tcp_send_active_reset): its reset carries the timestamps. */
    if (family == AF_INET)
        ((struct sockaddr_in *)&to)->sin_port = htons((unsigned short)port);
    else
        ((struct sockaddr_in6 *)&to)->sin6_port = htons((unsigned short)port);
    c = socket(family, SOCK_STREAM, 0);
    printf("connect again=%ld", result(connect(c, (void *)&to, size)));
    x = accept(l, NULL, NULL);
    printf(" accept=%d settled=%d", x >= 0, settle(c, 0));
    struct linger hard = {.l_onoff = 1, .l_linger = 0};
    setsockopt(c, SOL_SOCKET, SO_LINGER, &hard, sizeof hard);
    close(c);
    printf(" reset=%d\n", settle(x, TCP_CLOSE));
    close(x);
    snprintf(text, sizeof text, "%s, reset", label);
    counters(fd, text);
}
static int listener(int family, const char *ip, int port) {
    int fd = socket(family, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    if (family == AF_INET) {
        struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons((unsigned short)port)};
        inet_pton(AF_INET, ip, &a.sin_addr);
        printf("bind %s:%d=%ld", ip, port, result(bind(fd, (void *)&a, sizeof a)));
    } else {
        struct sockaddr_in6 a = {.sin6_family = AF_INET6, .sin6_port = htons((unsigned short)port)};
        inet_pton(AF_INET6, ip, &a.sin6_addr);
        printf("bind [%s]:%d=%ld", ip, port, result(bind(fd, (void *)&a, sizeof a)));
    }
    printf(" listen=%ld\n", result(listen(fd, 8)));
    return fd;
}

int main(int argc, char **argv) {
    if (argc < 2 || strcmp(argv[1], "net-dev-tcp")) return 99;
    setvbuf(stdout, NULL, _IOLBF, 0);
    printf("unshare=%ld\n", result(unshare(CLONE_NEWNET)));
    int ns_a = open("/proc/self/ns/net", O_RDONLY);
    int ctl = route_socket();
    up(ctl, 1, "lo up");
    tcp(ctl, AF_INET, "127.0.0.1", 6000, listener(AF_INET, "127.0.0.1", 6000), "127.0.0.1");
    tcp(ctl, AF_INET6, "::1", 6000, listener(AF_INET6, "::1", 6000), "::1");

    write_file("/proc/sys/net/ipv6/conf/all/disable_ipv6", "1");
    write_file("/proc/sys/net/ipv6/conf/default/disable_ipv6", "1");
    printf("unshare=%ld\n", result(unshare(CLONE_NEWNET)));
    int ns_b = open("/proc/self/ns/net", O_RDONLY);
    int far = route_socket();
    write_file("/proc/sys/net/ipv6/conf/all/disable_ipv6", "1");
    write_file("/proc/sys/net/ipv6/conf/default/disable_ipv6", "1");
    up(far, 1, "B's lo up");
    int lb = listener(AF_INET, "0.0.0.0", 7000);
    printf("setns=%ld\n", result(setns(ns_a, CLONE_NEWNET)));
    struct body m = {0};
    const unsigned a[4] = {0, VA, 0, 0}, b[4] = {0, VB, 0, 0};
    raw(&m, a, 16);
    put(&m, IFLA_IFNAME, "va", 3);
    size_t link = begin(&m, IFLA_LINKINFO);
    put(&m, IFLA_INFO_KIND, "veth", 5);
    size_t data = begin(&m, IFLA_INFO_DATA), peer = begin(&m, VETH_INFO_PEER);
    raw(&m, b, 16);
    put(&m, IFLA_IFNAME, "vb", 3);
    put(&m, IFLA_NET_NS_FD, &ns_b, 4);
    end(&m, peer);
    end(&m, data);
    end(&m, link);
    request(ctl, RTM_NEWLINK, &m, "make va, and vb in B");
    address(ctl, VA, "10.0.0.1", "va's 10.0.0.1/24");
    address(far, VB, "10.0.0.2", "vb's 10.0.0.2/24");
    up(ctl, VA, "va up");
    up(far, VB, "vb up");
    printf("running: %d %d\n", running(ctl, VA), running(far, VB));
    tcp(ctl, AF_INET, "10.0.0.2", 7000, lb, "10.0.0.2 across the pair");
    printf("setns=%ld\n", result(setns(ns_b, CLONE_NEWNET)));
    counters(far, "B");
    return 0;
}
