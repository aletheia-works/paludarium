/* What a device's counters take of neighbour discovery (so as root): a
   veth pair, va (1000, 02:00:00:00:00:0a) in a network namespace A and
   vb (1001, ...:0b) in another, B, with IPv6 and without duplicate
   address detection, both forwarding, so that neither solicits routers.
   Each sends MLD reports of its own groups, again on Linux's timers, which
   are not counted here: the case asks Linux to send them again after
   1 ms (mldv2_unsolicited_report_interval, which is not here, so what the
   write gives is not shown), waits until va's counters have stayed for
   2 s, then shows what each step adds to them. A datagram to vb's
   link-local address takes a neighbour solicitation to its
   solicited-node group with va's link-layer address, and vb's solicited
   advertisement back with its own (ndisc_send_ns, ndisc_send_na), 86
   bytes each; one back, from B, takes none, as vb learnt va from the
   solicitation. The case ends before the neighbours' timers (5 s) would
   probe. */
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
static void write_file(const char *path, const char *text) {
    int fd = open(path, O_WRONLY);
    long n = fd < 0 ? -errno : result(write(fd, text, strlen(text)));
    if (fd >= 0) close(fd);
    printf("%s <- %s: %ld\n", path, text, n);
}

static int bound(int family, const char *ip, int port) {
    int fd = socket(family, SOCK_DGRAM, 0);
    int big = 1 << 20;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &big, sizeof big);
    if (family == AF_INET) {
        struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons((unsigned short)port)};
        inet_pton(AF_INET, ip, &a.sin_addr);
        printf("bind %s:%d=%ld\n", ip, port, result(bind(fd, (void *)&a, sizeof a)));
    } else {
        struct sockaddr_in6 a = {.sin6_family = AF_INET6, .sin6_port = htons((unsigned short)port)};
        inet_pton(AF_INET6, ip, &a.sin6_addr);
        printf("bind [%s]:%d=%ld\n", ip, port, result(bind(fd, (void *)&a, sizeof a)));
    }
    return fd;
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

/* The packets and bytes va or vb has sent and taken in, by the
   /proc/net/dev of the namespace the process is in. */
static void tally(const char *name, unsigned long long t[4]) {
    char text[8192], key[8];
    snprintf(key, sizeof key, " %s:", name);
    int f = open("/proc/net/dev", O_RDONLY);
    long n = f < 0 ? 0 : read(f, text, sizeof text - 1);
    if (f >= 0) close(f);
    text[n > 0 ? n : 0] = 0;
    memset(t, 0, 4 * sizeof *t);
    char *line = strstr(text, key);
    if (!line) return;
    unsigned long long v[16] = {0};
    sscanf(line + strlen(key), "%llu %llu %llu %llu %llu %llu %llu %llu %llu %llu", &v[0], &v[1], &v[2], &v[3], &v[4],
           &v[5], &v[6], &v[7], &v[8], &v[9]);
    t[0] = v[1], t[1] = v[0], t[2] = v[9], t[3] = v[8];
}
static void delta(const char *name, unsigned long long before[4], const char *label) {
    unsigned long long now[4];
    tally(name, now);
    printf("-- %s: %s rx %llu packets %llu bytes, tx %llu packets %llu bytes\n", label, name, now[0] - before[0],
           now[1] - before[1], now[2] - before[2], now[3] - before[3]);
    memcpy(before, now, sizeof now);
}
/* Writes `text` to `path`, showing nothing of how it went. */
static void quietly(const char *path, const char *text) {
    int fd = open(path, O_WRONLY);
    if (fd < 0) return;
    if (write(fd, text, strlen(text)) < 0) {
    }
    close(fd);
}
static double seconds(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec + (double)t.tv_nsec / 1e9;
}
/* Polls the file `path` until it has `entry`, for 10 s at most. */
static int await_file(const char *path, const char *entry) {
    char text[8192];
    for (double until = seconds() + 10; seconds() < until;) {
        int f = open(path, O_RDONLY);
        long n = f < 0 ? 0 : read(f, text, sizeof text - 1);
        if (f >= 0) close(f);
        text[n > 0 ? n : 0] = 0;
        if (strstr(text, entry)) return 0;
        struct timespec pause = {0, 20 * 1000 * 1000};
        nanosleep(&pause, NULL);
    }
    return 1;
}
/* Polls va's counters until they have stayed for 2 s, for 15 s at most:
   whether they never did. */
static int settle(void) {
    unsigned long long last[4], now[4];
    tally("va", last);
    double since = seconds();
    for (double until = since + 15; seconds() < until;) {
        struct timespec pause = {0, 50 * 1000 * 1000};
        nanosleep(&pause, NULL);
        tally("va", now);
        if (memcmp(now, last, sizeof now)) {
            memcpy(last, now, sizeof now);
            since = seconds();
        } else if (seconds() - since >= 2) {
            return 0;
        }
    }
    return 1;
}

int main(int argc, char **argv) {
    if (argc < 2 || strcmp(argv[1], "net-dev-ndisc")) return 99;
    setvbuf(stdout, NULL, _IOLBF, 0);
    printf("unshare=%ld\n", result(unshare(CLONE_NEWNET)));
    int ns_a = open("/proc/self/ns/net", O_RDONLY);
    int ctl = route_socket();
    write_file("/proc/sys/net/ipv6/conf/default/accept_dad", "0");
    write_file("/proc/sys/net/ipv6/conf/default/forwarding", "1");
    quietly("/proc/sys/net/ipv6/conf/default/mldv2_unsolicited_report_interval", "1");
    up(ctl, 1, "lo up");
    printf("unshare=%ld\n", result(unshare(CLONE_NEWNET)));
    int ns_b = open("/proc/self/ns/net", O_RDONLY);
    int far = route_socket();
    write_file("/proc/sys/net/ipv6/conf/default/accept_dad", "0");
    write_file("/proc/sys/net/ipv6/conf/default/forwarding", "1");
    quietly("/proc/sys/net/ipv6/conf/default/mldv2_unsolicited_report_interval", "1");
    up(far, 1, "B's lo up");
    int rb = bound(AF_INET6, "::", 7000);
    printf("setns=%ld\n", result(setns(ns_a, CLONE_NEWNET)));
    int ra = bound(AF_INET6, "::", 7000);
    struct body m = {0};
    const unsigned a[4] = {0, VA, 0, 0}, b[4] = {0, VB, 0, 0};
    const unsigned char mac_a[6] = {2, 0, 0, 0, 0, 0x0a}, mac_b[6] = {2, 0, 0, 0, 0, 0x0b};
    raw(&m, a, 16);
    put(&m, IFLA_IFNAME, "va", 3);
    put(&m, 1, mac_a, 6);
    size_t link = begin(&m, IFLA_LINKINFO);
    put(&m, IFLA_INFO_KIND, "veth", 5);
    size_t data = begin(&m, IFLA_INFO_DATA), peer = begin(&m, VETH_INFO_PEER);
    raw(&m, b, 16);
    put(&m, IFLA_IFNAME, "vb", 3);
    put(&m, 1, mac_b, 6);
    put(&m, IFLA_NET_NS_FD, &ns_b, 4);
    end(&m, peer);
    end(&m, data);
    end(&m, link);
    request(ctl, RTM_NEWLINK, &m, "make va, and vb in B");
    up(ctl, VA, "va up");
    up(far, VB, "vb up");
    printf("running: %d %d\n", running(ctl, VA), running(far, VB));
    printf("va's link-local address waited for: %d\n", await_file("/proc/net/if_inet6", "fe80000000000000000000fffe00000a"));
    printf("setns=%ld\n", result(setns(ns_b, CLONE_NEWNET)));
    printf("vb's link-local address waited for: %d\n", await_file("/proc/net/if_inet6", "fe80000000000000000000fffe00000b"));
    printf("setns=%ld\n", result(setns(ns_a, CLONE_NEWNET)));
    printf("settled: %d\n", settle() == 0);

    unsigned long long va[4], vb[4];
    tally("va", va);
    int s = socket(AF_INET6, SOCK_DGRAM, 0);
    struct sockaddr_in6 to = {.sin6_family = AF_INET6, .sin6_port = htons(7000), .sin6_scope_id = VA};
    inet_pton(AF_INET6, "fe80::ff:fe00:b", &to.sin6_addr);
    printf("10 bytes to vb's fe80::ff:fe00:b: %ld", result(sendto(s, "0123456789", 10, 0, (void *)&to, sizeof to)));
    struct pollfd ready = {.fd = rb, .events = POLLIN};
    printf(" taken=%d\n", poll(&ready, 1, 3000));
    delta("va", va, "the solicitation, its answer and the datagram");

    printf("setns=%ld\n", result(setns(ns_b, CLONE_NEWNET)));
    tally("vb", vb);
    int t = socket(AF_INET6, SOCK_DGRAM, 0);
    to.sin6_scope_id = VB;
    inet_pton(AF_INET6, "fe80::ff:fe00:a", &to.sin6_addr);
    printf("10 bytes back to va's fe80::ff:fe00:a: %ld", result(sendto(t, "0123456789", 10, 0, (void *)&to, sizeof to)));
    ready.fd = ra;
    printf(" taken=%d\n", poll(&ready, 1, 3000));
    delta("vb", vb, "the datagram back, as vb knows va");
    return 0;
}
