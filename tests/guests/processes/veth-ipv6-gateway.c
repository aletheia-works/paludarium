/* IPv6 routes through a gateway across a veth pair (so as root): a child,
   B, makes a network namespace of its own and waits; the parent, A, makes
   another and a pair, its end "va" (1000, 02:00:00:00:00:0a) in A and "vb"
   (1001, 02:00:00:00:00:0b) in B. The ends have 2001:db8::1/64 and
   2001:db8::2/64, B's loopback 2001:db8:2::2/128 and A's 2001:db8:5::1/128,
   all IFA_F_NODAD, and B routes 2001:db8:5::/64 through A's link-local
   address. A's routes through a gateway are refused for a group, the
   unspecified address, its own addresses, the loopback, an address no
   route without a gateway reaches (EHOSTUNREACH), a link-local gateway
   without a device or through lo, one through another device than its
   route's, and an on-link one without a device (ENODEV); an on-link one
   through va is taken without a route to it. 2001:db8:2::/64 through
   2001:db8::2 takes va as its device, is EEXIST again, and is replaced by
   one through vb's link-local address; a removal naming another gateway
   is ESRCH. UDP to B's loopback address resolves the gateway's neighbour,
   not the destination's, and B's answer to 2001:db8:5::1 comes back
   through its own gateway; TCP connects. Route lookups show the gateway
   and device, out and in through va or lo (RTA_IIF): strictly through
   the device for a link-local, loopback or group address, through lo for
   a local one, and EMSGSIZE for a group's. The routes of the main table
   through va are dumped, and what RTNLGRP_IPV6_ROUTE hears is shown in its
   order. The two processes take turns through pipes, so their lines come
   in one order; an address done and a neighbour resolved are waited for
   on netlink. */
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
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define NETLINK_ROUTE_ 0
#define RTM_NEWLINK 16
#define RTM_NEWADDR 20
#define RTM_NEWROUTE 24
#define RTM_DELROUTE 25
#define RTM_GETROUTE 26
#define RTM_NEWNEIGH 28
#define NLM_F_REQUEST 1
#define NLM_F_ACK 4
#define NLM_F_DUMP 0x300
#define NLM_F_REPLACE 0x100
#define NLM_F_EXCL 0x200
#define NLM_F_CREATE 0x400
#define IFLA_ADDRESS 1
#define IFLA_IFNAME 3
#define IFLA_MTU 4
#define IFLA_LINKINFO 18
#define IFLA_NET_NS_PID 19
#define IFLA_CARRIER 33
#define IFLA_INFO_KIND 1
#define IFLA_INFO_DATA 2
#define VETH_INFO_PEER 1
#define IFA_LOCAL 2
#define IFA_FLAGS 8
#define IFA_F_NODAD 0x02
#define RTA_DST 1
#define RTA_IIF 3
#define RTA_OIF 4
#define RTA_GATEWAY 5
#define RTA_PRIORITY 6
#define RTA_PREFSRC 7
#define RTA_TABLE 15
#define RTNH_F_ONLINK 4
#define RTM_F_FIB_MATCH 0x2000
#define NUD_REACHABLE 0x02
#define A_INDEX 1000
#define B_INDEX 1001


struct nl_address {
    unsigned short family;
    unsigned short pad;
    unsigned pid;
    unsigned groups;
};
struct nl_header {
    unsigned len;
    unsigned short type, flags;
    unsigned seq, pid;
};
struct ifinfo {
    unsigned char family, pad;
    unsigned short type;
    int index;
    unsigned flags, change;
};
struct ndmsg_ {
    unsigned char family, pad1;
    unsigned short pad2;
    int index;
    unsigned short state;
    unsigned char flags, type;
};
struct body {
    unsigned char bytes[1024];
    size_t len;
};

static const char *side = "A";
static unsigned seq;
/* RTNLGRP_LINK and RTNLGRP_IPV6_ROUTE, and RTNLGRP_NEIGH, what is waited
   for; and RTNLGRP_IPV6_ROUTE, what is shown. */
static int events = -1, resolved = -1, routes = -1;

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
static void put32(struct body *b, unsigned short type, unsigned value) { put(b, type, &value, 4); }
static size_t begin(struct body *b, unsigned short type) {
    size_t at = b->len;
    put(b, type, NULL, 0);
    return at;
}
static void end(struct body *b, size_t at) {
    unsigned short len = (unsigned short)(b->len - at);
    memcpy(b->bytes + at, &len, 2);
}
static void info(struct body *b, int index, unsigned flags, unsigned change) {
    struct ifinfo i = {.index = index, .flags = flags, .change = change};
    raw(b, &i, sizeof i);
}
static int route_socket(unsigned groups) {
    int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE_);
    struct nl_address at = {.family = AF_NETLINK, .groups = groups};
    bind(fd, (void *)&at, sizeof at);
    return fd;
}
/* Sends a request and prints its acknowledgement's error, which it
   gives. */
static int request(int fd, unsigned short type, unsigned short flags, const struct body *b, const char *label) {
    unsigned char buf[4096] = {0};
    struct nl_header *h = (void *)buf;
    h->len = sizeof *h + b->len;
    h->type = type;
    h->flags = NLM_F_REQUEST | NLM_F_ACK | flags;
    h->seq = ++seq;
    memcpy(buf + sizeof *h, b->bytes, b->len);
    struct nl_address kernel = {.family = AF_NETLINK};
    if (sendto(fd, buf, h->len, 0, (void *)&kernel, sizeof kernel) < 0) printf("%s: send=%d\n", side, -errno);
    for (;;) {
        struct pollfd ready = {.fd = fd, .events = POLLIN};
        if (poll(&ready, 1, 2000) <= 0) {
            printf("%s: %s: no answer\n", side, label);
            return 1;
        }
        long n = recv(fd, buf, sizeof buf, 0);
        if (n < (long)sizeof *h + 4) return 1;
        if (h->type == 2) {
            int error;
            memcpy(&error, buf + sizeof *h, 4);
            printf("%s: %s: error=%d\n", side, label, error);
            return error;
        }
    }
}
static void set_link(int fd, int index, int up, const char *label) {
    struct body b = {0};
    info(&b, index, up ? IFF_UP : 0, IFF_UP);
    request(fd, RTM_NEWLINK, 0, &b, label);
}
static void sysctl(const char *path, const char *value) {
    int fd = open(path, O_WRONLY);
    long r = result(fd < 0 ? fd : write(fd, value, strlen(value)));
    printf("%s: %s=%ld\n", side, path, r);
    if (fd >= 0) close(fd);
}
static void drain(int fd) {
    static unsigned char buf[65536];
    while (recv(fd, buf, sizeof buf, MSG_DONTWAIT) > 0) {
    }
}
static unsigned char wanted[16];
/* Whether `h` is what is waited for: the local route of `wanted` (an
   address done), the RTM_NEWLINK of the device of `index` with its
   carrier `carrier`, or the neighbour `wanted` in the state `state`. */
static int is(const struct nl_header *h, int index, int carrier, int state) {
    const unsigned char *body = (const unsigned char *)(h + 1);
    int len = (int)(h->len - sizeof *h);
    int start;
    if (state) {
        struct ndmsg_ n;
        if (h->type != RTM_NEWNEIGH || len < (int)sizeof n) return 0;
        memcpy(&n, body, sizeof n);
        if (n.family != AF_INET6 || n.state != state) return 0;
        start = (int)sizeof n;
    } else if (index) {
        int got;
        if (h->type != RTM_NEWLINK) return 0;
        memcpy(&got, body + 4, 4);
        if (got != index) return 0;
        start = 16;
    } else {
        if (h->type != RTM_NEWROUTE || body[0] != AF_INET6 || body[7] != 2) return 0;
        start = 12;
    }
    for (int a = start; a + 4 <= len;) {
        unsigned short alen, kind;
        memcpy(&alen, body + a, 2);
        memcpy(&kind, body + a + 2, 2);
        if (alen < 4 || a + alen > len) break;
        if (!index && kind == 1 && alen == 20) return !memcmp(body + a + 4, wanted, 16);
        if (index && (kind & 0x3fff) == IFLA_CARRIER && alen >= 5) return body[a + 4] == carrier;
        a += (alen + 3) & ~3;
    }
    return 0;
}
/* Waits, up to 5 s however much else comes, on `fd` for what `is` says. */
static void wait_for(int fd, const char *ip, int index, int carrier, int state, const char *label) {
    static unsigned char buf[65536];
    memset(wanted, 0, sizeof wanted);
    if (ip) inet_pton(AF_INET6, ip, wanted);
    struct timespec start, now;
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (;;) {
        clock_gettime(CLOCK_MONOTONIC, &now);
        long left = 5000 - ((now.tv_sec - start.tv_sec) * 1000 + (now.tv_nsec - start.tv_nsec) / 1000000);
        if (left <= 0) break;
        struct pollfd ready = {.fd = fd, .events = POLLIN};
        if (poll(&ready, 1, (int)(left < 1000 ? left : 1000)) <= 0) continue;
        long n;
        while ((n = recv(fd, buf, sizeof buf, MSG_DONTWAIT)) > 0)
            for (long at = 0; at + (long)sizeof(struct nl_header) <= n;) {
                const struct nl_header *h = (const void *)(buf + at);
                if (h->len < sizeof *h || at + h->len > n) break;
                if (is(h, index, carrier, state)) return;
                at += (h->len + 3) & ~3u;
            }
    }
    printf("%s: %s: never came\n", side, label);
}
/* Adds the IPv6 address `ip`/`prefix` of the device of `index`,
   IFA_F_NODAD, and waits for its local route. */
static void address6(int fd, int index, const char *ip, int prefix, const char *label) {
    struct body b = {0};
    const unsigned char m[8] = {AF_INET6, (unsigned char)prefix, IFA_F_NODAD, 0, (unsigned char)index,
                                (unsigned char)(index >> 8), 0, 0};
    unsigned char in[16];
    inet_pton(AF_INET6, ip, in);
    raw(&b, m, sizeof m);
    put(&b, IFA_LOCAL, in, 16);
    put32(&b, IFA_FLAGS, IFA_F_NODAD);
    drain(events);
    if (request(fd, RTM_NEWADDR, NLM_F_CREATE | NLM_F_EXCL, &b, label) == 0)
        wait_for(events, ip, 0, 0, 0, label);
}
/* Adds (`type` RTM_NEWROUTE, with `flags`) or removes an IPv6 route of
   the main table to `dst`/`prefix` through the gateway `via` (none for
   NULL), through the device of `oif` (none for 0), on link or not. */
static void route6(int fd, unsigned short type, unsigned short flags, const char *dst, int prefix, const char *via,
                   int oif, int onlink, const char *label) {
    struct body b = {0};
    unsigned char rtm[12] = {AF_INET6, (unsigned char)prefix, 0, 0, 254, 3, 0, 1};
    unsigned nh = onlink ? RTNH_F_ONLINK : 0;
    memcpy(rtm + 8, &nh, 4);
    unsigned char in[16];
    inet_pton(AF_INET6, dst, in);
    raw(&b, rtm, sizeof rtm);
    put(&b, RTA_DST, in, 16);
    if (via) {
        inet_pton(AF_INET6, via, in);
        put(&b, RTA_GATEWAY, in, 16);
    }
    if (oif) put32(&b, RTA_OIF, (unsigned)oif);
    request(fd, type, flags, &b, label);
}
/* Describes an IPv6 route message: table, type, protocol, flags,
   destination, gateway, the device it comes in on and the one it goes
   out through, preferred source and metric; 0 for another. */
static int describe(const struct nl_header *h, char *line, size_t size) {
    const unsigned char *body = (const unsigned char *)(h + 1);
    int len = (int)(h->len - sizeof *h);
    if ((h->type != RTM_NEWROUTE && h->type != RTM_DELROUTE) || body[0] != AF_INET6) return 0;
    char dst[64] = "::", via[64] = "-", src[64] = "-";
    int oif = 0, iif = 0;
    unsigned table = body[4], metric = 0, flags;
    memcpy(&flags, body + 8, 4);
    for (int a = 12; a + 4 <= len;) {
        unsigned short alen, kind;
        memcpy(&alen, body + a, 2);
        memcpy(&kind, body + a + 2, 2);
        if (alen < 4 || a + alen > len) break;
        const unsigned char *v = body + a + 4;
        if (kind == RTA_DST && alen == 20) inet_ntop(AF_INET6, v, dst, sizeof dst);
        if (kind == RTA_GATEWAY && alen == 20) inet_ntop(AF_INET6, v, via, sizeof via);
        if (kind == RTA_PREFSRC && alen == 20) inet_ntop(AF_INET6, v, src, sizeof src);
        if (kind == RTA_OIF && alen == 8) memcpy(&oif, v, 4);
        if (kind == RTA_IIF && alen == 8) memcpy(&iif, v, 4);
        if (kind == RTA_PRIORITY && alen == 8) memcpy(&metric, v, 4);
        if (kind == RTA_TABLE && alen == 8) memcpy(&table, v, 4);
        a += (alen + 3) & ~3;
    }
    snprintf(line, size, "%s table=%u type=%u proto=%u flags=0x%x %s/%u via %s iif=%d dev=%d src=%s metric=%u",
             h->type == RTM_NEWROUTE ? "route" : "-route", table, body[7], body[5], flags, dst, body[1], via, iif, oif,
             src, metric);
    return 1;
}
/* Dumps IPv6's routes of the main table through va. */
static void dump(int fd, const char *label) {
    static unsigned char buf[65536];
    struct {
        struct nl_header h;
        unsigned char m[12];
    } ask = {{sizeof ask, RTM_GETROUTE, NLM_F_REQUEST | NLM_F_DUMP, ++seq, 0}, {AF_INET6}};
    struct nl_address kernel = {.family = AF_NETLINK};
    sendto(fd, &ask, sizeof ask, 0, (void *)&kernel, sizeof kernel);
    for (;;) {
        struct pollfd ready = {.fd = fd, .events = POLLIN};
        if (poll(&ready, 1, 2000) <= 0) break;
        long n = recv(fd, buf, sizeof buf, 0);
        if (n <= 0) break;
        for (long at = 0; at + (long)sizeof(struct nl_header) <= n;) {
            const struct nl_header *h = (const void *)(buf + at);
            if (h->len < sizeof *h || at + h->len > n) break;
            if (h->type == 3 || h->type == 2) return;
            char line[256];
            if (describe(h, line, sizeof line) && strstr(line, "table=254 ") && strstr(line, "dev=1000 "))
                printf("%s: %s: %s\n", side, label, line);
            at += (h->len + 3) & ~3u;
        }
    }
    printf("%s: %s: no end\n", side, label);
}
/* Prints the routes of the main table `routes` heard since, in its
   order. */
static void heard(const char *label) {
    static unsigned char buf[65536];
    for (;;) {
        long n = recv(routes, buf, sizeof buf, MSG_DONTWAIT);
        if (n <= 0) return;
        for (long at = 0; at + (long)sizeof(struct nl_header) <= n;) {
            const struct nl_header *h = (const void *)(buf + at);
            if (h->len < sizeof *h || at + h->len > n) break;
            char line[256];
            if (describe(h, line, sizeof line) && strstr(line, "table=254 "))
                printf("%s: %s: %s\n", side, label, line);
            at += (h->len + 3) & ~3u;
        }
    }
}
/* Looks up the route to `dst`, coming in on the device of `iif`, or going
   out through that of `oif` (none for 0), with `flags`. */
static void get(int fd, const char *dst, int iif, int oif, unsigned flags, const char *label) {
    struct body b = {0};
    unsigned char rtm[12] = {AF_INET6, 128, 0, 0, 0, 0, 0, 0};
    memcpy(rtm + 8, &flags, 4);
    unsigned char in[16];
    inet_pton(AF_INET6, dst, in);
    raw(&b, rtm, sizeof rtm);
    put(&b, RTA_DST, in, 16);
    if (iif) put32(&b, RTA_IIF, (unsigned)iif);
    if (oif) put32(&b, RTA_OIF, (unsigned)oif);
    unsigned char buf[4096] = {0};
    struct nl_header *h = (void *)buf;
    h->len = sizeof *h + b.len;
    h->type = RTM_GETROUTE;
    h->flags = NLM_F_REQUEST;
    h->seq = ++seq;
    memcpy(buf + sizeof *h, b.bytes, b.len);
    struct nl_address kernel = {.family = AF_NETLINK};
    sendto(fd, buf, h->len, 0, (void *)&kernel, sizeof kernel);
    struct pollfd ready = {.fd = fd, .events = POLLIN};
    char line[256];
    if (poll(&ready, 1, 2000) <= 0 || recv(fd, buf, sizeof buf, 0) < (long)sizeof *h + 4) {
        printf("%s: %s: no answer\n", side, label);
    } else if (h->type == 2) {
        int error;
        memcpy(&error, buf + sizeof *h, 4);
        printf("%s: %s: error=%d\n", side, label, error);
    } else if (describe(h, line, sizeof line)) {
        printf("%s: %s: %s\n", side, label, line);
    }
}

static struct sockaddr_in6 at(const char *ip, int port) {
    struct sockaddr_in6 a = {.sin6_family = AF_INET6, .sin6_port = htons((unsigned short)port)};
    inet_pton(AF_INET6, ip, &a.sin6_addr);
    return a;
}
/* The address of a socket's end, without its port where `port` is 0. */
static void show_name(int fd, int peer, int port, const char *label) {
    struct sockaddr_in6 a = {0};
    socklen_t len = sizeof a;
    long r = result(peer ? getpeername(fd, (void *)&a, &len) : getsockname(fd, (void *)&a, &len));
    char ip[64] = "?";
    inet_ntop(AF_INET6, &a.sin6_addr, ip, sizeof ip);
    if (port)
        printf("%s: %s=%ld %s:%u\n", side, label, r, ip, ntohs(a.sin6_port));
    else
        printf("%s: %s=%ld %s\n", side, label, r, ip);
}
/* Receives a datagram on `fd`, and gives where it came from. */
static struct sockaddr_in6 receive(int fd, const char *label) {
    char buf[64] = {0};
    struct sockaddr_in6 from = {0};
    struct pollfd ready = {.fd = fd, .events = POLLIN};
    if (poll(&ready, 1, 2000) <= 0) {
        printf("%s: %s: nothing\n", side, label);
        return from;
    }
    socklen_t len = sizeof from;
    long n = result(recvfrom(fd, buf, sizeof buf - 1, 0, (void *)&from, &len));
    char ip[64] = "-";
    if (from.sin6_family == AF_INET6) inet_ntop(AF_INET6, &from.sin6_addr, ip, sizeof ip);
    printf("%s: %s=%ld \"%s\" from %s\n", side, label, n, n > 0 ? buf : "", ip);
    return from;
}

/* B: makes its namespace, then does what A writes to `in`, one letter at
   a time, writing back to `out` when done. */
static void child(int in, int out) {
    side = "B";
    if (unshare(CLONE_NEWNET) < 0) printf("B: unshare=%d\n", -errno);
    int ctl = route_socket(0);
    events = route_socket(1 | 0x400);
    int listener = -1, udp = -1;
    fflush(stdout);
    if (write(out, "r", 1) != 1) _exit(2);
    for (char command; read(in, &command, 1) == 1;) {
        if (command == 'u') {
            sysctl("/proc/sys/net/ipv6/conf/vb/accept_dad", "0");
            set_link(ctl, 1, 1, "up lo");
            /* Its carrier comes with va's, which A waits for. */
            set_link(ctl, B_INDEX, 1, "up the end");
            address6(ctl, B_INDEX, "2001:db8::2", 64, "add its address");
            address6(ctl, 1, "2001:db8:2::2", 128, "add lo's address");
            route6(ctl, RTM_NEWROUTE, NLM_F_CREATE | NLM_F_EXCL, "2001:db8:5::", 64, "fe80::ff:fe00:a", B_INDEX, 0,
                   "route 2001:db8:5::/64 through A's link-local address");
            listener = socket(AF_INET6, SOCK_STREAM, 0);
            struct sockaddr_in6 any = at("::", 5000);
            printf("B: bind=%ld\n", result(bind(listener, (void *)&any, sizeof any)));
            printf("B: listen=%ld\n", result(listen(listener, 4)));
            udp = socket(AF_INET6, SOCK_DGRAM, 0);
            any = at("::", 6000);
            printf("B: bind udp=%ld\n", result(bind(udp, (void *)&any, sizeof any)));
        } else if (command == 'd') {
            /* A datagram, answered where it came from. */
            struct sockaddr_in6 from = receive(udp, "udp recvfrom");
            if (from.sin6_family == AF_INET6)
                printf("B: udp reply=%ld\n", result(sendto(udp, "back", 4, 0, (void *)&from, sizeof from)));
        } else if (command == 'a') {
            int conn = (int)result(accept(listener, NULL, NULL));
            printf("B: accept=%d\n", conn >= 0 ? 0 : conn);
            show_name(conn, 0, 1, "accepted at");
            show_name(conn, 1, 0, "accepted from");
            char buf[16] = {0};
            printf("B: read=%ld \"%s\"\n", result(read(conn, buf, sizeof buf - 1)), buf);
            printf("B: write=%ld\n", result(write(conn, "pong", 4)));
            close(conn);
        } else if (command == 'x') {
            fflush(stdout);
            _exit(0);
        }
        fflush(stdout);
        if (write(out, "d", 1) != 1) _exit(2);
    }
    _exit(0);
}

static void make_pair(int ctl, int ns) {
    struct body m = {0};
    const unsigned char mac_a[6] = {2, 0, 0, 0, 0, 0x0a}, mac_b[6] = {2, 0, 0, 0, 0, 0x0b};
    info(&m, A_INDEX, 0, 0);
    put(&m, IFLA_IFNAME, "va", 3);
    put(&m, IFLA_ADDRESS, mac_a, 6);
    size_t link = begin(&m, IFLA_LINKINFO);
    put(&m, IFLA_INFO_KIND, "veth", 5);
    size_t data = begin(&m, IFLA_INFO_DATA);
    size_t peer = begin(&m, VETH_INFO_PEER);
    info(&m, B_INDEX, 0, 0);
    put(&m, IFLA_IFNAME, "vb", 3);
    put(&m, IFLA_ADDRESS, mac_b, 6);
    put32(&m, IFLA_NET_NS_PID, (unsigned)ns);
    end(&m, peer);
    end(&m, data);
    end(&m, link);
    request(ctl, RTM_NEWLINK, NLM_F_CREATE | NLM_F_EXCL, &m, "make a pair");
}

int main(int argc, char **argv) {
    if (argc < 2 || strcmp(argv[1], "veth-ipv6-gateway")) return 99;
    setvbuf(stdout, NULL, _IOLBF, 0);
    int to_b[2], to_a[2];
    if (pipe(to_b) < 0 || pipe(to_a) < 0) return 98;
    fflush(stdout);
    pid_t b = fork();
    if (b == 0) {
        close(to_b[1]), close(to_a[0]);
        child(to_b[0], to_a[1]);
    }
    close(to_b[0]), close(to_a[1]);
    char ready;
    if (read(to_a[0], &ready, 1) != 1) return 97;
#define B_DOES(command)                                                       \
    do {                                                                      \
        fflush(stdout);                                                       \
        if (write(to_b[1], command, 1) != 1 || read(to_a[0], &ready, 1) != 1) \
            printf("A: B gone\n");                                            \
    } while (0)
    printf("A: unshare=%ld\n", result(unshare(CLONE_NEWNET)));
    int ctl = route_socket(0);
    events = route_socket(1 | 0x400);
    resolved = route_socket(4);
    make_pair(ctl, b);
    sysctl("/proc/sys/net/ipv6/conf/va/accept_dad", "0");
    set_link(ctl, 1, 1, "up lo");
    B_DOES("u");
    drain(events);
    set_link(ctl, A_INDEX, 1, "up the end");
    wait_for(events, NULL, A_INDEX, 1, 0, "the carrier");
    wait_for(events, "fe80::ff:fe00:a", 0, 0, 0, "the link-local address");
    address6(ctl, A_INDEX, "2001:db8::1", 64, "add its address");
    address6(ctl, 1, "2001:db8:5::1", 128, "add lo's address");
    routes = route_socket(0x400);

    /* Gateways refused. */
    const unsigned short add = NLM_F_CREATE | NLM_F_EXCL;
    route6(ctl, RTM_NEWROUTE, add, "2001:db8:2::", 64, "ff02::1", 0, 0, "through a group");
    route6(ctl, RTM_NEWROUTE, add, "2001:db8:2::", 64, "::", 0, 0, "through ::");
    route6(ctl, RTM_NEWROUTE, add, "2001:db8:2::", 64, "2001:db8::1", 0, 0, "through its own address");
    route6(ctl, RTM_NEWROUTE, add, "2001:db8:2::", 64, "2001:db8::1", A_INDEX, 0, "through its own address on va");
    route6(ctl, RTM_NEWROUTE, add, "2001:db8:2::", 64, "2001:db8:5::1", 0, 0, "through lo's address");
    route6(ctl, RTM_NEWROUTE, add, "2001:db8:2::", 64, "::1", 0, 0, "through ::1");
    route6(ctl, RTM_NEWROUTE, add, "2001:db8:2::", 64, "2001:db8:9::1", 0, 0, "through an address no route has");
    route6(ctl, RTM_NEWROUTE, add, "2001:db8:2::", 64, "::ffff:10.0.0.1", 0, 0, "through an IPv4 one");
    route6(ctl, RTM_NEWROUTE, add, "2001:db8:2::", 64, "fe80::ff:fe00:b", 0, 0, "through a link-local one alone");
    route6(ctl, RTM_NEWROUTE, add, "2001:db8:2::", 64, "fe80::ff:fe00:b", 1, 0, "through a link-local one on lo");
    route6(ctl, RTM_NEWROUTE, add, "2001:db8:2::", 64, "fe80::ff:fe00:a", A_INDEX, 0,
           "through its own link-local one");
    route6(ctl, RTM_NEWROUTE, add, "2001:db8:2::", 64, "2001:db8::2", 1, 0, "through 2001:db8::2 on lo");
    route6(ctl, RTM_NEWROUTE, add, "2001:db8:2::", 64, "2001:db8:7::1", A_INDEX, 0, "through 2001:db8:7::1 on va");
    route6(ctl, RTM_NEWROUTE, add, "2001:db8:2::", 64, "2001:db8:7::1", 0, 1, "on link without a device");
    /* On link, no route to it is needed. */
    route6(ctl, RTM_NEWROUTE, add, "2001:db8:3::", 64, "2001:db8:7::1", A_INDEX, 1, "2001:db8:3::/64 on link");
    route6(ctl, RTM_NEWROUTE, add, "2001:db8:4::", 64, "2001:db8:5::1", A_INDEX, 1, "on link through lo's address");
    /* Through 2001:db8::2: va, which its route goes through. */
    route6(ctl, RTM_NEWROUTE, add, "2001:db8:2::", 64, "2001:db8::2", 0, 0, "2001:db8:2::/64 through 2001:db8::2");
    route6(ctl, RTM_NEWROUTE, add, "2001:db8:2::", 64, "2001:db8::2", 0, 0, "again");
    route6(ctl, RTM_NEWROUTE, add, "2001:db8:6::", 64, "2001:db8:2::2", 0, 0, "through a gateway's destination");
    heard("heard");
    dump(ctl, "routes");
    get(ctl, "2001:db8:2::2", 0, 0, 0, "route to 2001:db8:2::2");

    /* UDP to B's loopback: the gateway's neighbour is resolved. */
    int u = socket(AF_INET6, SOCK_DGRAM, 0);
    struct sockaddr_in6 mine = at("::", 6100);
    printf("A: bind udp=%ld\n", result(bind(u, (void *)&mine, sizeof mine)));
    struct sockaddr_in6 to = at("2001:db8:2::2", 6000);
    drain(resolved);
    printf("A: udp sendto=%ld\n", result(sendto(u, "hello", 5, 0, (void *)&to, sizeof to)));
    wait_for(resolved, "2001:db8::2", 0, 0, NUD_REACHABLE, "2001:db8::2 reachable");
    B_DOES("d");
    receive(u, "udp recvfrom");

    /* Through vb's link-local address instead. */
    route6(ctl, RTM_NEWROUTE, NLM_F_REPLACE, "2001:db8:2::", 64, "fe80::ff:fe00:b", A_INDEX, 0,
           "replace it through fe80::ff:fe00:b");
    route6(ctl, RTM_DELROUTE, 0, "2001:db8:2::", 64, "2001:db8::2", 0, 0, "remove it through 2001:db8::2");
    heard("heard");
    get(ctl, "2001:db8:2::2", 0, 0, 0, "route to 2001:db8:2::2");
    get(ctl, "2001:db8:2::2", 0, 0, RTM_F_FIB_MATCH, "its route");
    /* From lo's address, which B's answer reaches through A's link-local
       address. */
    int five = socket(AF_INET6, SOCK_DGRAM, 0);
    mine = at("2001:db8:5::1", 6200);
    printf("A: bind 2001:db8:5::1=%ld\n", result(bind(five, (void *)&mine, sizeof mine)));
    drain(resolved);
    printf("A: udp sendto=%ld\n", result(sendto(five, "again", 5, 0, (void *)&to, sizeof to)));
    wait_for(resolved, "fe80::ff:fe00:b", 0, 0, NUD_REACHABLE, "fe80::ff:fe00:b reachable");
    B_DOES("d");
    receive(five, "udp recvfrom");
    int c = socket(AF_INET6, SOCK_STREAM, 0);
    to = at("2001:db8:2::2", 5000);
    printf("A: connect=%ld\n", result(connect(c, (void *)&to, sizeof to)));
    show_name(c, 0, 0, "connected from");
    printf("A: write=%ld\n", result(write(c, "ping", 4)));
    B_DOES("a");
    char buf[16] = {0};
    printf("A: read=%ld \"%s\"\n", result(read(c, buf, sizeof buf - 1)), buf);
    close(c);

    /* Lookups in through va and lo, and out. */
    get(ctl, "2001:db8::1", A_INDEX, 0, 0, "in on va to 2001:db8::1");
    get(ctl, "2001:db8:2::2", A_INDEX, 0, 0, "in on va to 2001:db8:2::2");
    get(ctl, "2001:db8:2::2", A_INDEX, 0, RTM_F_FIB_MATCH, "in on va to 2001:db8:2::2's route");
    get(ctl, "fe80::ff:fe00:a", A_INDEX, 0, 0, "in on va to fe80::ff:fe00:a");
    get(ctl, "fe80::ff:fe00:b", A_INDEX, 0, 0, "in on va to fe80::ff:fe00:b");
    get(ctl, "ff02::1", A_INDEX, 0, 0, "in on va to ff02::1");
    get(ctl, "2001:db8:9::9", A_INDEX, 0, 0, "in on va to 2001:db8:9::9");
    get(ctl, "::1", A_INDEX, 0, 0, "in on va to ::1");
    get(ctl, "fe80::ff:fe00:a", 1, 0, 0, "in on lo to fe80::ff:fe00:a");
    get(ctl, "2001:db8:2::2", 1, 0, 0, "in on lo to 2001:db8:2::2");
    get(ctl, "2001:db8:5::1", 1, 0, 0, "in on lo to 2001:db8:5::1");
    get(ctl, "2001:db8::2", 0, 0, 0, "out to 2001:db8::2");
    get(ctl, "2001:db8::2", 0, 1, 0, "out through lo to 2001:db8::2");
    get(ctl, "2001:db8::1", 0, 1, 0, "out through lo to 2001:db8::1");
    get(ctl, "fe80::ff:fe00:b", 0, A_INDEX, 0, "out through va to fe80::ff:fe00:b");
    get(ctl, "fe80::ff:fe00:b", 0, 1, 0, "out through lo to fe80::ff:fe00:b");
    get(ctl, "2001:db8:3::1", 0, 0, 0, "out to 2001:db8:3::1");

    route6(ctl, RTM_DELROUTE, 0, "2001:db8:2::", 64, "fe80::ff:fe00:b", 0, 0, "remove it");
    route6(ctl, RTM_DELROUTE, 0, "2001:db8:3::", 64, NULL, A_INDEX, 0, "remove the one on link");
    heard("heard");
    dump(ctl, "routes left");
    B_DOES("x");
    int status = 0;
    waitpid(b, &status, 0);
    printf("A: B exited=%d\n", WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    return 0;
}
