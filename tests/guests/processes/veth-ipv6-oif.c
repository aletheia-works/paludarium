/* The device an IPv6 datagram goes out through (so as root): IPV6_UNICAST_IF,
   IPV6_MULTICAST_IF and the sticky IPV6_PKTINFO. A child, B, makes a network
   namespace of its own and waits; the parent, A, makes another and two
   pairs, "va" (1000) with "vb" (1001) and "vc" (1002) with "vd" (1003), vb
   and vd in B, both with fe80::1 and 2001:db8:9::1. A reaches 2001:db8:9::/64
   on link through va and through vc, 2001:db8:a::/64 by a gateway through
   va and, of a higher metric, through vc, 2001:db8:1::/64 through va only
   and 2001:db8:3::/64 through vc only. B has a UDP socket bound to each end, and
   tells which took a datagram, and from where.
   The options take a device there is (ENODEV, EADDRNOTAVAIL), in so many
   bytes, the socket's own where it has one, and not IPV6_MULTICAST_IF for
   TCP; IPV6_PKTINFO takes any device. A datagram goes through its address's
   scope ID's device, else the socket's, else IPV6_PKTINFO's, else
   IPV6_MULTICAST_IF's to a group and IPV6_UNICAST_IF's to another address,
   from an address of that device's. Where its source is chosen already, the
   last two only prefer their device. A connect asks in the same order, but
   takes no link-local address without the socket's device, and a group of
   the link makes IPV6_MULTICAST_IF's the socket's. TCP asks none of them.
   Sockets bound to a group by scope IDs of two devices share a port. The two
   processes take turns through pipes, so their lines come in one order; an
   address done is waited for on netlink. */
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
#define NLM_F_REQUEST 1
#define NLM_F_ACK 4
#define NLM_F_EXCL 0x200
#define NLM_F_CREATE 0x400
#define IFLA_ADDRESS 1
#define IFLA_IFNAME 3
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
#define RTA_OIF 4
#define RTA_GATEWAY 5
#define RTA_PRIORITY 6
#define NLM_F_APPEND_ 0x800
#define IPV6_MULTICAST_IF_ 17
#define IPV6_PKTINFO_ 50
#define IPV6_UNICAST_IF_ 76
#define SO_BINDTOIFINDEX_ 62
#define VA 1000
#define VB 1001
#define VC 1002
#define VD 1003

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
struct body {
    unsigned char bytes[1024];
    size_t len;
};

static const char *side = "A";
static unsigned seq;
/* RTNLGRP_LINK and RTNLGRP_IPV6_ROUTE, what is waited for. */
static int events = -1;

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
   address done), or the RTM_NEWLINK of the device of `index` with its
   carrier. */
static int is(const struct nl_header *h, int index) {
    const unsigned char *body = (const unsigned char *)(h + 1);
    int len = (int)(h->len - sizeof *h);
    int start;
    if (index) {
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
        if (index && (kind & 0x3fff) == IFLA_CARRIER && alen >= 5) return body[a + 4] == 1;
        a += (alen + 3) & ~3;
    }
    return 0;
}
/* Waits, up to 5 s however much else comes, for what `is` says. */
static void wait_for(const char *ip, int index, const char *label) {
    static unsigned char buf[65536];
    memset(wanted, 0, sizeof wanted);
    if (ip) inet_pton(AF_INET6, ip, wanted);
    struct timespec start, now;
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (;;) {
        clock_gettime(CLOCK_MONOTONIC, &now);
        long left = 5000 - ((now.tv_sec - start.tv_sec) * 1000 + (now.tv_nsec - start.tv_nsec) / 1000000);
        if (left <= 0) break;
        struct pollfd ready = {.fd = events, .events = POLLIN};
        if (poll(&ready, 1, (int)(left < 1000 ? left : 1000)) <= 0) continue;
        long n;
        while ((n = recv(events, buf, sizeof buf, MSG_DONTWAIT)) > 0)
            for (long at = 0; at + (long)sizeof(struct nl_header) <= n;) {
                const struct nl_header *h = (const void *)(buf + at);
                if (h->len < sizeof *h || at + h->len > n) break;
                if (is(h, index)) return;
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
    if (request(fd, RTM_NEWADDR, NLM_F_CREATE | NLM_F_EXCL, &b, label) == 0) wait_for(ip, 0, label);
}
static void make_pair(int ctl, int a, const char *name_a, int b, const char *name_b, unsigned char last, int ns) {
    struct body m = {0};
    const unsigned char mac_a[6] = {2, 0, 0, 0, 0, last}, mac_b[6] = {2, 0, 0, 0, 0, (unsigned char)(last + 1)};
    info(&m, a, 0, 0);
    put(&m, IFLA_IFNAME, name_a, 3);
    put(&m, IFLA_ADDRESS, mac_a, 6);
    size_t link = begin(&m, IFLA_LINKINFO);
    put(&m, IFLA_INFO_KIND, "veth", 5);
    size_t data = begin(&m, IFLA_INFO_DATA);
    size_t peer = begin(&m, VETH_INFO_PEER);
    info(&m, b, 0, 0);
    put(&m, IFLA_IFNAME, name_b, 3);
    put(&m, IFLA_ADDRESS, mac_b, 6);
    put32(&m, IFLA_NET_NS_PID, (unsigned)ns);
    end(&m, peer);
    end(&m, data);
    end(&m, link);
    request(ctl, RTM_NEWLINK, NLM_F_CREATE | NLM_F_EXCL, &m, "make a pair");
}
/* A route to `ip`/64 through the device of `index`, by the gateway `via`
   or on link, beside any other, of the metric `metric` or the default. */
static void route(int ctl, const char *ip, int index, const char *via, unsigned metric, const char *label) {
    struct body b = {0};
    const unsigned char m[12] = {AF_INET6, 64, 0, 0, 254, 4, 0, 1, 0, 0, 0, 0};
    unsigned char in[16];
    inet_pton(AF_INET6, ip, in);
    raw(&b, m, sizeof m);
    put(&b, RTA_DST, in, 16);
    put32(&b, RTA_OIF, (unsigned)index);
    if (via) {
        inet_pton(AF_INET6, via, in);
        put(&b, RTA_GATEWAY, in, 16);
    }
    if (metric) put32(&b, RTA_PRIORITY, metric);
    request(ctl, RTM_NEWROUTE, NLM_F_CREATE | NLM_F_APPEND_, &b, label);
}

static struct sockaddr_in6 at(const char *ip, int port, unsigned scope) {
    struct sockaddr_in6 a = {.sin6_family = AF_INET6, .sin6_port = htons((unsigned short)port), .sin6_scope_id = scope};
    inet_pton(AF_INET6, ip, &a.sin6_addr);
    return a;
}
static int udp(void) { return socket(AF_INET6, SOCK_DGRAM, 0); }
static void bind6(int fd, const char *ip, int port, unsigned scope, const char *label) {
    struct sockaddr_in6 a = at(ip, port, scope);
    printf("%s: %s: bind=%ld\n", side, label, result(bind(fd, (void *)&a, sizeof a)));
}
static void show(const char *label, long r, const struct sockaddr_in6 *a) {
    char ip[64] = "-";
    if (a->sin6_family == AF_INET6) inet_ntop(AF_INET6, &a->sin6_addr, ip, sizeof ip);
    printf("%s: %s=%ld %s scope=%u\n", side, label, r, ip, a->sin6_scope_id);
}
/* Where the socket is, its ephemeral port left out, and its device. */
static void name(int fd) {
    struct sockaddr_in6 a = {0};
    socklen_t len = sizeof a;
    show("getsockname", result(getsockname(fd, (void *)&a, &len)), &a);
    int device = -1;
    len = sizeof device;
    long r = result(getsockopt(fd, SOL_SOCKET, SO_BINDTOIFINDEX_, &device, &len));
    printf("%s: its device=%ld %d\n", side, r, device);
}
static void connect6(int fd, const char *ip, int port, unsigned scope, const char *label) {
    struct sockaddr_in6 to = at(ip, port, scope);
    printf("%s: %s: connect=%ld\n", side, label, result(connect(fd, (void *)&to, sizeof to)));
}
static void send_to(int fd, const char *ip, int port, unsigned scope, const char *what) {
    struct sockaddr_in6 to = at(ip, port, scope);
    printf("%s: %s, to %s: sendto=%ld\n", side, what, ip, result(sendto(fd, what, strlen(what), 0, (void *)&to, sizeof to)));
}
static void set(int fd, int option, const void *value, int len, const char *label) {
    printf("%s: %s: setsockopt=%ld\n", side, label, result(setsockopt(fd, IPPROTO_IPV6, option, value, (socklen_t)len)));
}
static void unicast(int fd, int index, const char *label) {
    int value = (int)htonl((unsigned)index);
    set(fd, IPV6_UNICAST_IF_, &value, sizeof value, label);
}
static void multicast(int fd, int index, const char *label) {
    set(fd, IPV6_MULTICAST_IF_, &index, sizeof index, label);
}
static void pktinfo(int fd, int index, const char *label) {
    struct {
        unsigned char address[16];
        int index;
    } info = {.index = index};
    set(fd, IPV6_PKTINFO_, &info, sizeof info, label);
}
static void device(int fd, int index, const char *label) {
    printf("%s: %s: setsockopt=%ld\n", side, label,
           result(setsockopt(fd, SOL_SOCKET, SO_BINDTOIFINDEX_, &index, sizeof index)));
}
/* Gets `option` in `room` bytes. */
static void get(int fd, int option, int room, const char *label) {
    unsigned char got[32] = {0};
    socklen_t len = (socklen_t)room;
    long r = result(getsockopt(fd, IPPROTO_IPV6, option, got, &len));
    printf("%s: %s: getsockopt=%ld len=%u", side, label, r, len);
    for (unsigned i = 0; r == 0 && i < len && i < sizeof got; i++) printf(" %02x", got[i]);
    printf("\n");
}

/* B: makes its namespace, then does what A writes to `in`, one letter at
   a time, writing back to `out` when done. */
static void child(int in, int out) {
    side = "B";
    if (unshare(CLONE_NEWNET) < 0) printf("B: unshare=%d\n", -errno);
    int ctl = route_socket(0);
    events = route_socket(1 | 0x400);
    int on[2] = {-1, -1};
    const char *const names[2] = {"vb", "vd"};
    fflush(stdout);
    if (write(out, "r", 1) != 1) _exit(2);
    for (char command; read(in, &command, 1) == 1;) {
        if (command == 'u') {
            sysctl("/proc/sys/net/ipv6/conf/vb/accept_dad", "0");
            sysctl("/proc/sys/net/ipv6/conf/vd/accept_dad", "0");
            set_link(ctl, 1, 1, "up lo");
            set_link(ctl, VB, 1, "up vb");
            set_link(ctl, VD, 1, "up vd");
            address6(ctl, VB, "fe80::1", 64, "vb's fe80::1");
            address6(ctl, VD, "fe80::1", 64, "vd's fe80::1");
            address6(ctl, VB, "2001:db8:9::1", 128, "vb's 2001:db8:9::1");
            address6(ctl, VD, "2001:db8:9::1", 128, "vd's 2001:db8:9::1");
            address6(ctl, VB, "2001:db8:1::2", 64, "vb's 2001:db8:1::2");
            address6(ctl, VD, "2001:db8:3::2", 64, "vd's 2001:db8:3::2");
            address6(ctl, 1, "2001:db8:a::1", 128, "lo's 2001:db8:a::1");
            for (int i = 0; i < 2; i++) {
                on[i] = udp();
                device(on[i], i ? VD : VB, names[i]);
                bind6(on[i], "::", 6000, 0, names[i]);
            }
        } else if (command == 'd') {
            /* A datagram, on either. */
            struct pollfd ready[2] = {{.fd = on[0], .events = POLLIN}, {.fd = on[1], .events = POLLIN}};
            if (poll(ready, 2, 5000) <= 0) printf("B: nothing\n");
            for (int i = 0; i < 2; i++) {
                if (!(ready[i].revents & POLLIN)) continue;
                char buf[64] = {0}, line[128];
                struct sockaddr_in6 from = {0};
                socklen_t len = sizeof from;
                long n = result(recvfrom(on[i], buf, sizeof buf - 1, 0, (void *)&from, &len));
                snprintf(line, sizeof line, "\"%s\" on %s", n > 0 ? buf : "", names[i]);
                show(line, n, &from);
            }
        } else if (command == 'x') {
            fflush(stdout);
            _exit(0);
        }
        fflush(stdout);
        if (write(out, "d", 1) != 1) _exit(2);
    }
    _exit(0);
}

int main(int argc, char **argv) {
    if (argc < 2 || strcmp(argv[1], "veth-ipv6-oif")) return 99;
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
    make_pair(ctl, VA, "va", VB, "vb", 0x0a, b);
    make_pair(ctl, VC, "vc", VD, "vd", 0x0c, b);
    sysctl("/proc/sys/net/ipv6/conf/va/accept_dad", "0");
    sysctl("/proc/sys/net/ipv6/conf/vc/accept_dad", "0");
    set_link(ctl, 1, 1, "up lo");
    B_DOES("u");
    drain(events);
    set_link(ctl, VA, 1, "up va");
    wait_for(NULL, VA, "va's carrier");
    wait_for("fe80::ff:fe00:a", 0, "va's link-local address");
    drain(events);
    set_link(ctl, VC, 1, "up vc");
    wait_for(NULL, VC, "vc's carrier");
    wait_for("fe80::ff:fe00:c", 0, "vc's link-local address");
    address6(ctl, VA, "2001:db8:1::1", 64, "va's 2001:db8:1::1");
    address6(ctl, VC, "2001:db8:3::1", 64, "vc's 2001:db8:3::1");
    route(ctl, "2001:db8:9::", VA, NULL, 0, "2001:db8:9::/64 through va");
    route(ctl, "2001:db8:9::", VC, NULL, 0, "2001:db8:9::/64 through vc");
    route(ctl, "2001:db8:a::", VA, "fe80::1", 100, "2001:db8:a::/64 through va");
    route(ctl, "2001:db8:a::", VC, "fe80::1", 200, "2001:db8:a::/64 through vc");

    /* The options. */
    const void *nowhere = (const void *)8;
    int s = udp(), t = socket(AF_INET6, SOCK_STREAM, 0), four = socket(AF_INET, SOCK_DGRAM, 0);
    get(s, IPV6_MULTICAST_IF_, 4, "IPV6_MULTICAST_IF unset");
    get(s, IPV6_UNICAST_IF_, 4, "IPV6_UNICAST_IF unset");
    get(s, IPV6_PKTINFO_, 20, "IPV6_PKTINFO");
    multicast(s, VA, "IPV6_MULTICAST_IF va");
    get(s, IPV6_MULTICAST_IF_, 32, "IPV6_MULTICAST_IF of va");
    multicast(s, 9999, "IPV6_MULTICAST_IF of none");
    multicast(s, -1, "IPV6_MULTICAST_IF -1");
    set(s, IPV6_MULTICAST_IF_, &(int){VC}, 3, "IPV6_MULTICAST_IF in 3 bytes");
    set(s, IPV6_MULTICAST_IF_, &(long){VC}, 8, "IPV6_MULTICAST_IF vc in 8 bytes");
    get(s, IPV6_MULTICAST_IF_, 4, "IPV6_MULTICAST_IF of vc");
    set(s, IPV6_MULTICAST_IF_, nowhere, 4, "IPV6_MULTICAST_IF from nowhere");
    set(s, IPV6_MULTICAST_IF_, NULL, 4, "IPV6_MULTICAST_IF from NULL");
    get(s, IPV6_MULTICAST_IF_, 4, "IPV6_MULTICAST_IF after");
    multicast(t, VA, "IPV6_MULTICAST_IF, TCP");
    set(t, IPV6_MULTICAST_IF_, nowhere, 4, "IPV6_MULTICAST_IF, TCP, from nowhere");
    multicast(four, VA, "IPV6_MULTICAST_IF, IPv4");
    get(four, IPV6_MULTICAST_IF_, 4, "IPV6_MULTICAST_IF, IPv4");
    unicast(s, VC, "IPV6_UNICAST_IF vc");
    get(s, IPV6_UNICAST_IF_, 4, "IPV6_UNICAST_IF of vc");
    get(s, IPV6_UNICAST_IF_, 2, "IPV6_UNICAST_IF in 2 bytes");
    unicast(s, 9999, "IPV6_UNICAST_IF of none");
    unicast(s, -1, "IPV6_UNICAST_IF -1");
    set(s, IPV6_UNICAST_IF_, &(int){VA}, 4, "IPV6_UNICAST_IF va in host order");
    set(s, IPV6_UNICAST_IF_, &(long){(long)htonl(VA)}, 8, "IPV6_UNICAST_IF in 8 bytes");
    set(s, IPV6_UNICAST_IF_, nowhere, 8, "IPV6_UNICAST_IF in 8 bytes from nowhere");
    set(s, IPV6_UNICAST_IF_, NULL, 4, "IPV6_UNICAST_IF from NULL");
    get(s, IPV6_UNICAST_IF_, 4, "IPV6_UNICAST_IF after");
    unicast(t, VA, "IPV6_UNICAST_IF, TCP");
    get(t, IPV6_UNICAST_IF_, 4, "IPV6_UNICAST_IF, TCP");
    pktinfo(s, 9999, "IPV6_PKTINFO of none");
    pktinfo(s, -1, "IPV6_PKTINFO -1");
    set(s, IPV6_PKTINFO_, "0123456789012345678", 19, "IPV6_PKTINFO in 19 bytes");
    set(s, IPV6_PKTINFO_, nowhere, 3, "IPV6_PKTINFO in 3 bytes from nowhere");
    set(s, IPV6_PKTINFO_, nowhere, 19, "IPV6_PKTINFO in 19 bytes from nowhere");
    set(s, IPV6_PKTINFO_, NULL, 20, "IPV6_PKTINFO from NULL");
    set(s, IPV6_PKTINFO_, NULL, 0, "IPV6_PKTINFO from NULL, no bytes");
    pktinfo(t, VA, "IPV6_PKTINFO, TCP");
    device(s, VA, "to va");
    multicast(s, VA, "IPV6_MULTICAST_IF va, on va");
    multicast(s, VC, "IPV6_MULTICAST_IF vc, on va");
    multicast(s, 9999, "IPV6_MULTICAST_IF of none, on va");
    multicast(s, 0, "IPV6_MULTICAST_IF none, on va");
    unicast(s, VA, "IPV6_UNICAST_IF va, on va");
    unicast(s, 9999, "IPV6_UNICAST_IF of none, on va");
    unicast(s, 0, "IPV6_UNICAST_IF none, on va");
    pktinfo(s, VA, "IPV6_PKTINFO va, on va");
    pktinfo(s, VC, "IPV6_PKTINFO vc, on va");
    pktinfo(s, 0, "IPV6_PKTINFO none, on va");
    close(s), close(t), close(four);

    /* Datagrams to a link-local address, of no scope ID. */
    s = udp();
    unicast(s, VC, "IPV6_UNICAST_IF vc");
    send_to(s, "fe80::1", 6000, 0, "unicast vc");
    B_DOES("d");
    unicast(s, VA, "IPV6_UNICAST_IF va");
    send_to(s, "fe80::1", 6000, 0, "unicast va");
    B_DOES("d");
    pktinfo(s, VC, "IPV6_PKTINFO vc");
    send_to(s, "fe80::1", 6000, 0, "pktinfo vc, unicast va");
    B_DOES("d");
    device(s, VA, "to va");
    send_to(s, "fe80::1", 6000, 0, "on va, pktinfo vc");
    B_DOES("d");
    send_to(s, "fe80::1", 6000, VC, "scope ID vc, on va");
    B_DOES("d");
    device(s, 0, "to none");
    pktinfo(s, 9999, "IPV6_PKTINFO of none");
    send_to(s, "fe80::1", 6000, 0, "pktinfo of none");
    close(s);
    /* To a global address both reach, from the device's address. */
    s = udp();
    unicast(s, VC, "IPV6_UNICAST_IF vc");
    send_to(s, "2001:db8:9::1", 6000, 0, "unicast vc");
    B_DOES("d");
    send_to(s, "2001:db8:a::1", 6000, 0, "unicast vc, by a gateway");
    B_DOES("d");
    unicast(s, VA, "IPV6_UNICAST_IF va");
    send_to(s, "2001:db8:9::1", 6000, 0, "unicast va");
    B_DOES("d");
    multicast(s, VC, "IPV6_MULTICAST_IF vc");
    send_to(s, "2001:db8:9::1", 6000, 0, "unicast va, multicast vc");
    B_DOES("d");
    send_to(s, "2001:db8:3::2", 6000, 0, "unicast va");
    send_to(s, "2001:db8:3::1", 6000, 0, "unicast va");
    send_to(s, "::1", 6000, 0, "unicast va");
    send_to(s, "::", 6000, 0, "unicast va");
    unicast(s, 1, "IPV6_UNICAST_IF lo");
    send_to(s, "::1", 6000, 0, "unicast lo");
    send_to(s, "2001:db8:9::1", 6000, 0, "unicast lo");
    device(s, VA, "to va");
    send_to(s, "::", 6000, 0, "on va");
    close(s);
    /* From an address bound: the device is only preferred. */
    s = udp();
    bind6(s, "2001:db8:1::1", 6100, 0, "to va's address");
    unicast(s, VC, "IPV6_UNICAST_IF vc");
    send_to(s, "2001:db8:9::1", 6000, 0, "bound, unicast vc");
    B_DOES("d");
    send_to(s, "2001:db8:a::1", 6000, 0, "bound, unicast vc, by a gateway");
    B_DOES("d");
    send_to(s, "2001:db8:1::2", 6000, 0, "bound, unicast vc");
    B_DOES("d");
    send_to(s, "fe80::1", 6000, 0, "bound, unicast vc");
    B_DOES("d");
    pktinfo(s, 9999, "IPV6_PKTINFO of none");
    send_to(s, "2001:db8:1::2", 6000, 0, "bound, pktinfo of none");
    B_DOES("d");
    send_to(s, "fe80::1", 6000, 0, "bound, pktinfo of none");
    send_to(s, "::1", 6000, 0, "bound, pktinfo of none");
    send_to(s, "2001:db8:3::1", 6000, 0, "bound, pktinfo of none");
    close(s);

    /* Connects. */
    s = udp();
    unicast(s, VC, "IPV6_UNICAST_IF vc");
    connect6(s, "fe80::1", 6000, 0, "unicast vc, link-local");
    connect6(s, "2001:db8:9::1", 6000, 0, "unicast vc, global");
    name(s);
    printf("A: send=%ld\n", result(send(s, "connected", 9, 0)));
    B_DOES("d");
    connect6(s, "2001:db8:1::2", 6000, 0, "then through va only");
    name(s);
    close(s);
    s = udp();
    unicast(s, VC, "IPV6_UNICAST_IF vc");
    connect6(s, "2001:db8:1::2", 6000, 0, "unicast vc, through va only");
    connect6(s, "ff02::5", 6000, 0, "unicast vc, a group of the link");
    pktinfo(s, VA, "IPV6_PKTINFO va");
    connect6(s, "ff02::5", 6000, 0, "pktinfo va, a group of the link");
    connect6(s, "2001:db8:9::1", 6000, 0, "pktinfo va, unicast vc, global");
    name(s);
    close(s);
    s = udp();
    connect6(s, "ff02::5", 6000, 0, "a group of the link");
    multicast(s, VC, "IPV6_MULTICAST_IF vc");
    connect6(s, "fe80::1", 6000, 0, "multicast vc, link-local");
    connect6(s, "ff02::5", 6000, 0, "multicast vc, a group of the link");
    name(s);
    close(s);
    s = udp();
    multicast(s, VC, "IPV6_MULTICAST_IF vc");
    connect6(s, "ff02::5", 6000, VA, "multicast vc, a group of the link, scope ID va");
    name(s);
    close(s);
    s = udp();
    multicast(s, VC, "IPV6_MULTICAST_IF vc");
    unicast(s, VA, "IPV6_UNICAST_IF va");
    connect6(s, "ff0e::5", 6000, 0, "multicast vc, unicast va, a global group");
    name(s);
    close(s);
    s = udp();
    multicast(s, 1, "IPV6_MULTICAST_IF lo");
    connect6(s, "ff0e::5", 6000, 0, "multicast lo, a global group");
    send_to(s, "ff0e::5", 6000, 0, "multicast lo");
    multicast(s, VA, "IPV6_MULTICAST_IF va");
    send_to(s, "ff02::5", 6000, 0, "multicast va");
    close(s);
    /* The scope ID's device gives the source. */
    s = udp();
    connect6(s, "fe80::1", 6000, VC, "scope ID vc");
    name(s);
    close(s);
    s = socket(AF_INET6, SOCK_STREAM, 0);
    unicast(s, VC, "IPV6_UNICAST_IF vc");
    pktinfo(s, VC, "IPV6_PKTINFO vc");
    connect6(s, "2001:db8:1::2", 6001, 0, "tcp, unicast and pktinfo vc, through va only");
    close(s);

    /* Scope IDs' devices share a port. */
    s = udp(), t = udp();
    int again = udp();
    bind6(s, "ff02::5", 6200, VA, "a group on va");
    bind6(t, "ff02::5", 6200, VC, "a group on vc");
    bind6(again, "ff02::5", 6200, VC, "a group on vc again");
    close(s), close(t), close(again);
    B_DOES("x");
    int status = 0;
    waitpid(b, &status, 0);
    printf("A: B exited=%d\n", WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    return 0;
}
