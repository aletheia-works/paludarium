/* Which answers come back through veth ends, where a route back goes by
   another way than the one there (so as root): a network namespace with
   "va" (1000, 2001:db8::1/64) and "vc" (1002, 2001:db8:1::1/64), whose
   peers "vb" and "vd", in another, have 2001:db8::2 and 2001:db8:1::2,
   with IPv6 addresses on each lo which the other routes through either
   pair, by a hash of its own. A connection, a refusal and a port
   unreachable come back through whichever they take; that of a listener
   bound to a device goes out through it (inet6_csk_route_req), and one to
   a socket bound to a device comes through that alone; one to a
   link-local address goes out through the device it came in on. Then
   what IPv4 sends to 0.0.0.0/8, routed as any other but for 0.0.0.0
   itself (ipv4_is_zeronet), and route lookups from a loopback source out
   of an end (__mkroute_output). */
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
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define NETLINK_ROUTE_ 0
#define RTM_NEWLINK 16
#define RTM_NEWADDR 20
#define RTM_NEWROUTE 24
#define RTM_GETROUTE 26
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
#define IFA_ADDRESS_ 1
#define IFA_FLAGS 8
#define IFA_F_NODAD 0x02
#define RTA_DST 1
#define RTA_SRC 2
#define RTA_OIF 4
#define RTA_GATEWAY 5
#define RTA_MULTIPATH 9
#define RTM_F_FIB_MATCH 0x2000
#define VA 1000
#define VB 1001
#define VC 1002
#define VD 1003
/* Each source and destination's addresses on lo. */
#define COUNT 40

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

static unsigned seq;
/* RTNLGRP_LINK and RTNLGRP_IPV6_ROUTE of this or the other namespace, what
   is waited for. */
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
    if (sendto(fd, buf, h->len, 0, (void *)&kernel, sizeof kernel) < 0) printf("send=%d\n", -errno);
    for (;;) {
        struct pollfd ready = {.fd = fd, .events = POLLIN};
        if (poll(&ready, 1, 2000) <= 0) {
            printf("%s: no answer\n", label);
            return 1;
        }
        long n = recv(fd, buf, sizeof buf, 0);
        if (n < (long)sizeof *h + 4) return 1;
        if (h->type == 2) {
            int error;
            memcpy(&error, buf + sizeof *h, 4);
            printf("%s: error=%d\n", label, error);
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
    printf("%s=%ld\n", path, r);
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
        if (!index && kind == RTA_DST && alen == 20) return !memcmp(body + a + 4, wanted, 16);
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
    printf("%s: never came\n", label);
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
/* Brings the device of `index` up and waits for its carrier and its
   link-local address `ll`. */
static void up(int fd, int index, const char *ll, const char *label) {
    drain(events);
    set_link(fd, index, 1, label);
    wait_for(NULL, index, "its carrier");
    wait_for(ll, 0, "its link-local address");
}
static void make_pair(int ctl, int a, const char *name_a, int b, const char *name_b, unsigned char last) {
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
    put32(&m, IFLA_NET_NS_PID, (unsigned)getpid());
    end(&m, peer);
    end(&m, data);
    end(&m, link);
    request(ctl, RTM_NEWLINK, NLM_F_CREATE | NLM_F_EXCL, &m, "make a pair");
}


/* Adds a route to `dst`/64 through the gateways `one`, on `dev_one`, and
   `two`, on `dev_two`, of even weights. */
static void route6(int fd, const char *dst, const char *one, int dev_one, const char *two, int dev_two,
                   const char *label) {
    struct body b = {0};
    const unsigned char rtm[12] = {AF_INET6, 64, 0, 0, 254, 3, 0, 1};
    const char *via[] = {one, two};
    const int oif[] = {dev_one, dev_two};
    unsigned char in[16];
    inet_pton(AF_INET6, dst, in);
    raw(&b, rtm, sizeof rtm);
    put(&b, RTA_DST, in, 16);
    size_t mp = begin(&b, RTA_MULTIPATH);
    for (int i = 0; i < 2; i++) {
        size_t at = b.len;
        unsigned char rtnh[8] = {0};
        memcpy(rtnh + 4, &oif[i], 4);
        raw(&b, rtnh, sizeof rtnh);
        inet_pton(AF_INET6, via[i], in);
        put(&b, RTA_GATEWAY, in, 16);
        unsigned short len = (unsigned short)(b.len - at);
        memcpy(b.bytes + at, &len, 2);
    }
    end(&b, mp);
    request(fd, RTM_NEWROUTE, NLM_F_CREATE | NLM_F_EXCL, &b, label);
}
/* The address `net`::`host`, on `port`, of the device `scope`. */
static struct sockaddr_in6 at6(const char *net, int host, int port, int scope) {
    struct sockaddr_in6 a = {.sin6_family = AF_INET6, .sin6_port = htons((unsigned short)port)};
    char text[64];
    snprintf(text, sizeof text, "%s%x", net, host);
    inet_pton(AF_INET6, text, &a.sin6_addr);
    a.sin6_scope_id = (unsigned)scope;
    return a;
}
static int listener(const char *device, int port) {
    struct sockaddr_in6 any = {.sin6_family = AF_INET6, .sin6_port = htons((unsigned short)port)};
    int s = socket(AF_INET6, SOCK_STREAM, 0);
    long d = device ? result(setsockopt(s, SOL_SOCKET, SO_BINDTODEVICE, device, 3)) : 0;
    long b = result(bind(s, (void *)&any, sizeof any));
    printf("listener on %s: %ld %ld %ld\n", device ? device : "any", d, b, result(listen(s, 64)));
    return s;
}
/* A connection of a socket bound to `from` and the device `device` (none
   for NULL) to `to`, given up after 300 ms, which the listener `s` then
   accepts (-1 for one of none). */
static long opens(const struct sockaddr_in6 *from, const struct sockaddr_in6 *to, const char *device, int s) {
    int c = socket(AF_INET6, SOCK_STREAM, 0);
    struct timeval limit = {.tv_usec = 300000};
    setsockopt(c, SOL_SOCKET, SO_SNDTIMEO, &limit, sizeof limit);
    if (device) setsockopt(c, SOL_SOCKET, SO_BINDTODEVICE, device, 3);
    if (from) bind(c, (void *)from, sizeof *from);
    long r = result(connect(c, (void *)to, sizeof *to));
    if (r == 0 && s >= 0) close(accept(s, NULL, NULL));
    close(c);
    return r;
}
/* A datagram to `to`, where nothing is, from a socket connected there:
   what the next one gives. */
static long unreachable(const struct sockaddr_in6 *from, const struct sockaddr_in6 *to) {
    int c = socket(AF_INET6, SOCK_DGRAM, 0);
    if (from) bind(c, (void *)from, sizeof *from);
    if (connect(c, (void *)to, sizeof *to) < 0) return -errno;
    send(c, "x", 1, 0);
    struct pollfd ready = {.fd = c, .events = POLLIN};
    poll(&ready, 1, 2000);
    long r = result(send(c, "x", 1, 0));
    close(c);
    return r;
}
static const char *share(int count) { return count == 0 ? "none" : count == COUNT ? "all" : "some"; }
/* The type of a lookup of the IPv4 address `dst` from `src` (none for
   NULL) through `oif` (0 for any), with the flags `flags`, or its error. */
static void lookup4_from(int fd, const char *dst, const char *src, int oif, unsigned flags, const char *label) {
    struct body b = {0};
    unsigned char rtm[12] = {AF_INET, 32, src ? 32 : 0};
    memcpy(rtm + 8, &flags, 4);
    unsigned char in[4];
    inet_pton(AF_INET, dst, in);
    raw(&b, rtm, sizeof rtm);
    put(&b, RTA_DST, in, 4);
    if (src) {
        inet_pton(AF_INET, src, in);
        put(&b, RTA_SRC, in, 4);
    }
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
    if (poll(&ready, 1, 2000) <= 0 || recv(fd, buf, sizeof buf, 0) < (long)sizeof *h + 12) {
        printf("%s: no answer\n", label);
        return;
    }
    int error;
    memcpy(&error, buf + sizeof *h, 4);
    if (h->type == 2) printf("%s: error=%d\n", label, error);
    else printf("%s: kind=%d\n", label, buf[sizeof *h + 7]);
}
static void lookup4(int fd, const char *dst, int oif, const char *label) { lookup4_from(fd, dst, NULL, oif, 0, label); }
/* What sending and connecting to the IPv4 address `dst` give, of sockets
   bound to `device` (none for NULL). */
static void reach4(const char *dst, const char *device, const char *label) {
    struct sockaddr_in to = {.sin_family = AF_INET, .sin_port = htons(7000)};
    inet_pton(AF_INET, dst, &to.sin_addr);
    int u = socket(AF_INET, SOCK_DGRAM, 0), c = socket(AF_INET, SOCK_DGRAM, 0), t = socket(AF_INET, SOCK_STREAM, 0);
    if (device) {
        setsockopt(u, SOL_SOCKET, SO_BINDTODEVICE, device, 3);
        setsockopt(c, SOL_SOCKET, SO_BINDTODEVICE, device, 3);
        setsockopt(t, SOL_SOCKET, SO_BINDTODEVICE, device, 3);
    }
    long sent = result(sendto(u, "x", 1, 0, (void *)&to, sizeof to));
    long connected = result(connect(c, (void *)&to, sizeof to));
    printf("%s: sendto=%ld connect=%ld stream=%ld\n", label, sent, connected,
           result(connect(t, (void *)&to, sizeof to)));
    close(u);
    close(c);
    close(t);
}
static void address4(int fd, int index, const char *ip, int prefix, const char *label) {
    struct body b = {0};
    const unsigned char m[8] = {AF_INET, (unsigned char)prefix, 0, 0, (unsigned char)index,
                                (unsigned char)(index >> 8), 0, 0};
    unsigned char in[4];
    inet_pton(AF_INET, ip, in);
    raw(&b, m, sizeof m);
    put(&b, IFA_LOCAL, in, 4);
    put(&b, IFA_ADDRESS_, in, 4);
    request(fd, RTM_NEWADDR, NLM_F_CREATE | NLM_F_EXCL, &b, label);
}
static void default4(int fd, int oif, const char *label) {
    struct body b = {0};
    const unsigned char rtm[12] = {AF_INET, 0, 0, 0, 254, 3, 253, 1};
    raw(&b, rtm, sizeof rtm);
    put32(&b, RTA_OIF, (unsigned)oif);
    request(fd, RTM_NEWROUTE, NLM_F_CREATE | NLM_F_EXCL, &b, label);
}

int main(int argc, char **argv) {
    if (argc < 2 || strcmp(argv[1], "veth-answers")) return 99;
    setvbuf(stdout, NULL, _IOLBF, 0);
    printf("unshare=%ld\n", result(unshare(CLONE_NEWNET)));
    int ctl = route_socket(0), here = route_socket(1 | 0x400);
    int ns = open("/proc/self/ns/net", O_RDONLY);
    printf("unshare=%ld\n", result(unshare(CLONE_NEWNET)));
    int far = route_socket(0), there = route_socket(1 | 0x400);
    make_pair(ctl, VA, "va", VB, "vb", 0x0a);
    make_pair(ctl, VC, "vc", VD, "vd", 0x0c);
    sysctl("/proc/sys/net/ipv6/conf/vb/accept_dad", "0");
    sysctl("/proc/sys/net/ipv6/conf/vd/accept_dad", "0");
    int far_ns = open("/proc/self/ns/net", O_RDONLY);
    printf("setns=%ld\n", result(setns(ns, CLONE_NEWNET)));
    sysctl("/proc/sys/net/ipv6/conf/va/accept_dad", "0");
    sysctl("/proc/sys/net/ipv6/conf/vc/accept_dad", "0");
    set_link(ctl, 1, 1, "up lo");
    set_link(far, 1, 1, "up the other lo");
    set_link(far, VB, 1, "up vb");
    set_link(far, VD, 1, "up vd");
    events = here;
    up(ctl, VA, "fe80::ff:fe00:a", "up va");
    events = there;
    wait_for("fe80::ff:fe00:b", 0, "vb's link-local address");
    events = here;
    up(ctl, VC, "fe80::ff:fe00:c", "up vc");
    events = there;
    wait_for("fe80::ff:fe00:d", 0, "vd's link-local address");
    address6(far, VB, "2001:db8::2", 64, "add vb's address");
    address6(far, VD, "2001:db8:1::2", 64, "add vd's address");
    char text[64];
    for (int i = 1; i <= COUNT; i++) {
        snprintf(text, sizeof text, "2001:db8:2::%x", i);
        address6(far, 1, text, 128, text);
    }
    events = here;
    address6(ctl, VA, "2001:db8::1", 64, "add va's address");
    address6(ctl, VC, "2001:db8:1::1", 64, "add vc's address");
    for (int i = 1; i <= COUNT; i++) {
        snprintf(text, sizeof text, "2001:db8:5::%x", i);
        address6(ctl, 1, text, 128, text);
    }
    route6(ctl, "2001:db8:2::", "2001:db8::2", VA, "2001:db8:1::2", VC, "2001:db8:2::/64 through va and vc");
    route6(far, "2001:db8:5::", "2001:db8::1", VB, "2001:db8:1::1", VD, "2001:db8:5::/64 through vb and vd");
    printf("setns=%ld\n", result(setns(far_ns, CLONE_NEWNET)));
    int any = listener(NULL, 7002), on_vd = listener("vd", 7003);
    printf("setns=%ld\n", result(setns(ns, CLONE_NEWNET)));

    /* Each of the flows goes and comes back by hops of hashes of its own:
       all come, whatever those. */
    int accepted = 0, refused = 0;
    for (int i = 1; i <= COUNT; i++) {
        struct sockaddr_in6 from = at6("2001:db8:5::", i, 0, 0), to = at6("2001:db8:2::", i, 7002, 0);
        accepted += opens(&from, &to, NULL, any) == 0;
        to.sin6_port = htons(7009);
        refused += opens(&from, &to, NULL, -1) == -ECONNREFUSED;
    }
    printf("answers: accepted %s, refused %s\n", share(accepted), share(refused));
    struct sockaddr_in6 from = at6("2001:db8:5::", 1, 0, 0), to = at6("2001:db8:2::", 1, 7010, 0);
    printf("port unreachable: %ld\n", unreachable(&from, &to));
    /* A listener's bound device is its answers'. */
    accepted = 0;
    for (int i = 1; i <= COUNT; i++) {
        struct sockaddr_in6 source = at6("2001:db8:5::", i, 0, 0), vd = at6("2001:db8:1::", 2, 7003, 0);
        accepted += opens(&source, &vd, NULL, on_vd) == 0;
    }
    printf("answers of a listener on vd: accepted %s\n", share(accepted));
    /* A socket bound to va takes those through it alone: none or all has a
       chance of 2^-39 over the keys. */
    accepted = 0;
    int waiting = 0;
    for (int i = 1; i <= COUNT; i++) {
        struct sockaddr_in6 source = at6("2001:db8:5::", i, 0, 0), vb = at6("2001:db8::", 2, 7002, 0);
        long r = opens(&source, &vb, "va", any);
        accepted += r == 0;
        waiting += r == -EINPROGRESS;
    }
    printf("answers to a socket on va: accepted %s, waiting %s\n", share(accepted), share(waiting));
    /* To a link-local address, through the device it came in on: vd, whose
       route is not the first. */
    to = at6("fe80::ff:fe00:", 0xd, 7002, VC);
    printf("from vc's link-local address: %ld\n", opens(NULL, &to, NULL, any));
    to.sin6_port = htons(7009);
    printf("refused there: %ld\n", opens(NULL, &to, NULL, -1));
    to.sin6_port = htons(7003);
    printf("at the listener on vd: %ld\n", opens(NULL, &to, NULL, on_vd));
    to = at6("fe80::ff:fe00:", 0xb, 7002, VA);
    printf("from va's link-local address: %ld\n", opens(NULL, &to, NULL, any));
    to.sin6_port = htons(7003);
    printf("at the listener on vd, through vb: %ld\n", opens(NULL, &to, NULL, -1));

    address4(ctl, VA, "10.0.0.1", 24, "add va's IPv4 address");
    lookup4(ctl, "0.1.2.3", 0, "lookup of 0.1.2.3");
    lookup4(ctl, "0.1.2.3", VA, "lookup of 0.1.2.3 through va");
    lookup4(ctl, "0.1.2.3", 1, "lookup of 0.1.2.3 through lo");
    lookup4(ctl, "0.0.0.0", VA, "lookup of 0.0.0.0 through va");
    reach4("0.1.2.3", NULL, "to 0.1.2.3");
    reach4("0.1.2.3", "va", "to 0.1.2.3 through va");
    default4(ctl, VA, "a default route through va");
    lookup4(ctl, "0.1.2.3", 0, "lookup of 0.1.2.3");
    lookup4(ctl, "0.255.255.255", 0, "lookup of 0.255.255.255");
    lookup4(ctl, "1.0.0.0", 0, "lookup of 1.0.0.0");
    reach4("0.1.2.3", NULL, "to 0.1.2.3");
    /* From a loopback source out of va, before RTM_F_FIB_MATCH finds an
       entry or none. */
    lookup4_from(ctl, "1.0.0.0", "127.0.0.1", 0, 0, "lookup from lo's");
    lookup4_from(ctl, "1.0.0.0", "127.0.0.1", 0, RTM_F_FIB_MATCH, "its entry");
    lookup4_from(ctl, "1.0.0.0", "127.0.0.1", VC, 0, "lookup from lo's through vc");
    lookup4_from(ctl, "1.0.0.0", "127.0.0.1", VC, RTM_F_FIB_MATCH, "its entry");
    lookup4_from(ctl, "224.0.0.1", "127.0.0.1", VC, RTM_F_FIB_MATCH, "the entry of a group from lo's through vc");
    lookup4_from(ctl, "1.0.0.0", NULL, VC, RTM_F_FIB_MATCH, "the entry through vc");
    lookup4_from(ctl, "127.0.0.2", "127.0.0.1", 0, RTM_F_FIB_MATCH, "the entry of 127.0.0.2 from lo's");
    return 0;
}
