/* The source of a packet from an IPv6 socket bound to none, to a multipath
   route's destination (so as root): a network namespace with "va" (1000,
   2001:db8::1/64) and "vc" (1002, 2001:db8:1::1/64), whose peers "vb" and
   "vd", in another, have 2001:db8::2 and 2001:db8:1::2, with the
   destinations, 2001:db8:2::1 and on, on its lo. Linux looks the route up
   once, from no source, and takes the source of the hop that gives
   (ip6_dst_lookup_tail): so each datagram, and each connection, comes in on
   the peer of the device whose address it is from, and where a lookup of
   its flow, of the protocol, says. The hash's key is random, so what is
   shown is how many of the 64 destinations that holds for, and whether each
   device took some, which no key changes but with a chance of 2^-63. */
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
#define IFA_FLAGS 8
#define IFA_F_NODAD 0x02
#define RTA_DST 1
#define RTA_OIF 4
#define RTA_GATEWAY 5
#define RTA_PREFSRC 7
#define RTA_MULTIPATH 9
#define RTA_IP_PROTO 27
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

static unsigned seq;
/* RTNLGRP_LINK of the first namespace, where carriers are waited for. */
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
/* Whether `h` is the RTM_NEWLINK of the device of `index` with its
   carrier `carrier`. */
static int is(const struct nl_header *h, int index, int carrier) {
    const unsigned char *body = (const unsigned char *)(h + 1);
    int len = (int)(h->len - sizeof *h), got;
    if (h->type != RTM_NEWLINK) return 0;
    memcpy(&got, body + 4, 4);
    if (got != index) return 0;
    for (int a = 16; a + 4 <= len;) {
        unsigned short alen, kind;
        memcpy(&alen, body + a, 2);
        memcpy(&kind, body + a + 2, 2);
        if (alen < 4 || a + alen > len) break;
        if ((kind & 0x3fff) == IFLA_CARRIER && alen >= 5) return body[a + 4] == carrier;
        a += (alen + 3) & ~3;
    }
    return 0;
}
/* Waits, up to 5 s however much else comes, for the device of `index`
   to have its carrier `carrier`. */
static void wait_carrier(int index, int carrier, const char *label) {
    static unsigned char buf[65536];
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
                if (is(h, index, carrier)) return;
                at += (h->len + 3) & ~3u;
            }
    }
    printf("%s: never came\n", label);
}
/* Makes the pair of `a` and, in this process's namespace, `b`. */
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

static void address6(int fd, int index, const char *ip, int prefix, const char *label) {
    struct body b = {0};
    const unsigned char m[8] = {AF_INET6, (unsigned char)prefix, IFA_F_NODAD, 0, (unsigned char)index,
                                (unsigned char)(index >> 8), 0, 0};
    unsigned char in[16];
    inet_pton(AF_INET6, ip, in);
    raw(&b, m, sizeof m);
    put(&b, IFA_LOCAL, in, 16);
    put32(&b, IFA_FLAGS, IFA_F_NODAD);
    request(fd, RTM_NEWADDR, NLM_F_CREATE | NLM_F_EXCL, &b, label);
}
/* Adds a route to 2001:db8:2::/64 by 2001:db8::2 through va and
   2001:db8:1::2 through vc. */
static void route6(int fd) {
    struct body b = {0};
    const unsigned char rtm[12] = {AF_INET6, 64, 0, 0, 254, 3, 0, 1};
    const char *const via[2] = {"2001:db8::2", "2001:db8:1::2"};
    unsigned char in[16];
    inet_pton(AF_INET6, "2001:db8:2::", in);
    raw(&b, rtm, sizeof rtm);
    put(&b, RTA_DST, in, 16);
    size_t mp = begin(&b, RTA_MULTIPATH);
    for (int i = 0; i < 2; i++) {
        size_t at = b.len;
        const int oif = i ? VC : VA;
        unsigned char rtnh[8] = {0};
        memcpy(rtnh + 4, &oif, 4);
        raw(&b, rtnh, sizeof rtnh);
        inet_pton(AF_INET6, via[i], in);
        put(&b, RTA_GATEWAY, in, 16);
        unsigned short len = (unsigned short)(b.len - at);
        memcpy(b.bytes + at, &len, 2);
    }
    end(&b, mp);
    request(fd, RTM_NEWROUTE, NLM_F_CREATE | NLM_F_EXCL, &b, "a multipath route");
}
static struct sockaddr_in6 destination(int i, int port) {
    struct sockaddr_in6 to = {.sin6_family = AF_INET6, .sin6_port = htons((unsigned short)port)};
    char text[64];
    snprintf(text, sizeof text, "2001:db8:2::%x", i);
    inet_pton(AF_INET6, text, &to.sin6_addr);
    return to;
}
/* 0 for va's address, 1 for vc's, -1 for another. */
static int whose(const struct in6_addr *ip) {
    struct in6_addr a, c;
    inet_pton(AF_INET6, "2001:db8::1", &a);
    inet_pton(AF_INET6, "2001:db8:1::1", &c);
    return !memcmp(ip, &a, 16) ? 0 : !memcmp(ip, &c, 16) ? 1 : -1;
}
/* The device (0 for va, 1 for vc) and the source's owner a lookup of the
   flow to `to`, of `protocol` (none for 0) and through `oif`, gives. */
static int lookup(int fd, const struct in6_addr *to, unsigned char protocol, int oif, int *source) {
    struct body b = {0};
    const unsigned char rtm[12] = {AF_INET6, 128};
    raw(&b, rtm, sizeof rtm);
    put(&b, RTA_DST, to, 16);
    if (protocol) put(&b, RTA_IP_PROTO, &protocol, 1);
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
    *source = -1;
    if (poll(&ready, 1, 2000) <= 0 || recv(fd, buf, sizeof buf, 0) < (long)sizeof *h + 4 || h->type != RTM_NEWROUTE)
        return -1;
    const unsigned char *body = (const unsigned char *)(h + 1);
    int len = (int)(h->len - sizeof *h), device = -1;
    for (int a = 12; a + 4 <= len;) {
        unsigned short alen, kind;
        memcpy(&alen, body + a, 2);
        memcpy(&kind, body + a + 2, 2);
        if (alen < 4 || a + alen > len) break;
        if (kind == RTA_OIF && alen == 8) memcpy(&device, body + a + 4, 4);
        if (kind == RTA_PREFSRC && alen == 20) *source = whose((const void *)(body + a + 4));
        a += (alen + 3) & ~3;
    }
    return device == VA ? 0 : device == VC ? 1 : -1;
}
/* The other namespace's sockets bound to vb and vd: UDP's and TCP's. */
static int udp[2], tcp[2];
static void bound(int i, const char *device) {
    struct sockaddr_in6 any = {.sin6_family = AF_INET6};
    udp[i] = socket(AF_INET6, SOCK_DGRAM, 0);
    tcp[i] = socket(AF_INET6, SOCK_STREAM, 0);
    any.sin6_port = htons(7000);
    long device_set = result(setsockopt(udp[i], SOL_SOCKET, SO_BINDTODEVICE, device, 3));
    printf("udp on %s: %ld %ld\n", device, device_set, result(bind(udp[i], (void *)&any, sizeof any)));
    any.sin6_port = htons(7001);
    device_set = result(setsockopt(tcp[i], SOL_SOCKET, SO_BINDTODEVICE, device, 3));
    long at = result(bind(tcp[i], (void *)&any, sizeof any));
    printf("tcp on %s: %ld %ld %ld\n", device, device_set, at, result(listen(tcp[i], 64)));
}
/* Which of the sockets `fds` is ready within 2 s: 0 or 1, or -1. */
static int arrived(const int *fds) {
    struct pollfd ready[2] = {{.fd = fds[0], .events = POLLIN}, {.fd = fds[1], .events = POLLIN}};
    if (poll(ready, 2, 2000) <= 0) return -1;
    return ready[0].revents ? 0 : 1;
}
#define COUNT 64
static const char *share(int count) { return count == 0 ? "none" : count == COUNT ? "all" : "some"; }
enum { SENDTO, CONNECT, STREAM };
/* A packet to each destination from a socket bound to none, through the
   device `oif` (any for 0): how many come, in on the device of its source,
   and as a lookup of its flow says. A datagram socket is connected alone,
   for its name. */
static void send_all(int fd, int how, int oif, const char *label) {
    int came = 0, own = 0, right = 0, through[2] = {0, 0};
    for (int i = 1; i <= COUNT; i++) {
        struct sockaddr_in6 to = destination(i, how == STREAM ? 7001 : 7000), from = {0};
        socklen_t len = sizeof from;
        int s = socket(AF_INET6, how == STREAM ? SOCK_STREAM : SOCK_DGRAM, 0), at = -1;
        if (oif) setsockopt(s, SOL_SOCKET, 62, &oif, sizeof oif); /* SO_BINDTOIFINDEX */
        long r = how == SENDTO ? sendto(s, "x", 1, 0, (void *)&to, sizeof to) : connect(s, (void *)&to, sizeof to);
        int source, device = lookup(fd, &to.sin6_addr, how == STREAM ? IPPROTO_TCP : IPPROTO_UDP, oif, &source);
        if (r < 0)
            printf("%s: %d: %d\n", label, i, -errno);
        else if (how == CONNECT) {
            getsockname(s, (void *)&from, &len);
            at = device;
        } else if ((at = arrived(how == STREAM ? tcp : udp)) >= 0) {
            char byte[4];
            if (how == STREAM)
                close(accept(tcp[at], (void *)&from, &len));
            else
                recvfrom(udp[at], byte, sizeof byte, 0, (void *)&from, &len);
        }
        close(s);
        if (at < 0) continue;
        came++;
        through[at]++;
        own += whose(&from.sin6_addr) == at;
        right += device == at && source == at;
    }
    printf("%s: came %d, va %s, vc %s, from its device's %d, by the lookup %d\n", label, came, share(through[0]),
           share(through[1]), own, right);
}

int main(int argc, char **argv) {
    if (argc < 2 || strcmp(argv[1], "veth-ipv6-source")) return 99;
    setvbuf(stdout, NULL, _IOLBF, 0);
    printf("unshare=%ld\n", result(unshare(CLONE_NEWNET)));
    int ctl = route_socket(0);
    events = route_socket(1);
    int ns = open("/proc/self/ns/net", O_RDONLY);
    sysctl("/proc/sys/net/ipv6/conf/default/accept_dad", "0");
    printf("unshare=%ld\n", result(unshare(CLONE_NEWNET)));
    int far = route_socket(0);
    sysctl("/proc/sys/net/ipv6/conf/default/accept_dad", "0");
    make_pair(ctl, VA, "va", VB, "vb", 0x0a);
    make_pair(ctl, VC, "vc", VD, "vd", 0x0c);
    set_link(ctl, 1, 1, "up lo");
    set_link(far, 1, 1, "up the other lo");
    set_link(far, VB, 1, "up vb");
    set_link(far, VD, 1, "up vd");
    drain(events);
    set_link(ctl, VA, 1, "up va");
    wait_carrier(VA, 1, "va's carrier");
    drain(events);
    set_link(ctl, VC, 1, "up vc");
    wait_carrier(VC, 1, "vc's carrier");
    address6(ctl, VA, "2001:db8::1", 64, "add va's address");
    address6(ctl, VC, "2001:db8:1::1", 64, "add vc's address");
    address6(far, VB, "2001:db8::2", 64, "add vb's address");
    address6(far, VD, "2001:db8:1::2", 64, "add vd's address");
    for (int i = 1; i <= COUNT; i++) {
        struct sockaddr_in6 to = destination(i, 0);
        char text[64];
        inet_ntop(AF_INET6, &to.sin6_addr, text, sizeof text);
        address6(far, 1, text, 128, text);
    }
    bound(0, "vb");
    bound(1, "vd");
    printf("setns=%ld\n", result(setns(ns, CLONE_NEWNET)));
    route6(ctl);
    send_all(ctl, SENDTO, 0, "sendto");
    send_all(ctl, CONNECT, 0, "connect");
    send_all(ctl, STREAM, 0, "stream");
    send_all(ctl, SENDTO, VA, "sendto through va");
    send_all(ctl, CONNECT, VC, "connect through vc");
    send_all(ctl, STREAM, VC, "stream through vc");
    set_link(ctl, VC, 0, "down vc");
    send_all(ctl, SENDTO, 0, "sendto with vc down");
    send_all(ctl, STREAM, 0, "stream with vc down");
    return 0;
}
