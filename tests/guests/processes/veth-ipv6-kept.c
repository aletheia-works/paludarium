/* The route a connected IPv6 UDP socket keeps (so as root): a network
   namespace with "va" (1000, 2001:db8::1/64) and "vc" (1002,
   2001:db8:1::1/64), whose peers "vb" and "vd", in another, have 2001:db8::2
   and 2001:db8:1::2, with the destinations, 2001:db8:2::1 and on, on its lo;
   a route to 2001:db8:2::/64 through va, and one of a higher metric through
   vc. A socket that connects while IPV6_UNICAST_IF names vc goes on through
   vc when it no longer does (ip6_sk_dst_lookup_flow), until its route's node
   changes (ip6_dst_check): a route added at the prefix or below it does
   that, as an address gone does, and one whose duplicate address detection
   is done; a route added elsewhere, or another removed, does not, nor does
   an address without that detection. So does the route's own going, the
   device it goes through going down, SO_BINDTOIFINDEX, another IP_TOS, and
   another IPV6_UNICAST_IF, after which the route that gave is kept. Of a
   multipath route, every datagram of a socket goes the way of the first, from
   the source of its hop, and after a hop is added or goes down every one the
   way of the first after that. What is shown is the device each comes in on. */
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
#define RTM_DELADDR 21
#define RTM_NEWROUTE 24
#define RTM_DELROUTE 25
#define NLM_F_REQUEST 1
#define NLM_F_ACK 4
#define NLM_F_EXCL 0x200
#define NLM_F_CREATE 0x400
#define NLM_F_APPEND 0x800
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
#define LINK_LOCAL 2

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
    if (carrier == LINK_LOCAL) {
        if (h->type != RTM_NEWADDR || len < 8 || body[0] != AF_INET6 || body[3] != 253) return 0;
        memcpy(&got, body + 4, 4);
        return got == index;
    }
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
   to have its carrier `carrier`, or with LINK_LOCAL its link-local
   address: that address's detection, done in a work of its own even
   without accept_dad (addrconf_dad_work), changes every route's node
   (rt_genid_bump_ipv6) when it ends. */
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

static void address(int type, int fd, int index, const char *ip, int prefix, unsigned flags, const char *label) {
    struct body b = {0};
    const unsigned char m[8] = {AF_INET6, (unsigned char)prefix, (unsigned char)flags, 0, (unsigned char)index,
                                (unsigned char)(index >> 8), 0, 0};
    unsigned char in[16];
    inet_pton(AF_INET6, ip, in);
    raw(&b, m, sizeof m);
    put(&b, IFA_LOCAL, in, 16);
    put32(&b, IFA_FLAGS, flags);
    request(fd, (unsigned short)type, type == RTM_NEWADDR ? NLM_F_CREATE | NLM_F_EXCL : 0, &b, label);
}
/* Adds or removes a route to `dst`/`len` by the gateway of `oif` (none for
   0), of `metric`. */
static void route(int type, int fd, const char *dst, int len, int oif, unsigned metric, const char *label) {
    struct body b = {0};
    const unsigned char rtm[12] = {AF_INET6, (unsigned char)len, 0, 0, 254, 3, 0, 1};
    unsigned char in[16];
    inet_pton(AF_INET6, dst, in);
    raw(&b, rtm, sizeof rtm);
    put(&b, RTA_DST, in, 16);
    inet_pton(AF_INET6, oif == VA ? "2001:db8::2" : "2001:db8:1::2", in);
    put(&b, RTA_GATEWAY, in, 16);
    put32(&b, RTA_OIF, (unsigned)oif);
    if (metric) put32(&b, RTA_PRIORITY, metric);
    request(fd, (unsigned short)type, type == RTM_NEWROUTE ? NLM_F_CREATE | NLM_F_APPEND : 0, &b, label);
}
static struct sockaddr_in6 destination(int i, int net) {
    struct sockaddr_in6 to = {.sin6_family = AF_INET6, .sin6_port = htons(7000)};
    char text[64];
    snprintf(text, sizeof text, "2001:db8:%d::%x", net, i);
    inet_pton(AF_INET6, text, &to.sin6_addr);
    return to;
}
/* The other namespace's sockets bound to vb and vd. */
static int udp[2];
static void bound(int i, const char *device) {
    struct sockaddr_in6 any = {.sin6_family = AF_INET6, .sin6_port = htons(7000)};
    udp[i] = socket(AF_INET6, SOCK_DGRAM, 0);
    long device_set = result(setsockopt(udp[i], SOL_SOCKET, SO_BINDTODEVICE, device, 3));
    printf("udp on %s: %ld %ld\n", device, device_set, result(bind(udp[i], (void *)&any, sizeof any)));
}
/* Sends a datagram of `s`, which is connected: which of vb (0) and vd (1) it
   comes in on, or -1; and from what address. */
static int sent(int s, struct in6_addr *source) {
    char byte[4];
    struct sockaddr_in6 from;
    socklen_t len = sizeof from;
    if (send(s, "x", 1, 0) != 1) return -2;
    struct pollfd ready[2] = {{.fd = udp[0], .events = POLLIN}, {.fd = udp[1], .events = POLLIN}};
    if (poll(ready, 2, 2000) <= 0) return -1;
    int at = ready[0].revents ? 0 : 1;
    recvfrom(udp[at], byte, sizeof byte, 0, (void *)&from, &len);
    if (source) *source = from.sin6_addr;
    return at;
}
static void shows(int s, const char *label) {
    struct in6_addr source = {0};
    char text[64];
    int at = sent(s, &source);
    inet_ntop(AF_INET6, &source, text, sizeof text);
    printf("%s: %s from %s\n", label, at == 0 ? "va" : at == 1 ? "vc" : "lost", text);
}
static void unicast(int s, int index) {
    const int value = (int)htonl((unsigned)index);
    long r = result(setsockopt(s, IPPROTO_IPV6, 76, &value, sizeof value)); /* IPV6_UNICAST_IF */
    if (r) printf("IPV6_UNICAST_IF: %ld\n", r);
}
/* A socket connected while IPV6_UNICAST_IF named vc. */
static int through_vc(void) {
    int s = socket(AF_INET6, SOCK_DGRAM, 0);
    struct sockaddr_in6 to = destination(1, 2);
    unicast(s, VC);
    long r = result(connect(s, (void *)&to, sizeof to));
    if (r) printf("connect: %ld\n", r);
    unicast(s, 0);
    return s;
}
#define COUNT 64
static int many[COUNT], first[COUNT];
static const char *share(int count) { return count == 0 ? "none" : count == COUNT ? "all" : "some"; }
/* A datagram of each of the sockets `many`, twice: how many come, and, with
   `again`, how many the way of the first; else that is noted. */
static void all(int again, const char *label) {
    int came = 0, vc = 0, same = 0, own = 0;
    for (int round = 0; round < 2; round++)
        for (int i = 0; i < COUNT; i++) {
            struct in6_addr source, mine;
            struct sockaddr_in6 name;
            socklen_t len = sizeof name;
            int at = sent(many[i], &source);
            if (!again && round == 0) first[i] = at;
            came += at >= 0;
            vc += round == 0 && at == 1;
            same += at == first[i];
            getsockname(many[i], (void *)&name, &len);
            inet_pton(AF_INET6, at ? "2001:db8:1::1" : "2001:db8::1", &mine);
            own += !memcmp(&source, &mine, 16) && !memcmp(&name.sin6_addr, &mine, 16);
        }
    printf("%s: came %d, vc %s, as the first %d, from its device's %d\n", label, came, share(vc), same, own);
}

int main(int argc, char **argv) {
    if (argc < 2 || strcmp(argv[1], "veth-ipv6-kept")) return 99;
    setvbuf(stdout, NULL, _IOLBF, 0);
    printf("unshare=%ld\n", result(unshare(CLONE_NEWNET)));
    int ctl = route_socket(0);
    events = route_socket(1 | 0x100);
    int ns = open("/proc/self/ns/net", O_RDONLY);
    sysctl("/proc/sys/net/ipv6/conf/default/accept_dad", "0");
    sysctl("/proc/sys/net/ipv6/conf/all/accept_dad", "0");
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
    wait_carrier(VA, LINK_LOCAL, "va's link-local address");
    drain(events);
    set_link(ctl, VC, 1, "up vc");
    wait_carrier(VC, 1, "vc's carrier");
    wait_carrier(VC, LINK_LOCAL, "vc's link-local address");
    address(RTM_NEWADDR, ctl, VA, "2001:db8::1", 64, IFA_F_NODAD, "add va's address");
    address(RTM_NEWADDR, ctl, VC, "2001:db8:1::1", 64, IFA_F_NODAD, "add vc's address");
    address(RTM_NEWADDR, far, VB, "2001:db8::2", 64, IFA_F_NODAD, "add vb's address");
    address(RTM_NEWADDR, far, VD, "2001:db8:1::2", 64, IFA_F_NODAD, "add vd's address");
    for (int net = 2; net < 4; net++)
        for (int i = 1; i <= (net == 2 ? 1 : COUNT); i++) {
            struct sockaddr_in6 to = destination(i, net);
            char text[64];
            inet_ntop(AF_INET6, &to.sin6_addr, text, sizeof text);
            address(RTM_NEWADDR, far, 1, text, 128, IFA_F_NODAD, text);
        }
    bound(0, "vb");
    bound(1, "vd");
    printf("setns=%ld\n", result(setns(ns, CLONE_NEWNET)));
    route(RTM_NEWROUTE, ctl, "2001:db8:2::", 64, VA, 100, "a route through va");
    route(RTM_NEWROUTE, ctl, "2001:db8:2::", 64, VC, 200, "one through vc");

    int s = through_vc();
    shows(s, "connected through vc");
    route(RTM_NEWROUTE, ctl, "2001:db8:5::", 64, VA, 100, "a route elsewhere");
    shows(s, "then");
    address(RTM_NEWADDR, ctl, VA, "2001:db8:6::1", 64, IFA_F_NODAD, "an address without its detection");
    shows(s, "then");
    route(RTM_NEWROUTE, ctl, "2001:db8::", 32, VA, 100, "a route of a shorter prefix");
    shows(s, "then");
    route(RTM_DELROUTE, ctl, "2001:db8:5::", 64, VA, 100, "the route elsewhere gone");
    shows(s, "then");
    route(RTM_NEWROUTE, ctl, "2001:db8:2:0:8000::", 65, VA, 100, "a route of a longer prefix");
    shows(s, "then");
    close(s);
    s = through_vc();
    route(RTM_DELROUTE, ctl, "2001:db8:2:0:8000::", 65, VA, 100, "the route of the longer prefix gone");
    shows(s, "then");
    route(RTM_DELROUTE, ctl, "2001:db8:2::", 64, VA, 100, "the route through va gone");
    shows(s, "then");
    route(RTM_NEWROUTE, ctl, "2001:db8:2::", 64, VA, 100, "the route through va again");
    shows(s, "then");
    close(s);
    s = through_vc();
    route(RTM_DELROUTE, ctl, "2001:db8:2::", 64, VC, 200, "its own route gone");
    shows(s, "then");
    route(RTM_NEWROUTE, ctl, "2001:db8:2::", 64, VC, 200, "its own route again");
    close(s);
    s = through_vc();
    address(RTM_DELADDR, ctl, VA, "2001:db8:6::1", 64, 0, "an address gone");
    shows(s, "then");
    close(s);
    s = through_vc();
    address(RTM_NEWADDR, ctl, VA, "2001:db8:6::1", 64, 0, "an address with its detection, done at once");
    /* By a work of its own, which makes the change last of all it does. */
    for (int i = 0; i < 200 && sent(s, NULL) != 0; i++) poll(NULL, 0, 10);
    shows(s, "then");
    close(s);

    s = through_vc();
    const int va = VA, none = 0;
    printf("device=%ld", result(setsockopt(s, SOL_SOCKET, 62, &va, sizeof va))); /* SO_BINDTOIFINDEX */
    printf(" none=%ld\n", result(setsockopt(s, SOL_SOCKET, 62, &none, sizeof none)));
    shows(s, "bound to va, then to none");
    close(s);
    s = through_vc();
    const int tos = 0x10;
    printf("tos=%ld\n", result(setsockopt(s, IPPROTO_IP, IP_TOS, &none, sizeof none)));
    shows(s, "IP_TOS as it was");
    printf("tos=%ld\n", result(setsockopt(s, IPPROTO_IP, IP_TOS, &tos, sizeof tos)));
    shows(s, "another IP_TOS");
    close(s);
    s = through_vc();
    unicast(s, VC);
    shows(s, "IPV6_UNICAST_IF vc again");
    unicast(s, 0);
    shows(s, "and none");
    unicast(s, VA);
    shows(s, "IPV6_UNICAST_IF va");
    unicast(s, 0);
    shows(s, "and none");
    unicast(s, VC);
    shows(s, "IPV6_UNICAST_IF vc");
    close(s);
    s = through_vc();
    struct sockaddr_in6 to = destination(1, 2);
    printf("connect=%ld\n", result(connect(s, (void *)&to, sizeof to)));
    shows(s, "connected again");
    close(s);

    /* A multipath route. */
    route(RTM_NEWROUTE, ctl, "2001:db8:3::", 64, VA, 100, "a hop through va");
    route(RTM_NEWROUTE, ctl, "2001:db8:3::", 64, VC, 100, "a hop through vc");
    for (int i = 0; i < COUNT; i++) {
        to = destination(i + 1, 3);
        many[i] = socket(AF_INET6, SOCK_DGRAM, 0);
        if (connect(many[i], (void *)&to, sizeof to)) printf("connect: %d\n", -errno);
    }
    all(0, "multipath");
    route(RTM_NEWROUTE, ctl, "2001:db8:7::", 64, VA, 100, "a route elsewhere");
    all(1, "then");
    s = through_vc();
    set_link(ctl, VC, 0, "down vc");
    shows(s, "then");
    for (int i = 0; i < COUNT; i++) first[i] = 0;
    int back = 0;
    for (int i = 0; i < COUNT; i++) back += sent(many[i], NULL) == 0;
    printf("multipath with vc down: va %s\n", share(back));
    return 0;
}
