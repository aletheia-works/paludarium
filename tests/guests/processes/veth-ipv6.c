/* IPv6 addresses and routes of veth ends (so as root): one process makes
   a network namespace and a pair in it, "va" (1000, 02:00:00:00:00:0a)
   and "vb" (1001, 02:00:00:00:00:0b), and brings both up. Each end makes
   its link-local address from its Ethernet address, tentative until
   duplicate address detection is done 1 to 2 seconds on, with its
   prefix route and the multicast route, and the local route once it is
   done (vb's is not checked, as its accept_dad is 0). An address added is
   tentative too, unless IFA_F_NODAD; removing
   one takes its routes; an end that goes down takes its addresses and
   routes, and comes up with its link-local one again. IPv6 turned off
   on an end takes them too, and on again makes them; an end whose MTU is
   below 1280 has none. The addresses and
   routes are dumped (IPv6's, of the ends), and what RTNLGRP_IPV6_IFADDR
   and RTNLGRP_IPV6_ROUTE hear is shown in its order. */
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
#define RTA_DST 1
#define RTA_OIF 4
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
#define IFA_ADDRESS 1
#define IFA_FLAGS 8
#define IFA_PROTO 11
#define RTM_DELLINK 17
#define RTM_DELADDR 21
#define RTM_GETADDR 22
#define RTM_NEWROUTE 24
#define RTM_DELROUTE 25
#define RTM_GETROUTE 26
#define NLM_F_DUMP 0x300
#define NLM_F_REPLACE 0x100
#define RTA_DST 1
#define RTA_OIF 4
#define RTA_PRIORITY 6
#define RTA_TABLE 15
#define RTA_PREF 20
#define IFA_F_NODAD 0x02
#define IFA_LOCAL 2
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
struct ifaddrmsg_ {
    unsigned char family, prefix, flags, scope;
    int index;
};
struct body {
    unsigned char bytes[1024];
    size_t len;
};

static const char *side = "A";
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
/* Sends a request and prints its acknowledgement's error. */
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
static void set_up(int fd, int index, const char *label) {
    struct body b = {0};
    info(&b, index, IFF_UP, IFF_UP);
    request(fd, RTM_NEWLINK, 0, &b, label);
}
/* Waits, up to 5 s, until the member links hears that the device of
   `index` has its carrier. */
static void carrier(int links, int index) {
    static unsigned char buf[65536];
    for (;;) {
        struct pollfd ready = {.fd = links, .events = POLLIN};
        if (poll(&ready, 1, 5000) <= 0) {
            printf("%s: no carrier on %d\n", side, index);
            return;
        }
        long n = recv(links, buf, sizeof buf, MSG_DONTWAIT);
        if (n <= 0) return;
        for (long at = 0; at + (long)sizeof(struct nl_header) <= n;) {
            const struct nl_header *h = (const void *)(buf + at);
            if (h->len < sizeof *h || at + h->len > n) break;
            const unsigned char *body = (const unsigned char *)(h + 1);
            int body_len = (int)(h->len - sizeof *h);
            struct ifinfo i;
            if (h->type == RTM_NEWLINK && body_len >= (int)sizeof i) {
                memcpy(&i, body, sizeof i);
                for (int a = 16; i.index == index && a + 4 <= body_len;) {
                    unsigned short alen, kind;
                    memcpy(&alen, body + a, 2);
                    memcpy(&kind, body + a + 2, 2);
                    if (alen < 4 || a + alen > body_len) break;
                    if ((kind & 0x3fff) == IFLA_CARRIER && alen >= 5 && body[a + 4] == 1) return;
                    a += (alen + 3) & ~3;
                }
            }
            at += (h->len + 3) & ~3u;
        }
    }
}




/* Describes an IPv6 address message (index, prefix, flags, scope,
   protocol, address) or route message (table, type, protocol, scope,
   destination, device, metric), or returns 0 for another. */
static int describe(const struct nl_header *h, char *line, size_t size) {
    const unsigned char *body = (const unsigned char *)(h + 1);
    int len = (int)(h->len - sizeof *h);
    if ((h->type == RTM_NEWADDR || h->type == RTM_DELADDR) && body[0] == AF_INET6) {
        int index;
        memcpy(&index, body + 4, 4);
        unsigned flags = body[2], proto = 0;
        char ip[64] = "?";
        for (int a = 8; a + 4 <= len;) {
            unsigned short alen, kind;
            memcpy(&alen, body + a, 2);
            memcpy(&kind, body + a + 2, 2);
            if (alen < 4 || a + alen > len) break;
            if (kind == IFA_ADDRESS && alen == 20) inet_ntop(AF_INET6, body + a + 4, ip, sizeof ip);
            if (kind == IFA_FLAGS && alen == 8) memcpy(&flags, body + a + 4, 4);
            if (kind == IFA_PROTO && alen == 5) proto = body[a + 4];
            a += (alen + 3) & ~3;
        }
        snprintf(line, size, "%s dev=%d %s/%u flags=0x%x scope=%u proto=%u", h->type == RTM_NEWADDR ? "addr" : "-addr",
                 index, ip, body[1], flags, body[3], proto);
        return 1;
    }
    if ((h->type == RTM_NEWROUTE || h->type == RTM_DELROUTE) && body[0] == AF_INET6) {
        char dst[64] = "::";
        int oif = 0;
        unsigned table = body[4], metric = 0;
        for (int a = 12; a + 4 <= len;) {
            unsigned short alen, kind;
            memcpy(&alen, body + a, 2);
            memcpy(&kind, body + a + 2, 2);
            if (alen < 4 || a + alen > len) break;
            if (kind == RTA_DST && alen == 20) inet_ntop(AF_INET6, body + a + 4, dst, sizeof dst);
            if (kind == RTA_OIF && alen == 8) memcpy(&oif, body + a + 4, 4);
            if (kind == RTA_PRIORITY && alen == 8) memcpy(&metric, body + a + 4, 4);
            if (kind == RTA_TABLE && alen == 8) memcpy(&table, body + a + 4, 4);
            a += (alen + 3) & ~3;
        }
        /* The ends' alone. */
        if (oif < A_INDEX) return 0;
        unsigned flags;
        memcpy(&flags, body + 8, 4);
        snprintf(line, size, "%s table=%u type=%u proto=%u scope=%u flags=0x%x %s/%u dev=%d metric=%u",
                 h->type == RTM_NEWROUTE ? "route" : "-route", table, body[7], body[5], body[6], flags, dst, body[1], oif,
                 metric);
        return 1;
    }
    return 0;
}
/* Dumps IPv6's addresses or routes. */
static void dump(int fd, unsigned short type, const char *label) {
    static unsigned char buf[65536];
    struct {
        struct nl_header h;
        unsigned char m[12];
    } ask = {{sizeof ask, type, NLM_F_REQUEST | NLM_F_DUMP, ++seq, 0}, {AF_INET6}};
    if (type == RTM_GETADDR) ask.h.len = sizeof ask.h + 8;
    struct nl_address kernel = {.family = AF_NETLINK};
    sendto(fd, &ask, ask.h.len, 0, (void *)&kernel, sizeof kernel);
    for (;;) {
        struct pollfd ready = {.fd = fd, .events = POLLIN};
        if (poll(&ready, 1, 2000) <= 0) break;
        long n = recv(fd, buf, sizeof buf, 0);
        if (n <= 0) break;
        for (long at = 0; at + (long)sizeof(struct nl_header) <= n;) {
            const struct nl_header *h = (const void *)(buf + at);
            if (h->len < sizeof *h || at + h->len > n) break;
            if (h->type == 3 || h->type == 2) return;
            char line[200];
            const unsigned char *body = (const unsigned char *)(h + 1);
            int index;
            memcpy(&index, body + 4, 4);
            /* Of the ends alone. */
            if (describe(h, line, sizeof line) && (h->type != RTM_NEWADDR || index >= A_INDEX))
                printf("%s: %s: %s\n", side, label, line);
            at += (h->len + 3) & ~3u;
        }
    }
    printf("%s: %s: no end\n", side, label);
}
/* Prints what the member `watch` heard since, in its order. */
static void heard(int watch, const char *label) {
    static unsigned char buf[65536];
    for (;;) {
        long n = recv(watch, buf, sizeof buf, MSG_DONTWAIT);
        if (n <= 0) return;
        for (long at = 0; at + (long)sizeof(struct nl_header) <= n;) {
            const struct nl_header *h = (const void *)(buf + at);
            if (h->len < sizeof *h || at + h->len > n) break;
            char line[200];
            const unsigned char *body = (const unsigned char *)(h + 1);
            int index;
            memcpy(&index, body + 4, 4);
            if (describe(h, line, sizeof line) &&
                (h->type == RTM_NEWROUTE || h->type == RTM_DELROUTE || index >= A_INDEX))
                printf("%s: %s: %s\n", side, label, line);
            at += (h->len + 3) & ~3u;
        }
    }
}
/* A member of RTNLGRP_LINK and RTNLGRP_IPV6_ROUTE that the waits below
   read, apart from what `heard` shows. */
static int events = -1;
/* Takes what `events` has heard so far, so that a wait sees only what
   comes after. */
static void drain(void) {
    static unsigned char buf[65536];
    while (recv(events, buf, sizeof buf, MSG_DONTWAIT) > 0) {
    }
}
/* Whether the message is the local route of `ip` (`index` 0), or the
   RTM_NEWLINK of the device of `index` without its carrier. */
static int is(const struct nl_header *h, const unsigned char *ip, int index) {
    const unsigned char *body = (const unsigned char *)(h + 1);
    int len = (int)(h->len - sizeof *h);
    int start = index ? 16 : 12;
    if (index ? h->type != RTM_NEWLINK : (h->type != RTM_NEWROUTE || body[0] != AF_INET6 || body[7] != 2)) return 0;
    if (index) {
        int got;
        memcpy(&got, body + 4, 4);
        if (got != index) return 0;
    }
    for (int a = start; a + 4 <= len;) {
        unsigned short alen, kind;
        memcpy(&alen, body + a, 2);
        memcpy(&kind, body + a + 2, 2);
        if (alen < 4 || a + alen > len) break;
        if (!index && kind == RTA_DST && alen == 20) return !memcmp(body + a + 4, ip, 16);
        if (index && (kind & 0x3fff) == IFLA_CARRIER && alen >= 5) return body[a + 4] == 0;
        a += (alen + 3) & ~3;
    }
    return 0;
}
/* Waits, up to 5 s, for what Linux's work queue or link watch does: the
   local route of `ip` (an address done), or the RTM_NEWLINK of the device
   of `index` without its carrier. */
static void wait_for(const char *ip, int index, const char *label) {
    static unsigned char buf[65536];
    unsigned char in[16] = {0};
    if (ip) inet_pton(AF_INET6, ip, in);
    struct timespec start, now;
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (;;) {
        clock_gettime(CLOCK_MONOTONIC, &now);
        long left = 5000 - ((now.tv_sec - start.tv_sec) * 1000 + (now.tv_nsec - start.tv_nsec) / 1000000);
        if (left <= 0) break;
        /* What else comes meanwhile takes none of the 5 s. */
        struct pollfd ready = {.fd = events, .events = POLLIN};
        if (poll(&ready, 1, (int)(left < 1000 ? left : 1000)) <= 0) continue;
        long n;
        while ((n = recv(events, buf, sizeof buf, MSG_DONTWAIT)) > 0)
            for (long at = 0; at + (long)sizeof(struct nl_header) <= n;) {
                const struct nl_header *h = (const void *)(buf + at);
                if (h->len < sizeof *h || at + h->len > n) break;
                if (is(h, in, index)) return;
                at += (h->len + 3) & ~3u;
            }
    }
    printf("A: %s: never came\n", label);
}
/* Adds or removes the IPv6 address `ip`/`prefix` of the device of
   `index`, with `flags`. */
static void address6(int fd, unsigned short type, int index, const char *ip, int prefix, unsigned flags, const char *label) {
    struct body b = {0};
    const unsigned char m[8] = {AF_INET6, (unsigned char)prefix, (unsigned char)flags, 0, (unsigned char)index,
                                (unsigned char)(index >> 8), 0, 0};
    unsigned char in[16];
    inet_pton(AF_INET6, ip, in);
    raw(&b, m, sizeof m);
    put(&b, IFA_LOCAL, in, 16);
    if (flags) put32(&b, IFA_FLAGS, flags);
    drain();
    int error = request(fd, type, type == RTM_NEWADDR ? NLM_F_CREATE | NLM_F_EXCL : 0, &b, label);
    /* One not checked is done in Linux's work queue: its local route comes
       last. */
    if (type == RTM_NEWADDR && flags & IFA_F_NODAD && error == 0) wait_for(ip, 0, label);
}

/* Adds (with NLM_F_EXCL) or removes an IPv6 route to `dst`/`prefix`
   through the device of `oif`, of metric `metric` (none for 0). */
static unsigned char route_kind = 1;
static void route6(int fd, unsigned short type, const char *dst, int prefix, int oif, unsigned metric, const char *label) {
    struct body b = {0};
    const unsigned char rtm[12] = {AF_INET6, (unsigned char)prefix, 0, 0, 254, 3, 0, route_kind};
    unsigned char in[16];
    inet_pton(AF_INET6, dst, in);
    raw(&b, rtm, sizeof rtm);
    put(&b, RTA_DST, in, 16);
    put32(&b, RTA_OIF, (unsigned)oif);
    if (metric) put32(&b, RTA_PRIORITY, metric);
    request(fd, type, type == RTM_NEWROUTE ? NLM_F_CREATE | NLM_F_EXCL : 0, &b, label);
}
/* Changes the IPv6 address `ip`/`prefix` of the device of `index` with
   NLM_F_REPLACE. */
static void replace6(int fd, int index, const char *ip, int prefix, const char *label) {
    struct body b = {0};
    const unsigned char m[8] = {AF_INET6, (unsigned char)prefix, 0, 0, (unsigned char)index, (unsigned char)(index >> 8), 0, 0};
    unsigned char in[16];
    inet_pton(AF_INET6, ip, in);
    raw(&b, m, sizeof m);
    put(&b, IFA_LOCAL, in, 16);
    request(fd, RTM_NEWADDR, NLM_F_CREATE | NLM_F_REPLACE, &b, label);
}

int main(int argc, char **argv) {
    if (argc < 2 || strcmp(argv[1], "veth-ipv6")) return 99;
    setvbuf(stdout, NULL, _IOLBF, 0);
    printf("A: unshare=%ld\n", result(unshare(CLONE_NEWNET)));
    /* RTNLGRP_LINK, RTNLGRP_IPV6_IFADDR and RTNLGRP_IPV6_ROUTE. */
    int ctl = route_socket(0), links = route_socket(1), watch = route_socket(0x100 | 0x400);
    events = route_socket(1 | 0x400);
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
    end(&m, peer);
    end(&m, data);
    end(&m, link);
    request(ctl, RTM_NEWLINK, NLM_F_CREATE | NLM_F_EXCL, &m, "make");
    /* Only one address at a time is checked for duplicates, so that what
       is heard comes in one order: vb's are not. */
    int dad = open("/proc/sys/net/ipv6/conf/vb/accept_dad", O_WRONLY);
    printf("A: vb's accept_dad=%ld\n", result(dad < 0 ? dad : write(dad, "0", 1)));
    if (dad >= 0) close(dad);
    address6(ctl, RTM_NEWADDR, A_INDEX, "2001:db8:9::1", 64, IFA_F_NODAD, "add while down");
    dump(ctl, RTM_GETADDR, "addresses, down");
    heard(watch, "heard");
    set_up(ctl, 1, "up lo");
    drain();
    set_up(ctl, A_INDEX, "up va");
    set_up(ctl, B_INDEX, "up vb");
    carrier(links, A_INDEX);
    /* vb's address, not checked, is done in Linux's work queue. */
    wait_for("fe80::ff:fe00:b", 0, "vb's link-local address");
    dump(ctl, RTM_GETADDR, "addresses, up");
    dump(ctl, RTM_GETROUTE, "routes, up");
    heard(watch, "heard");
    wait_for("fe80::ff:fe00:a", 0, "va's link-local address");
    dump(ctl, RTM_GETADDR, "addresses, checked");
    dump(ctl, RTM_GETROUTE, "routes, checked");
    heard(watch, "heard");
    /* NLM_F_EXCL finds the end's route of the same metric, whatever its
       device. */
    route6(ctl, RTM_NEWROUTE, "2001:db8:9::", 64, 1, 256, "add va's prefix through lo");
    /* Routes a request adds through the ends, of no gateway. */
    route6(ctl, RTM_NEWROUTE, "2001:db8:5::", 64, A_INDEX, 0, "add 2001:db8:5::/64 dev va");
    route6(ctl, RTM_NEWROUTE, "2001:db8:7::", 64, B_INDEX, 0, "add 2001:db8:7::/64 dev vb");
    route6(ctl, RTM_NEWROUTE, "2001:db8:7::", 64, A_INDEX, 0, "add it dev va");
    route6(ctl, RTM_DELROUTE, "2001:db8:7::", 64, B_INDEX, 0, "delete it dev vb");
    route6(ctl, RTM_DELROUTE, "2001:db8:7::", 64, B_INDEX, 0, "delete it dev vb again");
    route6(ctl, RTM_NEWROUTE, "2001:db8:7::", 64, 1234, 0, "add one through no device");
    dump(ctl, RTM_GETROUTE, "routes, requested");
    heard(watch, "heard");

    address6(ctl, RTM_NEWADDR, A_INDEX, "2001:db8::1", 64, 0, "add 2001:db8::1/64");
    address6(ctl, RTM_NEWADDR, A_INDEX, "2001:db8:1::1", 64, IFA_F_NODAD, "add 2001:db8:1::1/64 nodad");
    address6(ctl, RTM_NEWADDR, A_INDEX, "2001:db8:2::1", 128, IFA_F_NODAD, "add 2001:db8:2::1/128 nodad");
    address6(ctl, RTM_NEWADDR, A_INDEX, "2001:db8::1", 64, 0, "add it again");
    /* Changed while it is checked, it stays tentative. */
    replace6(ctl, A_INDEX, "2001:db8::1", 64, "replace it");
    dump(ctl, RTM_GETADDR, "addresses, added");
    dump(ctl, RTM_GETROUTE, "routes, added");
    heard(watch, "heard");
    wait_for("2001:db8::1", 0, "2001:db8::1 checked");
    dump(ctl, RTM_GETADDR, "addresses, added and checked");
    dump(ctl, RTM_GETROUTE, "routes, added and checked");
    heard(watch, "heard");
    address6(ctl, RTM_DELADDR, A_INDEX, "2001:db8::1", 64, 0, "delete 2001:db8::1");
    address6(ctl, RTM_DELADDR, A_INDEX, "2001:db8::1", 64, 0, "delete it again");
    dump(ctl, RTM_GETROUTE, "routes, deleted");
    heard(watch, "heard");

    struct body d = {0};
    info(&d, A_INDEX, 0, IFF_UP);
    drain();
    request(ctl, RTM_NEWLINK, 0, &d, "down va");
    route6(ctl, RTM_NEWROUTE, "2001:db8:6::", 64, A_INDEX, 0, "add 2001:db8:6::/64 dev va, down");
    /* vb's lost carrier marks its routes as Linux's link watch finds it,
       before it tells of vb. */
    wait_for(NULL, B_INDEX, "vb without its carrier");
    dump(ctl, RTM_GETADDR, "addresses, va down");
    dump(ctl, RTM_GETROUTE, "routes, va down");
    heard(watch, "heard");
    drain();
    set_up(ctl, A_INDEX, "up va again");
    carrier(links, A_INDEX);
    wait_for("fe80::ff:fe00:a", 0, "va's link-local address again");
    dump(ctl, RTM_GETADDR, "addresses, up again");
    dump(ctl, RTM_GETROUTE, "routes, up again");
    heard(watch, "heard");
    /* IPv6 off on vb: it loses its routes and addresses, and takes no
       route; on again, it is ready again. */
    int off = open("/proc/sys/net/ipv6/conf/vb/disable_ipv6", O_WRONLY);
    printf("A: vb's disable_ipv6=%ld\n", result(off < 0 ? off : write(off, "1", 1)));
    heard(watch, "heard");
    route6(ctl, RTM_NEWROUTE, "2001:db8:8::", 64, B_INDEX, 0, "add 2001:db8:8::/64 dev vb, off");
    drain();
    printf("A: vb's disable_ipv6 again=%ld\n", result(off < 0 ? off : pwrite(off, "0", 1, 0)));
    if (off >= 0) close(off);
    wait_for("fe80::ff:fe00:b", 0, "vb's link-local address again");
    dump(ctl, RTM_GETADDR, "addresses, vb on again");
    heard(watch, "heard");
    /* A pair whose MTU is below 1280 has no IPv6. */
    struct body small = {0};
    unsigned mtu = 1000;
    info(&small, 1002, 0, 0);
    put(&small, IFLA_IFNAME, "vc", 3);
    put32(&small, 4, mtu);
    size_t link2 = begin(&small, IFLA_LINKINFO);
    put(&small, IFLA_INFO_KIND, "veth", 5);
    size_t data2 = begin(&small, IFLA_INFO_DATA);
    size_t peer2 = begin(&small, VETH_INFO_PEER);
    info(&small, 1003, 0, 0);
    put(&small, IFLA_IFNAME, "vd", 3);
    put32(&small, 4, mtu);
    end(&small, peer2);
    end(&small, data2);
    end(&small, link2);
    request(ctl, RTM_NEWLINK, NLM_F_CREATE | NLM_F_EXCL, &small, "make vc and vd of MTU 1000");
    set_up(ctl, 1002, "up vc");
    set_up(ctl, 1003, "up vd");
    carrier(links, 1002);
    route6(ctl, RTM_NEWROUTE, "2001:db8:8::", 64, 1002, 0, "add 2001:db8:8::/64 dev vc");
    /* An unreachable one needs IPv6 on the device it names too. */
    route_kind = 7;
    route6(ctl, RTM_NEWROUTE, "2001:db8:8::", 64, 1002, 0, "add an unreachable one dev vc");
    route_kind = 1;
    dump(ctl, RTM_GETADDR, "addresses, vc");
    heard(watch, "heard");
    struct body g = {0};
    info(&g, B_INDEX, 0, 0);
    request(ctl, RTM_DELLINK, 0, &g, "delete the pair");
    dump(ctl, RTM_GETADDR, "addresses, gone");
    heard(watch, "heard");
    return 0;
}
