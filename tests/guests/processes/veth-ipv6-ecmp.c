/* IPv6 multipath routes of veth ends (so as root): a network namespace
   with two pairs, "va" (1000) with "vb" (1001) and "vc" (1002) with "vd"
   (1003), va having 2001:db8::1/64 and vc 2001:db8:1::1/64, IFA_F_NODAD.
   Routes to 2001:db8:2::/64 of one metric through a gateway are siblings
   of one multipath route (rt6_qualify_for_ecmp): one through 2001:db8::2,
   then one through 2001:db8:1::2 (vc), then a route through va without a
   gateway, then one through 2001:db8::3 with NLM_F_APPEND. Each sibling
   added is told of with all the hops, from itself on, without NLM_F_EXCL;
   NLM_F_EXCL, and the same gateway again, are EEXIST. A dump tells of the
   multipath route once, its hops in the order they came, and passes over
   the route without a gateway, which came between them
   (fib6_dump_node). A lookup takes one of the hops, which one Linux picks
   by a hash of a random seed, so only that it is one is shown, and its
   route's hops in order; a datagram from a bound socket asks neighbour
   discovery for the gateway of the hop a lookup of its flow gives. A
   removal naming a gateway takes that hop; vc
   going down leaves its hop RTNH_F_DEAD and RTNH_F_LINKDOWN, without a
   word, which lookups pass over, until vc is ready again. Replacing the
   multipath route takes all its hops; one without a gateway takes them
   all in one message. A dead hop goes when its device does; all of a
   multipath route goes when its hops' devices are all down. What
   RTNLGRP_IPV6_ROUTE hears of 2001:db8:2::/64 is shown in its order. A
   RTA_MULTIPATH requests add and remove hops with their weights, and a
   lookup of each of a few flows takes one of the hops. A carrier and an
   address done are waited for on netlink. */
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
#define RTM_DELLINK 17
#define RTM_NEWADDR 20
#define RTM_NEWROUTE 24
#define RTM_DELROUTE 25
#define RTM_GETROUTE 26
#define NLM_F_REQUEST 1
#define NLM_F_ACK 4
#define NLM_F_DUMP 0x300
#define NLM_F_REPLACE 0x100
#define NLM_F_EXCL 0x200
#define NLM_F_CREATE 0x400
#define NLM_F_APPEND 0x800
#define IFLA_ADDRESS 1
#define IFLA_IFNAME 3
#define IFLA_LINKINFO 18
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
#define RTA_MULTIPATH 9
#define RTA_SRC 2
#define RTA_TABLE 15
#define RTA_FLOWLABEL 31
#define RTA_IP_PROTO 27
#define RTM_F_FIB_MATCH 0x2000
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
/* RTNLGRP_LINK and RTNLGRP_IPV6_ROUTE, what is waited for; and
   RTNLGRP_IPV6_ROUTE, what is shown. */
static int events = -1, routes = -1;

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
/* Adds (`type` RTM_NEWROUTE, with `flags`) or removes an IPv6 route of
   the main table to 2001:db8:2::/64 through the gateway `via` (none for
   NULL), through the device of `oif` (none for 0). */
static void route6(int fd, unsigned short type, unsigned short flags, const char *via, int oif, const char *label) {
    struct body b = {0};
    unsigned char rtm[12] = {AF_INET6, 64, 0, 0, 254, 3, 0, 1};
    unsigned char in[16];
    inet_pton(AF_INET6, "2001:db8:2::", in);
    raw(&b, rtm, sizeof rtm);
    put(&b, RTA_DST, in, 16);
    if (via) {
        inet_pton(AF_INET6, via, in);
        put(&b, RTA_GATEWAY, in, 16);
    }
    if (oif) put32(&b, RTA_OIF, (unsigned)oif);
    request(fd, type, flags, &b, label);
}
/* A next hop of an RTA_MULTIPATH request: its gateway (none for NULL,
   or "short" for a 4-byte one), device and weight. */
struct hop {
    const char *via;
    int oif;
    int weight;
};
/* Adds (`type` RTM_NEWROUTE, with `flags`) or removes a route to
   2001:db8:2::/64 of the next hops `hops`, through the gateway `via` of
   the request itself (none for NULL). */
static void multipath6(int fd, unsigned short type, unsigned short flags, const char *via, const struct hop *hops, int n,
                       const char *label) {
    struct body b = {0};
    unsigned char rtm[12] = {AF_INET6, 64, 0, 0, 254, 3, 0, 1};
    unsigned char in[16];
    inet_pton(AF_INET6, "2001:db8:2::", in);
    raw(&b, rtm, sizeof rtm);
    put(&b, RTA_DST, in, 16);
    if (via) {
        inet_pton(AF_INET6, via, in);
        put(&b, RTA_GATEWAY, in, 16);
    }
    size_t mp = begin(&b, RTA_MULTIPATH);
    for (int i = 0; i < n; i++) {
        size_t at = b.len;
        unsigned char rtnh[8] = {0, 0, 0, (unsigned char)(hops[i].weight - 1)};
        memcpy(rtnh + 4, &hops[i].oif, 4);
        raw(&b, rtnh, sizeof rtnh);
        if (hops[i].via && !strcmp(hops[i].via, "short")) {
            put(&b, RTA_GATEWAY, in, 4);
        } else if (hops[i].via) {
            inet_pton(AF_INET6, hops[i].via, in);
            put(&b, RTA_GATEWAY, in, 16);
        }
        unsigned short len = (unsigned short)(b.len - at);
        memcpy(b.bytes + at, &len, 2);
    }
    end(&b, mp);
    request(fd, type, flags, &b, label);
}
/* The next hops of an RTA_MULTIPATH, as "gateway@device/flags" each, in
   their order, or sorted where `sorted`. */
static void hops(const unsigned char *v, int len, int sorted, char *out, size_t size) {
    char each[8][80];
    int count = 0;
    for (int a = 0; a + 8 <= len && count < 8;) {
        unsigned short hlen;
        memcpy(&hlen, v + a, 2);
        if (hlen < 8 || a + hlen > len) break;
        int dev;
        memcpy(&dev, v + a + 4, 4);
        char via[64] = "-";
        for (int b = a + 8; b + 4 <= a + hlen;) {
            unsigned short alen, kind;
            memcpy(&alen, v + b, 2);
            memcpy(&kind, v + b + 2, 2);
            if (alen < 4 || b + alen > a + hlen) break;
            if (kind == RTA_GATEWAY && alen == 20) inet_ntop(AF_INET6, v + b + 4, via, sizeof via);
            b += (alen + 3) & ~3;
        }
        snprintf(each[count++], sizeof each[0], "%s@%d/0x%x/%u", via, dev, v[a + 2], v[a + 3]);
        a += (hlen + 3) & ~3;
    }
    if (sorted)
        for (int i = 0; i < count; i++)
            for (int j = i + 1; j < count; j++)
                if (strcmp(each[j], each[i]) < 0) {
                    char t[80];
                    memcpy(t, each[i], sizeof t);
                    memcpy(each[i], each[j], sizeof t);
                    memcpy(each[j], t, sizeof t);
                }
    out[0] = 0;
    for (int i = 0; i < count; i++) {
        if (i) strncat(out, ",", size - strlen(out) - 1);
        strncat(out, each[i], size - strlen(out) - 1);
    }
}
/* Describes a route message to 2001:db8:2::/64 of the main table: its
   flags, type, gateway and device, or hops, and metric; 0 for another. */
static int describe(const struct nl_header *h, int sorted, char *line, size_t size) {
    const unsigned char *body = (const unsigned char *)(h + 1);
    int len = (int)(h->len - sizeof *h);
    if ((h->type != RTM_NEWROUTE && h->type != RTM_DELROUTE) || body[0] != AF_INET6) return 0;
    char dst[64] = "::", via[64] = "-", multi[512] = "";
    int oif = 0;
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
        if (kind == RTA_OIF && alen == 8) memcpy(&oif, v, 4);
        if (kind == RTA_PRIORITY && alen == 8) memcpy(&metric, v, 4);
        if (kind == RTA_TABLE && alen == 8) memcpy(&table, v, 4);
        if (kind == RTA_MULTIPATH) hops(v, alen - 4, sorted, multi, sizeof multi);
        a += (alen + 3) & ~3;
    }
    if (table != 254 || strcmp(dst, "2001:db8:2::") || body[1] != 64) return 0;
    if (multi[0])
        snprintf(line, size, "%s nlflags=0x%x flags=0x%x type=%u hops %s metric=%u",
                 h->type == RTM_NEWROUTE ? "route" : "-route", h->flags, flags, body[7], multi, metric);
    else
        snprintf(line, size, "%s nlflags=0x%x flags=0x%x type=%u via %s dev=%d metric=%u",
                 h->type == RTM_NEWROUTE ? "route" : "-route", h->flags, flags, body[7], via, oif, metric);
    return 1;
}
/* Dumps IPv6's routes, showing those to 2001:db8:2::/64. */
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
            struct nl_header *h = (void *)(buf + at);
            if (h->len < sizeof *h || at + h->len > n) break;
            if (h->type == 3 || h->type == 2) return;
            char line[640];
            /* A dump's messages are NLM_F_MULTI, whatever else. */
            h->flags &= (unsigned short)~2;
            if (describe(h, 0, line, sizeof line)) printf("%s: %s\n", label, line);
            at += (h->len + 3) & ~3u;
        }
    }
    printf("%s: no end\n", label);
}
/* Prints what `routes` heard of 2001:db8:2::/64 since, in its order. */
static void heard(const char *label) {
    static unsigned char buf[65536];
    for (;;) {
        long n = recv(routes, buf, sizeof buf, MSG_DONTWAIT);
        if (n <= 0) return;
        for (long at = 0; at + (long)sizeof(struct nl_header) <= n;) {
            const struct nl_header *h = (const void *)(buf + at);
            if (h->len < sizeof *h || at + h->len > n) break;
            char line[640];
            if (describe(h, 0, line, sizeof line)) printf("%s: %s\n", label, line);
            at += (h->len + 3) & ~3u;
        }
    }
}
/* Looks up the route to 2001:db8:2::9 with `flags`, and says whether its
   next hop is one of `allowed` ("gateway@device", by commas), or prints
   it where `allowed` is NULL; its route's hops, of a multipath one, are
   shown sorted where `sorted`. */
/* The next hop the last lookup gave. */
static char last_via[64];
static int last_oif;
/* Says whether the IPv6 neighbours dumped have an entry of `last_via` on
   the device of `last_oif`, and how many of the gateways `vias` (by
   commas) have one. */
static void neighbours(int fd, const char *vias, const char *label) {
    static unsigned char buf[65536];
    struct {
        struct nl_header h;
        unsigned char m[12];
    } ask = {{sizeof ask, 30, NLM_F_REQUEST | NLM_F_DUMP, ++seq, 0}, {AF_INET6}};
    struct nl_address kernel = {.family = AF_NETLINK};
    sendto(fd, &ask, sizeof ask, 0, (void *)&kernel, sizeof kernel);
    int hop = 0, of = 0;
    for (int done = 0; !done;) {
        struct pollfd ready = {.fd = fd, .events = POLLIN};
        if (poll(&ready, 1, 2000) <= 0) break;
        long n = recv(fd, buf, sizeof buf, 0);
        if (n <= 0) break;
        for (long at = 0; at + (long)sizeof(struct nl_header) <= n;) {
            const struct nl_header *h = (const void *)(buf + at);
            if (h->len < sizeof *h || at + h->len > n) break;
            if (h->type == 3 || h->type == 2) {
                done = 1;
                break;
            }
            const unsigned char *body = (const unsigned char *)(h + 1);
            int len = (int)(h->len - sizeof *h), index;
            memcpy(&index, body + 4, 4);
            for (int a = 12; a + 4 <= len;) {
                unsigned short alen, kind;
                memcpy(&alen, body + a, 2);
                memcpy(&kind, body + a + 2, 2);
                if (alen < 4 || a + alen > len) break;
                if (kind == 1 && alen == 20) {
                    char ip[64];
                    inet_ntop(AF_INET6, body + a + 4, ip, sizeof ip);
                    if (!strcmp(ip, last_via) && index == last_oif) hop = 1;
                    char list[256];
                    snprintf(list, sizeof list, "%s", vias);
                    for (char *each = strtok(list, ","); each; each = strtok(NULL, ","))
                        if (!strcmp(each, ip)) of++;
                }
                a += (alen + 3) & ~3;
            }
            at += (h->len + 3) & ~3u;
        }
    }
    printf("%s: the lookup's hop has one: %s; the gateways have %d\n", label, hop ? "yes" : "no", of);
}
static void lookup(int fd, unsigned flags, const char *src, unsigned flowlabel, int proto, const char *allowed,
                   int sorted, const char *label) {
    struct body b = {0};
    unsigned char rtm[12] = {AF_INET6, 128, src ? 128 : 0, 0, 0, 0, 0, 0};
    memcpy(rtm + 8, &flags, 4);
    unsigned char in[16];
    inet_pton(AF_INET6, "2001:db8:2::9", in);
    raw(&b, rtm, sizeof rtm);
    put(&b, RTA_DST, in, 16);
    if (src) {
        unsigned char from[16];
        inet_pton(AF_INET6, src, from);
        put(&b, RTA_SRC, from, 16);
    }
    if (flowlabel) {
        unsigned be = htonl(flowlabel);
        put(&b, RTA_FLOWLABEL, &be, 4);
    }
    if (proto) {
        unsigned char p = (unsigned char)proto;
        put(&b, RTA_IP_PROTO, &p, 1);
    }
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
    if (poll(&ready, 1, 2000) <= 0 || recv(fd, buf, sizeof buf, 0) < (long)sizeof *h + 4) {
        printf("%s: no answer\n", label);
        return;
    }
    if (h->type == 2) {
        int error;
        memcpy(&error, buf + sizeof *h, 4);
        printf("%s: error=%d\n", label, error);
        return;
    }
    const unsigned char *body = (const unsigned char *)(h + 1);
    int len = (int)(h->len - sizeof *h);
    char via[64] = "-";
    int oif = 0;
    for (int a = 12; a + 4 <= len;) {
        unsigned short alen, kind;
        memcpy(&alen, body + a, 2);
        memcpy(&kind, body + a + 2, 2);
        if (alen < 4 || a + alen > len) break;
        if (kind == RTA_GATEWAY && alen == 20) inet_ntop(AF_INET6, body + a + 4, via, sizeof via);
        if (kind == RTA_OIF && alen == 8) memcpy(&oif, body + a + 4, 4);
        a += (alen + 3) & ~3;
    }
    char line[640];
    if (flags & RTM_F_FIB_MATCH) {
        if (describe(h, sorted, line, sizeof line)) printf("%s: %s\n", label, line);
        else printf("%s: another route\n", label);
        return;
    }
    char hop[96];
    snprintf(hop, sizeof hop, "%s@%d", via, oif);
    snprintf(last_via, sizeof last_via, "%s", via);
    last_oif = oif;
    if (!allowed) {
        printf("%s: via %s\n", label, hop);
        return;
    }
    int found = 0;
    char list[256];
    snprintf(list, sizeof list, "%s", allowed);
    for (char *each = strtok(list, ","); each; each = strtok(NULL, ","))
        if (!strcmp(each, hop)) found = 1;
    printf("%s: through one of %s: %s\n", label, allowed, found ? "yes" : "no");
}
static void get(int fd, unsigned flags, const char *allowed, int sorted, const char *label) {
    lookup(fd, flags, NULL, 0, 0, allowed, sorted, label);
}
static void get_from(int fd, const char *src, unsigned flowlabel, int proto, const char *allowed, const char *label) {
    lookup(fd, 0, src, flowlabel, proto, allowed, 0, label);
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
    end(&m, peer);
    end(&m, data);
    end(&m, link);
    request(ctl, RTM_NEWLINK, NLM_F_CREATE | NLM_F_EXCL, &m, "make a pair");
}

int main(int argc, char **argv) {
    if (argc < 2 || strcmp(argv[1], "veth-ipv6-ecmp")) return 99;
    setvbuf(stdout, NULL, _IOLBF, 0);
    printf("unshare=%ld\n", result(unshare(CLONE_NEWNET)));
    int ctl = route_socket(0);
    events = route_socket(1 | 0x400);
    make_pair(ctl, VA, "va", VB, "vb", 0x0a);
    make_pair(ctl, VC, "vc", VD, "vd", 0x0c);
    sysctl("/proc/sys/net/ipv6/conf/va/accept_dad", "0");
    sysctl("/proc/sys/net/ipv6/conf/vb/accept_dad", "0");
    sysctl("/proc/sys/net/ipv6/conf/vc/accept_dad", "0");
    sysctl("/proc/sys/net/ipv6/conf/vd/accept_dad", "0");
    set_link(ctl, 1, 1, "up lo");
    /* The peers first, whose carriers come with the ends'. */
    set_link(ctl, VB, 1, "up vb");
    set_link(ctl, VD, 1, "up vd");
    up(ctl, VA, "fe80::ff:fe00:a", "up va");
    up(ctl, VC, "fe80::ff:fe00:c", "up vc");
    address6(ctl, VA, "2001:db8::1", 64, "add va's address");
    address6(ctl, VC, "2001:db8:1::1", 64, "add vc's address");
    routes = route_socket(0x400);

    /* Siblings, and a route without a gateway between them. */
    const unsigned short add = NLM_F_CREATE | NLM_F_EXCL;
    route6(ctl, RTM_NEWROUTE, add, "2001:db8::2", 0, "through 2001:db8::2");
    route6(ctl, RTM_NEWROUTE, NLM_F_CREATE, "2001:db8:1::2", 0, "through 2001:db8:1::2");
    route6(ctl, RTM_NEWROUTE, add, "2001:db8::3", 0, "another, NLM_F_EXCL");
    route6(ctl, RTM_NEWROUTE, NLM_F_CREATE, "2001:db8:1::2", 0, "through 2001:db8:1::2 again");
    route6(ctl, RTM_NEWROUTE, NLM_F_CREATE, NULL, VA, "through va without a gateway");
    route6(ctl, RTM_NEWROUTE, NLM_F_CREATE | NLM_F_APPEND, "2001:db8::3", 0, "through 2001:db8::3, appended");
    heard("heard");
    dump(ctl, "routes");
    get(ctl, 0, "2001:db8::2@1000,2001:db8:1::2@1002,2001:db8::3@1000", 0, "lookup");
    get(ctl, RTM_F_FIB_MATCH, NULL, 1, "its route");
    /* A datagram from a bound socket goes to the hop a lookup of its flow
       gives, whose gateway it asks neighbour discovery for. */
    int u = socket(AF_INET6, SOCK_DGRAM, 0);
    struct sockaddr_in6 mine = {.sin6_family = AF_INET6, .sin6_port = htons(7100)};
    inet_pton(AF_INET6, "2001:db8::1", &mine.sin6_addr);
    printf("bind=%ld\n", result(bind(u, (void *)&mine, sizeof mine)));
    struct sockaddr_in6 far = {.sin6_family = AF_INET6, .sin6_port = htons(7000)};
    inet_pton(AF_INET6, "2001:db8:2::9", &far.sin6_addr);
    printf("sendto=%ld\n", result(sendto(u, "x", 1, 0, (void *)&far, sizeof far)));
    get_from(ctl, "2001:db8::1", 0, 17, "2001:db8::2@1000,2001:db8:1::2@1002,2001:db8::3@1000", "its flow's lookup");
    neighbours(ctl, "2001:db8::2,2001:db8:1::2,2001:db8::3", "neighbours");
    close(u);

    /* One hop away, then one dead. */
    route6(ctl, RTM_DELROUTE, 0, "2001:db8::3", 0, "remove the one through 2001:db8::3");
    heard("heard");
    set_link(ctl, VC, 0, "down vc");
    heard("heard");
    dump(ctl, "routes with vc down");
    get(ctl, 0, NULL, 0, "lookup");
    get(ctl, RTM_F_FIB_MATCH, NULL, 0, "its route");
    up(ctl, VC, "fe80::ff:fe00:c", "up vc");
    heard("heard");
    dump(ctl, "routes with vc up");

    /* Replaced, then all of one removed in one message. */
    route6(ctl, RTM_NEWROUTE, NLM_F_REPLACE, "2001:db8::4", 0, "replace it through 2001:db8::4");
    heard("heard");
    dump(ctl, "routes replaced");
    route6(ctl, RTM_NEWROUTE, NLM_F_CREATE, "2001:db8::5", 0, "through 2001:db8::5");
    route6(ctl, RTM_DELROUTE, 0, NULL, 0, "remove it");
    route6(ctl, RTM_DELROUTE, 0, NULL, 0, "remove the one without a gateway");
    route6(ctl, RTM_DELROUTE, 0, NULL, 0, "remove another");
    heard("heard");
    dump(ctl, "routes left");

    /* A dead hop goes with its device. */
    address6(ctl, VC, "2001:db8:1::1", 64, "add vc's address again");
    route6(ctl, RTM_NEWROUTE, add, "2001:db8::2", 0, "through 2001:db8::2");
    route6(ctl, RTM_NEWROUTE, NLM_F_CREATE, "2001:db8:1::2", 0, "through 2001:db8:1::2");
    set_link(ctl, VC, 0, "down vc");
    struct body gone = {0};
    info(&gone, VC, 0, 0);
    request(ctl, RTM_DELLINK, 0, &gone, "delete vc");
    heard("heard");
    dump(ctl, "routes without vc");

    /* RTA_MULTIPATH: refused for no next hop, one without a gateway, a
       short gateway or a hop twice; a hop takes the request's gateway;
       appended, told of from the first sibling; one hop already there
       tells of those put in, then of their going. A removal takes each
       hop, giving the last error; a replacement takes all the hops. */
    /* A weight of 256, the most rtnh_hops (255) gives. */
    const struct hop two[] = {{"2001:db8::4", 0, 1}, {"2001:db8::5", VA, 256}};
    const struct hop none[] = {{NULL, 0, 1}};
    const struct hop bad[] = {{"short", 0, 1}};
    const struct hop same[] = {{"2001:db8::6", 0, 1}, {"2001:db8::6", VA, 1}};
    const struct hop clash[] = {{"2001:db8::7", 0, 1}, {"2001:db8::2", 0, 1}};
    const struct hop going[] = {{"2001:db8::4", 0, 1}, {"2001:db8::9", 0, 1}};
    multipath6(ctl, RTM_NEWROUTE, NLM_F_CREATE, NULL, NULL, 0, "multipath of none");
    multipath6(ctl, RTM_NEWROUTE, NLM_F_CREATE, NULL, none, 1, "multipath without a gateway");
    multipath6(ctl, RTM_NEWROUTE, NLM_F_CREATE, "2001:db8::8", none, 1, "multipath taking the request's gateway");
    multipath6(ctl, RTM_NEWROUTE, NLM_F_CREATE, NULL, bad, 1, "multipath with a short gateway");
    multipath6(ctl, RTM_NEWROUTE, NLM_F_CREATE, NULL, same, 2, "multipath with one hop twice");
    multipath6(ctl, RTM_NEWROUTE, NLM_F_CREATE | NLM_F_APPEND, NULL, two, 2, "multipath appended");
    multipath6(ctl, RTM_NEWROUTE, NLM_F_CREATE, NULL, clash, 2, "multipath with a hop there");
    heard("heard");
    dump(ctl, "multipath routes");
    const char *hops4 = "2001:db8::2@1000,2001:db8::8@1000,2001:db8::4@1000,2001:db8::5@1000";
    get(ctl, 0, hops4, 0, "lookup");
    get_from(ctl, "2001:db8::1", 0, 17, hops4, "lookup from 2001:db8::1, UDP");
    get_from(ctl, "2001:db8::1", 0x12345, 6, hops4, "lookup from 2001:db8::1, TCP, a flow label");
    get_from(ctl, "2001:db8::1", 7, 58, hops4, "lookup from 2001:db8::1, ICMPv6, another label");
    multipath6(ctl, RTM_DELROUTE, 0, NULL, going, 2, "remove two hops, one not there");
    multipath6(ctl, RTM_NEWROUTE, NLM_F_REPLACE, NULL, two, 2, "replace it by a multipath");
    heard("heard");
    dump(ctl, "multipath replaced");
    multipath6(ctl, RTM_DELROUTE, 0, NULL, two, 2, "remove both");
    heard("heard");

    /* All of one goes when its hops' devices are all down. */
    route6(ctl, RTM_NEWROUTE, add, "2001:db8::2", 0, "through 2001:db8::2");
    route6(ctl, RTM_NEWROUTE, NLM_F_CREATE, "2001:db8::3", 0, "through 2001:db8::3");
    set_link(ctl, VA, 0, "down va");
    heard("heard");
    dump(ctl, "routes with va down");
    return 0;
}
