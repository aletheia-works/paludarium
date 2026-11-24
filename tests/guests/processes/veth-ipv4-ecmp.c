/* IPv4 multipath routes of veth ends (so as root): a network namespace
   with two pairs, "va" (1000) with "vb" (1001) and "vc" (1002) with "vd"
   (1003), va having 10.0.0.1/24 and vc 10.1.0.1/24. A route's
   RTA_MULTIPATH is one route of its next hops (fib_get_nhs), told of and
   dumped with them in RTA_MULTIPATH, each with its flags, weight less
   one, device and gateway; one of one next hop is a route of one. It is
   refused for data past its next hops, a hop DEAD or LINKDOWN, a short
   gateway, a first hop not of the request's RTA_OIF or RTA_GATEWAY, a
   kind that rejects, more than one of host scope, and a hop each refuses
   as a route's next hop (fib_check_nh). The same route again is EEXIST;
   one of other weights is another. A lookup takes one of its hops, of
   which only that it is one is shown. A device going down leaves its hop
   RTNH_F_DEAD and RTNH_F_LINKDOWN, without a word, until it comes up; one
   losing its carrier, RTNH_F_LINKDOWN; a route whose hops are all dead
   goes. A removal's RTA_MULTIPATH names each hop in turn
   (fib_nh_match), a device or gateway its first. What RTNLGRP_IPV4_ROUTE
   hears of 10.2.0.0/24 is shown in its order. A carrier is waited for on
   netlink. */
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
#define IFA_ADDRESS_ 1
#define IFA_FLAGS 8
#define IFA_F_NODAD 0x02
#define RTA_DST 1
#define RTA_OIF 4
#define RTA_GATEWAY 5
#define RTA_PRIORITY 6
#define RTA_MULTIPATH 9
#define RTA_TABLE 15
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

/* A next hop of an RTA_MULTIPATH request: its gateway (none for NULL,
   "short" for a 2-byte one), device, weight and flags. */
struct hop {
    const char *via;
    int oif;
    int weight;
    unsigned char flags;
};
/* Adds (`type` RTM_NEWROUTE, with `flags`) or removes a route to
   10.2.0.0/24 of the scope `scope` and kind `kind`, through `via` and
   `oif` of its own (none for NULL and 0), and of the next hops `hops`
   (no RTA_MULTIPATH for -1), with `tail` bytes of junk after them. */
static void route4(int fd, unsigned short type, unsigned short flags, unsigned char scope, unsigned char kind,
                   const char *via, int oif, const struct hop *hops, int n, int tail, const char *label) {
    struct body b = {0};
    unsigned char rtm[12] = {AF_INET, 24, 0, 0, 254, 3, scope, kind};
    unsigned char in[4];
    inet_pton(AF_INET, "10.2.0.0", in);
    raw(&b, rtm, sizeof rtm);
    put(&b, RTA_DST, in, 4);
    if (via) {
        inet_pton(AF_INET, via, in);
        put(&b, RTA_GATEWAY, in, 4);
    }
    if (oif) put32(&b, RTA_OIF, (unsigned)oif);
    if (n >= 0) {
        size_t mp = begin(&b, RTA_MULTIPATH);
        for (int i = 0; i < n; i++) {
            size_t at = b.len;
            unsigned char rtnh[8] = {0, 0, hops[i].flags, (unsigned char)(hops[i].weight - 1)};
            memcpy(rtnh + 4, &hops[i].oif, 4);
            raw(&b, rtnh, sizeof rtnh);
            if (hops[i].via && !strcmp(hops[i].via, "short")) {
                put(&b, RTA_GATEWAY, in, 2);
            } else if (hops[i].via) {
                inet_pton(AF_INET, hops[i].via, in);
                put(&b, RTA_GATEWAY, in, 4);
            }
            unsigned short len = (unsigned short)(b.len - at);
            memcpy(b.bytes + at, &len, 2);
        }
        if (tail) {
            unsigned char junk[4] = {0};
            raw(&b, junk, (size_t)tail);
        }
        end(&b, mp);
    }
    request(fd, type, flags, &b, label);
}
/* The next hops of an RTA_MULTIPATH, as "gateway@device/flags/hops",
   sorted where `sorted`. */
static void hops_of(const unsigned char *v, int len, int sorted, char *out, size_t size) {
    char each[8][64];
    int count = 0;
    for (int a = 0; a + 8 <= len && count < 8;) {
        unsigned short hlen;
        memcpy(&hlen, v + a, 2);
        if (hlen < 8 || a + hlen > len) break;
        int dev;
        memcpy(&dev, v + a + 4, 4);
        char via[32] = "-";
        for (int b = a + 8; b + 4 <= a + hlen;) {
            unsigned short alen, kind;
            memcpy(&alen, v + b, 2);
            memcpy(&kind, v + b + 2, 2);
            if (alen < 4 || b + alen > a + hlen) break;
            if (kind == RTA_GATEWAY && alen == 8) inet_ntop(AF_INET, v + b + 4, via, sizeof via);
            b += (alen + 3) & ~3;
        }
        snprintf(each[count++], sizeof each[0], "%s@%d/0x%x/%u", via, dev, v[a + 2], v[a + 3]);
        a += (hlen + 3) & ~3;
    }
    if (sorted)
        for (int i = 0; i < count; i++)
            for (int j = i + 1; j < count; j++)
                if (strcmp(each[j], each[i]) < 0) {
                    char t[64];
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
/* Describes a route message to 10.2.0.0/24 of the main table; 0 for
   another. */
static int describe(const struct nl_header *h, int sorted, char *line, size_t size) {
    const unsigned char *body = (const unsigned char *)(h + 1);
    int len = (int)(h->len - sizeof *h);
    if ((h->type != RTM_NEWROUTE && h->type != RTM_DELROUTE) || body[0] != AF_INET) return 0;
    char dst[32] = "0.0.0.0", via[32] = "-", multi[512] = "";
    int oif = 0;
    unsigned table = body[4], metric = 0, flags;
    memcpy(&flags, body + 8, 4);
    for (int a = 12; a + 4 <= len;) {
        unsigned short alen, kind;
        memcpy(&alen, body + a, 2);
        memcpy(&kind, body + a + 2, 2);
        if (alen < 4 || a + alen > len) break;
        const unsigned char *v = body + a + 4;
        if (kind == RTA_DST && alen == 8) inet_ntop(AF_INET, v, dst, sizeof dst);
        if (kind == RTA_GATEWAY && alen == 8) inet_ntop(AF_INET, v, via, sizeof via);
        if (kind == RTA_OIF && alen == 8) memcpy(&oif, v, 4);
        if (kind == RTA_PRIORITY && alen == 8) memcpy(&metric, v, 4);
        if (kind == RTA_TABLE && alen == 8) memcpy(&table, v, 4);
        if (kind == RTA_MULTIPATH) hops_of(v, alen - 4, sorted, multi, sizeof multi);
        a += (alen + 3) & ~3;
    }
    if (table != 254 || strcmp(dst, "10.2.0.0") || body[1] != 24) return 0;
    const char *what = h->type == RTM_NEWROUTE ? "route" : "-route";
    if (multi[0])
        snprintf(line, size, "%s nlflags=0x%x flags=0x%x scope=%u hops %s metric=%u", what, h->flags, flags,
                 body[6], multi, metric);
    else
        snprintf(line, size, "%s nlflags=0x%x flags=0x%x scope=%u via %s dev=%d metric=%u", what, h->flags, flags,
                 body[6], via, oif, metric);
    return 1;
}
/* Dumps IPv4's routes, showing those to 10.2.0.0/24. */
static void dump(int fd, const char *label) {
    static unsigned char buf[65536];
    struct {
        struct nl_header h;
        unsigned char m[12];
    } ask = {{sizeof ask, RTM_GETROUTE, NLM_F_REQUEST | NLM_F_DUMP, ++seq, 0}, {AF_INET}};
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
            h->flags &= (unsigned short)~2;
            if (describe(h, 0, line, sizeof line)) printf("%s: %s\n", label, line);
            at += (h->len + 3) & ~3u;
        }
    }
    printf("%s: no end\n", label);
}
/* Prints what `routes` heard of 10.2.0.0/24 since, in its order. */
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
/* Looks up the route to 10.2.0.9 with `flags`, and says whether its
   next hop is one of `allowed` ("gateway@device", by commas), or prints
   its route's, hops sorted, with RTM_F_FIB_MATCH. */
static void get(int fd, unsigned flags, const char *allowed, const char *label) {
    struct body b = {0};
    unsigned char rtm[12] = {AF_INET, 32, 0, 0, 0, 0, 0, 0};
    memcpy(rtm + 8, &flags, 4);
    unsigned char in[4];
    inet_pton(AF_INET, "10.2.0.9", in);
    raw(&b, rtm, sizeof rtm);
    put(&b, RTA_DST, in, 4);
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
    char line[640];
    if (flags & RTM_F_FIB_MATCH) {
        if (describe(h, 1, line, sizeof line)) printf("%s: %s\n", label, line);
        else printf("%s: another route\n", label);
        return;
    }
    const unsigned char *body = (const unsigned char *)(h + 1);
    int len = (int)(h->len - sizeof *h), oif = 0;
    char via[32] = "-";
    for (int a = 12; a + 4 <= len;) {
        unsigned short alen, kind;
        memcpy(&alen, body + a, 2);
        memcpy(&kind, body + a + 2, 2);
        if (alen < 4 || a + alen > len) break;
        if (kind == RTA_GATEWAY && alen == 8) inet_ntop(AF_INET, body + a + 4, via, sizeof via);
        if (kind == RTA_OIF && alen == 8) memcpy(&oif, body + a + 4, 4);
        a += (alen + 3) & ~3;
    }
    char hop[64], list[256];
    snprintf(hop, sizeof hop, "%s@%d", via, oif);
    snprintf(list, sizeof list, "%s", allowed);
    int found = 0;
    for (char *each = strtok(list, ","); each; each = strtok(NULL, ","))
        if (!strcmp(each, hop)) found = 1;
    printf("%s: through one of %s: %s\n", label, allowed, found ? "yes" : "no");
}

int main(int argc, char **argv) {
    if (argc < 2 || strcmp(argv[1], "veth-ipv4-ecmp")) return 99;
    setvbuf(stdout, NULL, _IOLBF, 0);
    printf("unshare=%ld\n", result(unshare(CLONE_NEWNET)));
    int ctl = route_socket(0);
    events = route_socket(1);
    make_pair(ctl, VA, "va", VB, "vb", 0x0a);
    make_pair(ctl, VC, "vc", VD, "vd", 0x0c);
    set_link(ctl, 1, 1, "up lo");
    set_link(ctl, VB, 1, "up vb");
    set_link(ctl, VD, 1, "up vd");
    drain(events);
    set_link(ctl, VA, 1, "up va");
    wait_carrier(VA, 1, "va's carrier");
    drain(events);
    set_link(ctl, VC, 1, "up vc");
    wait_carrier(VC, 1, "vc's carrier");
    address4(ctl, VA, "10.0.0.1", 24, "add va's address");
    address4(ctl, VC, "10.1.0.1", 24, "add vc's address");
    routes = route_socket(0x40);

    const unsigned short add = NLM_F_CREATE | NLM_F_EXCL;
    const struct hop two[] = {{"10.0.0.2", VA, 1, 0}, {"10.1.0.2", VC, 3, 0}};
    const struct hop dead[] = {{"10.0.0.2", VA, 1, 1}};
    const struct hop shorter[] = {{"short", VA, 1, 0}};
    const struct hop far[] = {{"10.0.0.2", VA, 1, 0}, {"10.9.0.2", 0, 1, 0}};
    const struct hop plain[] = {{NULL, VA, 1, 0}, {NULL, VC, 1, 0}};
    const struct hop onlink[] = {{NULL, VA, 1, 4}};
    const struct hop nowhere[] = {{NULL, 9999, 1, 0}};
    const struct hop one[] = {{"10.0.0.2", VA, 3, 0}};
    route4(ctl, RTM_NEWROUTE, add, 0, 1, NULL, 0, two, 2, 4, "data past the next hops");
    route4(ctl, RTM_NEWROUTE, add, 0, 1, NULL, 0, dead, 1, 0, "a hop DEAD");
    route4(ctl, RTM_NEWROUTE, add, 0, 1, NULL, 0, shorter, 1, 0, "a short gateway");
    route4(ctl, RTM_NEWROUTE, add, 0, 1, NULL, VC, two, 2, 0, "RTA_OIF not the first hop's");
    route4(ctl, RTM_NEWROUTE, add, 0, 1, "10.1.0.2", 0, two, 2, 0, "RTA_GATEWAY not the first hop's");
    route4(ctl, RTM_NEWROUTE, add, 0, 6, NULL, 0, two, 2, 0, "a blackhole");
    route4(ctl, RTM_NEWROUTE, add, 254, 1, NULL, 0, plain, 2, 0, "two of host scope");
    route4(ctl, RTM_NEWROUTE, add, 0, 1, NULL, 0, far, 2, 0, "a hop no route reaches");
    route4(ctl, RTM_NEWROUTE, add, 0, 1, NULL, 0, onlink, 1, 0, "a hop on link without a gateway");
    route4(ctl, RTM_NEWROUTE, add, 0, 1, NULL, 0, nowhere, 1, 0, "a hop of no device");
    route4(ctl, RTM_NEWROUTE, add, 0, 1, NULL, 0, two, 2, 0, "through 10.0.0.2 and 10.1.0.2");
    route4(ctl, RTM_NEWROUTE, add, 0, 1, NULL, 0, two, 2, 0, "again");
    route4(ctl, RTM_NEWROUTE, NLM_F_CREATE | NLM_F_APPEND, 0, 1, NULL, 0, one, 1, 0, "one of weight 3, appended");
    route4(ctl, RTM_NEWROUTE, NLM_F_CREATE | NLM_F_APPEND, 0, 1, "10.0.0.2", VA, NULL, -1, 0, "a plain one, appended");
    route4(ctl, RTM_NEWROUTE, NLM_F_CREATE | NLM_F_APPEND, 0, 1, "10.0.0.2", VA, NULL, -1, 0, "it again");
    heard("heard");
    dump(ctl, "routes");
    get(ctl, 0, "10.0.0.2@1000,10.1.0.2@1002", "lookup");
    get(ctl, RTM_F_FIB_MATCH, NULL, "its route");

    /* A hop dead, then down, then up again. */
    set_link(ctl, VC, 0, "down vc");
    heard("heard");
    dump(ctl, "routes with vc down");
    get(ctl, 0, "10.0.0.2@1000", "lookup");
    drain(events);
    set_link(ctl, VC, 1, "up vc");
    wait_carrier(VC, 1, "vc's carrier");
    dump(ctl, "routes with vc up");
    drain(events);
    set_link(ctl, VD, 0, "down vd");
    wait_carrier(VC, 0, "vc's carrier gone");
    dump(ctl, "routes with vc's carrier gone");
    drain(events);
    set_link(ctl, VD, 1, "up vd");
    wait_carrier(VC, 1, "vc's carrier");
    dump(ctl, "routes with vc's carrier back");

    /* Removals. */
    const struct hop backwards[] = {{"10.1.0.2", VC, 1, 0}, {"10.0.0.2", VA, 1, 0}};
    const struct hop any_dev[] = {{"10.0.0.2", 0, 1, 0}, {NULL, 0, 1, 0}, {NULL, 0, 1, 0}};
    route4(ctl, RTM_DELROUTE, 0, 0, 1, NULL, 0, backwards, 2, 0, "remove them backwards");
    route4(ctl, RTM_DELROUTE, 0, 0, 1, NULL, 0, any_dev, 3, 0, "remove one of 10.0.0.2 and any");
    route4(ctl, RTM_DELROUTE, 0, 0, 1, "10.0.0.2", 0, NULL, -1, 0, "remove one through 10.0.0.2");
    heard("heard");
    dump(ctl, "routes left");
    route4(ctl, RTM_DELROUTE, 0, 0, 1, NULL, 0, NULL, -1, 0, "remove the rest");
    route4(ctl, RTM_DELROUTE, 0, 0, 1, NULL, 0, NULL, -1, 0, "remove another");
    heard("heard");

    /* All of a route's hops down. */
    route4(ctl, RTM_NEWROUTE, add, 0, 1, NULL, 0, two, 2, 0, "through both again");
    set_link(ctl, VA, 0, "down va");
    set_link(ctl, VC, 0, "down vc");
    heard("heard");
    dump(ctl, "routes with both down");
    return 0;
}
