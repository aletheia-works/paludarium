/* IPv4 routes through a gateway of IPv6 (RTA_VIA), of a veth pair (so as
   root): a network namespace with "va" (1000, 10.0.0.1/24,
   2001:db8::1/64) and "vc" (1002, no address of IPv4), whose peers "vb"
   and "vd", in another, have 10.0.0.2 and 2001:db8::2, and 10.2.0.1/24 on
   lo. What requests are refused, with their messages; the routes, as
   notifications, dumps and lookups show them; that a removal compares
   them; that a multipath route has such hops too; what goes there and
   comes back by neighbour discovery; and what a device going down does to
   them. */
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
#define RTM_DELROUTE 25
#define RTM_GETROUTE 26
#define RTM_GETNEIGH 30
#define NLM_F_REQUEST 1
#define NLM_F_ACK 4
#define NLM_F_DUMP 0x300
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
#define RTA_OIF 4
#define RTA_GATEWAY 5
#define RTA_PREFSRC 7
#define RTA_MULTIPATH 9
#define RTA_VIA 18
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
            printf("%s: error=%d", label, error);
            /* NLMSGERR_ATTR_MSG, after the request's header as it is capped
               or whole. */
            size_t at = sizeof *h + 4 + (error && !(h->flags & 0x100) ? ((struct nl_header *)(buf + sizeof *h + 4))->len : sizeof *h);
            at = (at + 3) & ~(size_t)3;
            if (h->flags & 0x200)
                while (at + 4 <= h->len) {
                    unsigned short alen, kind;
                    memcpy(&alen, buf + at, 2);
                    memcpy(&kind, buf + at + 2, 2);
                    if (alen < 4) break;
                    if (kind == 1) printf(" \"%s\"", (const char *)buf + at + 4);
                    at += (alen + 3) & ~3u;
                }
            printf("\n");
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
   address done), or the RTM_NEWLINK of the device of `index` with the
   carrier `carrier`. */
static int is(const struct nl_header *h, int index, int carrier) {
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
        if (index && (kind & 0x3fff) == IFLA_CARRIER && alen >= 5) return body[a + 4] == carrier;
        a += (alen + 3) & ~3;
    }
    return 0;
}
/* Waits, up to 5 s however much else comes, for what `is` says. */
static void wait_for(const char *ip, int index, int carrier, const char *label) {
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
                if (is(h, index, carrier)) return;
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
    if (request(fd, RTM_NEWADDR, NLM_F_CREATE | NLM_F_EXCL, &b, label) == 0) wait_for(ip, 0, 1, label);
}
/* Brings the device of `index` up and waits for its carrier and its
   link-local address `ll`. */
static void up(int fd, int index, const char *ll, const char *label) {
    drain(events);
    set_link(fd, index, 1, label);
    wait_for(NULL, index, 1, "its carrier");
    wait_for(ll, 0, 1, "its link-local address");
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
/* Puts the RTA_VIA of the gateway `ip`, of the family its text has. */
static void put_via(struct body *b, const char *ip) {
    unsigned char via[18] = {0};
    unsigned short family = strchr(ip, ':') ? AF_INET6 : AF_INET;
    memcpy(via, &family, 2);
    inet_pton(family, ip, via + 2);
    put(b, RTA_VIA, via, family == AF_INET6 ? 18 : 6);
}
static void start4(struct body *b, int kind, int scope, unsigned flags) {
    unsigned char rtm[12] = {AF_INET, 24, 0, 0, 254, 3, (unsigned char)scope, (unsigned char)kind};
    const unsigned char dst[4] = {10, 2, 0, 0};
    memcpy(rtm + 8, &flags, 4);
    raw(b, rtm, sizeof rtm);
    put(b, RTA_DST, dst, 4);
}
/* Asks for (`type`) a route to 10.2.0.0/24 through `via`, on `oif` (0 for
   none), of `kind` and `scope`, with the next hop's flags `flags`. */
static void route(int fd, unsigned short type, const char *via, int oif, int kind, int scope, unsigned flags,
                  const char *label) {
    struct body b = {0};
    start4(&b, kind, scope, flags);
    if (via) put_via(&b, via);
    if (oif) put32(&b, RTA_OIF, (unsigned)oif);
    request(fd, type, type == RTM_NEWROUTE ? NLM_F_CREATE | NLM_F_EXCL : 0, &b, label);
}
static void add(int fd, const char *via, int oif, const char *label) {
    route(fd, RTM_NEWROUTE, via, oif, 1, 0, 0, label);
}
static void del(int fd, const char *via, int oif, const char *label) {
    route(fd, RTM_DELROUTE, via, oif, 0, 255, 0, label);
}
/* A route whose RTA_VIA is the `len` bytes `bytes`, after the gateway
   10.0.0.2 with `gateway`, to a prefix of `prefix` bits. */
static void bad(int fd, const unsigned char *bytes, size_t len, int gateway, int prefix, const char *label) {
    struct body b = {0};
    const unsigned char gw[4] = {10, 0, 0, 2};
    start4(&b, 1, 0, 0);
    b.bytes[1] = (unsigned char)prefix;
    if (gateway) put(&b, RTA_GATEWAY, gw, 4);
    put(&b, RTA_VIA, bytes, len);
    request(fd, RTM_NEWROUTE, NLM_F_CREATE | NLM_F_EXCL, &b, label);
}
/* A hop of an RTA_MULTIPATH: through `via` by RTA_VIA, or with `gateway`
   by RTA_GATEWAY. */
struct hop {
    const char *via, *gateway;
    int oif;
};
static void multipath(int fd, unsigned short type, const struct hop *hops, int n, const char *label) {
    struct body b = {0};
    start4(&b, type == RTM_NEWROUTE ? 1 : 0, type == RTM_NEWROUTE ? 0 : 255, 0);
    size_t mp = begin(&b, RTA_MULTIPATH);
    for (int i = 0; i < n; i++) {
        size_t at = b.len;
        unsigned char rtnh[8] = {0}, in[4];
        memcpy(rtnh + 4, &hops[i].oif, 4);
        raw(&b, rtnh, sizeof rtnh);
        if (hops[i].gateway) {
            inet_pton(AF_INET, hops[i].gateway, in);
            put(&b, RTA_GATEWAY, in, 4);
        }
        if (hops[i].via) put_via(&b, hops[i].via);
        unsigned short len = (unsigned short)(b.len - at);
        memcpy(b.bytes + at, &len, 2);
    }
    end(&b, mp);
    request(fd, type, type == RTM_NEWROUTE ? NLM_F_CREATE | NLM_F_EXCL : 0, &b, label);
}
/* Shows an attribute of a route: an address, a gateway or a device. */
static void attribute(int kind, const unsigned char *v, int len) {
    char ip[64] = "?";
    int device;
    if ((kind == RTA_GATEWAY || kind == RTA_PREFSRC) && len == 4) {
        inet_ntop(AF_INET, v, ip, sizeof ip);
        printf(" %s=%s", kind == RTA_GATEWAY ? "gateway" : "prefsrc", ip);
    } else if (kind == RTA_VIA && len > 2) {
        unsigned short family;
        memcpy(&family, v, 2);
        inet_ntop(family, v + 2, ip, sizeof ip);
        printf(" via=%d/%d/%s", family, len, ip);
    } else if (kind == RTA_OIF && len == 4) {
        memcpy(&device, v, 4);
        printf(" dev=%d", device);
    }
}
/* Shows the route `h` to 10.2.0.0/24 or into it: its attributes in their
   order, and those of each of its next hops. */
static void show(const struct nl_header *h, const char *label) {
    const unsigned char *body = (const unsigned char *)(h + 1);
    int len = (int)(h->len - sizeof *h);
    unsigned flags;
    if (body[0] != AF_INET) return;
    int mine = 0;
    for (int a = 12; a + 4 <= len;) {
        unsigned short alen, kind;
        memcpy(&alen, body + a, 2);
        memcpy(&kind, body + a + 2, 2);
        if (alen < 4 || a + alen > len) break;
        if (kind == RTA_DST && alen == 8 && body[a + 4] == 10 && body[a + 5] == 2) mine = 1;
        a += (alen + 3) & ~3;
    }
    if (!mine) return;
    memcpy(&flags, body + 8, 4);
    printf("%s: type=%d len=%d flags=0x%x", label, h->type, body[1], flags & ~0x200u);
    for (int a = 12; a + 4 <= len;) {
        unsigned short alen, kind;
        memcpy(&alen, body + a, 2);
        memcpy(&kind, body + a + 2, 2);
        if (alen < 4 || a + alen > len) break;
        if (kind == RTA_MULTIPATH) {
            for (int n = a + 4; n + 8 <= a + alen;) {
                unsigned short nlen;
                int oif;
                memcpy(&nlen, body + n, 2);
                memcpy(&oif, body + n + 4, 4);
                if (nlen < 8) break;
                printf(" [flags=0x%x dev=%d", body[n + 2], oif);
                for (int m = n + 8; m + 4 <= n + nlen;) {
                    unsigned short mlen, mkind;
                    memcpy(&mlen, body + m, 2);
                    memcpy(&mkind, body + m + 2, 2);
                    if (mlen < 4) break;
                    attribute(mkind, body + m + 4, mlen - 4);
                    m += (mlen + 3) & ~3;
                }
                printf("]");
                n += (nlen + 3) & ~3;
            }
        } else {
            attribute(kind, body + a + 4, alen - 4);
        }
        a += (alen + 3) & ~3;
    }
    printf("\n");
}
static int routes = -1;
static void heard(const char *label) {
    static unsigned char buf[65536];
    long n;
    while ((n = recv(routes, buf, sizeof buf, MSG_DONTWAIT)) > 0)
        for (long at = 0; at + (long)sizeof(struct nl_header) <= n;) {
            const struct nl_header *h = (const void *)(buf + at);
            if (h->len < sizeof *h || at + h->len > n) break;
            if (h->type == RTM_NEWROUTE || h->type == RTM_DELROUTE) show(h, label);
            at += (h->len + 3) & ~3u;
        }
}
/* Dumps the routes (RTM_GETROUTE) or, of va, IPv6's neighbours
   (RTM_GETNEIGH) of 2001:db8::/64, as "address state". */
static void dump(unsigned short type, const char *label) {
    int fd = route_socket(0);
    unsigned char buf[65536] = {0};
    struct nl_header *h = (void *)buf;
    h->len = sizeof *h + 12;
    h->type = type;
    h->flags = NLM_F_REQUEST | NLM_F_DUMP;
    h->seq = ++seq;
    buf[sizeof *h] = type == RTM_GETROUTE ? AF_INET : AF_INET6;
    struct nl_address kernel = {.family = AF_NETLINK};
    sendto(fd, buf, h->len, 0, (void *)&kernel, sizeof kernel);
    for (;;) {
        struct pollfd ready = {.fd = fd, .events = POLLIN};
        long n;
        if (poll(&ready, 1, 2000) <= 0 || (n = recv(fd, buf, sizeof buf, 0)) <= 0) break;
        for (long at = 0; at + (long)sizeof(struct nl_header) <= n;) {
            h = (void *)(buf + at);
            if (h->type == 3 || h->type == 2 || h->len < sizeof *h) {
                close(fd);
                return;
            }
            const unsigned char *body = (const unsigned char *)(h + 1);
            int index;
            memcpy(&index, body + 4, 4);
            if (type == RTM_GETROUTE) show(h, label);
            else if (index == VA && h->len >= sizeof *h + 12 + 20 && body[14] == 1 && body[16] == 0x20) {
                char ip[64];
                inet_ntop(AF_INET6, body + 16, ip, sizeof ip);
                printf("%s: %s state=0x%x\n", label, ip, body[8]);
            }
            at += (h->len + 3) & ~3u;
        }
    }
    close(fd);
}
/* A lookup of `dst` with the flags `flags`. */
static void lookup(int fd, const char *dst, unsigned flags, const char *label) {
    struct body b = {0};
    unsigned char rtm[12] = {AF_INET, 32}, in[4];
    memcpy(rtm + 8, &flags, 4);
    inet_pton(AF_INET, dst, in);
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
    int error;
    memcpy(&error, buf + sizeof *h, 4);
    if (h->type == 2) printf("%s: error=%d\n", label, error);
    else show(h, label);
}
/* What a datagram and a connection to 10.2.0.1 give, and who sent the
   datagram that comes. */
static int udp, tcp;
static void traffic(const char *label) {
    struct sockaddr_in to = {.sin_family = AF_INET, .sin_port = htons(7000)}, from = {0};
    socklen_t len = sizeof from;
    inet_pton(AF_INET, "10.2.0.1", &to.sin_addr);
    int u = socket(AF_INET, SOCK_DGRAM, 0);
    long sent = result(sendto(u, "x", 1, 0, (void *)&to, sizeof to));
    struct pollfd ready = {.fd = udp, .events = POLLIN};
    char text[32] = "none";
    if (poll(&ready, 1, 300) > 0) {
        recvfrom(udp, text, sizeof text, 0, (void *)&from, &len);
        inet_ntop(AF_INET, &from.sin_addr, text, sizeof text);
    }
    close(u);
    int c = socket(AF_INET, SOCK_STREAM, 0);
    long opened = result(connect(c, (void *)&to, sizeof to));
    if (opened == 0) close(accept(tcp, NULL, NULL));
    close(c);
    printf("%s: sendto=%ld came from %s, connect=%ld\n", label, sent, text, opened);
}

/* The lines of /proc/net/route after its header, without the spaces
   that pad them: an IPv6 gateway is 00000000 there, and RTF_GATEWAY
   comes of its first 4 bytes (`fib_route_seq_show`). */
static void route_file(const char *label) {
    char line[256];
    FILE *f = fopen("/proc/net/route", "r");
    if (!f) {
        printf("%s: errno=%d\n", label, errno);
        return;
    }
    int first = 1;
    while (fgets(line, sizeof line, f)) {
        size_t n = strlen(line);
        while (n && (line[n - 1] == '\n' || line[n - 1] == ' ')) line[--n] = 0;
        if (!first) printf("%s: %s\n", label, line);
        first = 0;
    }
    fclose(f);
}
int main(int argc, char **argv) {
    if (argc < 2 || strcmp(argv[1], "veth-ipv4-via")) return 99;
    setvbuf(stdout, NULL, _IOLBF, 0);
    printf("unshare=%ld\n", result(unshare(CLONE_NEWNET)));
    int ctl = route_socket(0), here = route_socket(1 | 0x400);
    int on = 1;
    printf("extack=%ld\n", result(setsockopt(ctl, 270, 11, &on, sizeof on)));
    int ns = open("/proc/self/ns/net", O_RDONLY);
    printf("unshare=%ld\n", result(unshare(CLONE_NEWNET)));
    int far = route_socket(0);
    make_pair(ctl, VA, "va", VB, "vb", 0x0a);
    make_pair(ctl, VC, "vc", VD, "vd", 0x0c);
    sysctl("/proc/sys/net/ipv6/conf/vb/accept_dad", "0");
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
    int there = -1;
    printf("setns=%ld\n", result(setns(far_ns, CLONE_NEWNET)));
    there = route_socket(1 | 0x400);
    events = there;
    address6(far, VB, "2001:db8::2", 64, "add vb's address");
    address4(far, VB, "10.0.0.2", 24, "add vb's IPv4 address");
    address4(far, 1, "10.2.0.1", 24, "add 10.2.0.1/24");
    struct sockaddr_in any = {.sin_family = AF_INET, .sin_port = htons(7000)};
    udp = socket(AF_INET, SOCK_DGRAM, 0);
    tcp = socket(AF_INET, SOCK_STREAM, 0);
    printf("bind=%ld", result(bind(udp, (void *)&any, sizeof any)));
    printf(" %ld", result(bind(tcp, (void *)&any, sizeof any)));
    printf(" listen=%ld\n", result(listen(tcp, 8)));
    printf("setns=%ld\n", result(setns(ns, CLONE_NEWNET)));
    events = here;
    address6(ctl, VA, "2001:db8::1", 64, "add va's address");
    address4(ctl, VA, "10.0.0.1", 24, "add va's IPv4 address");
    routes = route_socket(0x40);

    /* What RTA_VIA holds. */
    const unsigned char none[] = {0}, odd[18] = {99}, short4[5] = {AF_INET, 0, 10, 0, 0}, long4[7] = {AF_INET},
                        short6[6] = {AF_INET6}, four[6] = {AF_INET, 0, 10, 0, 0, 2};
    bad(ctl, none, 0, 0, 24, "an empty via");
    bad(ctl, none, 1, 0, 24, "a via of one byte");
    bad(ctl, odd, 2, 0, 24, "a via of a family alone");
    bad(ctl, odd, 18, 0, 24, "a via of another family");
    bad(ctl, short4, 5, 0, 24, "a short IPv4 via");
    bad(ctl, long4, 7, 0, 24, "a long IPv4 via");
    bad(ctl, short6, 6, 0, 24, "a short IPv6 via");
    bad(ctl, four, 6, 1, 24, "a gateway and a via");
    bad(ctl, four, 6, 1, 8, "a gateway and a via, of a bad prefix");
    bad(ctl, odd, 18, 1, 24, "a gateway and a bad via");
    /* What the gateway is. */
    add(ctl, "2001:db8::1", 0, "through its own address");
    add(ctl, "2001:db8::1", VA, "through its own address, on va");
    add(ctl, "::", VA, "through ::");
    add(ctl, "ff02::1", VA, "through a group");
    add(ctl, "2001:db8:9::1", 0, "through an address no route has");
    add(ctl, "2001:db8:9::1", VA, "through one no route has, on va");
    add(ctl, "2001:db8::2", VC, "through one of another device");
    add(ctl, "2001:db8::2", 1, "through one on lo");
    add(ctl, "fe80::ff:fe00:b", 0, "through a link-local one");
    add(ctl, "fe80::ff:fe00:b", 1, "through a link-local one, on lo");
    add(ctl, "fe80::ff:fe00:d", VC, "through one of vc, down");
    add(ctl, "fe80::ff:fe00:d", 77, "through one of no device");
    add(ctl, "10.0.0.9", VC, "through an IPv4 via of another device");
    /* An IPv4 via of 0.0.0.0 is a gateway still (`fib_gw_from_via`
       sets its family), where RTA_GATEWAY's is none. */
    add(ctl, "0.0.0.0", VA, "through an IPv4 via of 0.0.0.0");
    add(ctl, "0.0.0.0", 0, "through an IPv4 via of 0.0.0.0, of no device");
    route(ctl, RTM_NEWROUTE, "0.0.0.0", VA, 1, 0, 4, "on link, through an IPv4 via of 0.0.0.0");
    route(ctl, RTM_NEWROUTE, "2001:db8:9::1", VC, 1, 0, 4, "on link, on vc");
    route(ctl, RTM_NEWROUTE, "2001:db8:9::1", 0, 1, 0, 4, "on link, of no device");
    route(ctl, RTM_NEWROUTE, "2001:db8::2", 0, 1, 254, 0, "of host scope");
    route(ctl, RTM_NEWROUTE, "2001:db8::2", 0, 1, 253, 0, "of link scope");
    del(ctl, "2001:db8::2", VA, "remove it");
    route(ctl, RTM_NEWROUTE, "2001:db8::2", 0, 7, 0, 0, "an unreachable one");
    heard("heard");
    up(ctl, VC, "fe80::ff:fe00:c", "up vc");
    sysctl("/proc/sys/net/ipv6/conf/vc/disable_ipv6", "1");
    add(ctl, "fe80::ff:fe00:d", VC, "through one of vc, IPv6 off");
    sysctl("/proc/sys/net/ipv6/conf/vc/disable_ipv6", "0");

    /* An IPv4 gateway in RTA_VIA is as one in RTA_GATEWAY. */
    add(ctl, "10.0.0.2", 0, "through 10.0.0.2");
    heard("heard");
    dump(RTM_GETROUTE, "routes");
    route_file("route file");
    traffic("traffic");
    del(ctl, "2001:db8::2", 0, "remove one through 2001:db8::2");
    del(ctl, "10.0.0.2", 0, "remove the one through 10.0.0.2");
    /* One of IPv6. */
    add(ctl, "2001:db8::2", 0, "through 2001:db8::2");
    add(ctl, "2001:db8::2", VA, "again");
    heard("heard");
    dump(RTM_GETROUTE, "routes");
    lookup(ctl, "10.2.0.1", 0, "lookup");
    lookup(ctl, "10.2.0.1", RTM_F_FIB_MATCH, "its route");
    route_file("route file");
    dump(RTM_GETNEIGH, "neighbours before");
    traffic("traffic");
    dump(RTM_GETNEIGH, "neighbours");
    del(ctl, "2001:db8::3", 0, "remove one through 2001:db8::3");
    del(ctl, "10.0.0.2", 0, "remove one through 10.0.0.2");
    del(ctl, "2001:db8::2", VC, "remove one on vc");
    del(ctl, "2001:db8::2", VA, "remove it");
    heard("heard");
    add(ctl, "fe80::ff:fe00:b", VA, "through fe80::ff:fe00:b");
    lookup(ctl, "10.2.0.1", 0, "lookup");
    route_file("route file");
    traffic("traffic");
    del(ctl, NULL, VA, "remove it by its device");
    route(ctl, RTM_NEWROUTE, "2001:db8:9::1", VA, 1, 0, 4, "on link");
    dump(RTM_GETROUTE, "routes");
    traffic("traffic to nobody");
    del(ctl, NULL, 0, "remove it");
    /* A gateway whose first 4 bytes are 0 is not RTF_GATEWAY there. */
    route(ctl, RTM_NEWROUTE, "::5", VA, 1, 0, 4, "on link through ::5");
    route_file("route file");
    del(ctl, NULL, 0, "remove it");
    heard("heard");

    /* Hops of both families. */
    const struct hop both[] = {{"2001:db8::2", NULL, 0}, {NULL, "10.0.0.2", VA}};
    const struct hop twice[] = {{"2001:db8::2", "10.0.0.2", 0}, {NULL, "10.0.0.2", VA}};
    const struct hop wrong[] = {{NULL, "10.0.0.2", 0}, {NULL, "10.0.0.2", 0}};
    const struct hop other[] = {{"2001:db8::3", NULL, 0}, {NULL, "10.0.0.2", 0}};
    const struct hop zero[] = {{"0.0.0.0", NULL, VA}};
    const struct hop any_hop[] = {{"2001:db8::2", NULL, 0}, {NULL, NULL, 0}};
    multipath(ctl, RTM_NEWROUTE, twice, 2, "a hop with a gateway and a via");
    multipath(ctl, RTM_NEWROUTE, zero, 1, "a hop through an IPv4 via of 0.0.0.0");
    multipath(ctl, RTM_NEWROUTE, other, 1, "one hop through 2001:db8::3");
    dump(RTM_GETROUTE, "routes");
    multipath(ctl, RTM_DELROUTE, both, 1, "remove one through 2001:db8::2");
    multipath(ctl, RTM_DELROUTE, other, 1, "remove it");
    multipath(ctl, RTM_NEWROUTE, both, 2, "hops through 2001:db8::2 and 10.0.0.2");
    heard("heard");
    dump(RTM_GETROUTE, "routes");
    lookup(ctl, "10.2.0.1", RTM_F_FIB_MATCH, "its route");
    traffic("traffic");
    multipath(ctl, RTM_DELROUTE, twice, 2, "remove one of a hop with both");
    multipath(ctl, RTM_DELROUTE, wrong, 2, "remove one through 10.0.0.2 twice");
    multipath(ctl, RTM_DELROUTE, other, 2, "remove one through 2001:db8::3");
    multipath(ctl, RTM_DELROUTE, any_hop, 2, "remove one through any second hop");
    heard("heard");
    /* RTA_VIA is compared with no next hop without a gateway. */
    route(ctl, RTM_NEWROUTE, NULL, VA, 1, 253, 0, "without a gateway");
    multipath(ctl, RTM_DELROUTE, wrong, 1, "remove one through 10.0.0.2");
    multipath(ctl, RTM_DELROUTE, both, 1, "remove one through 2001:db8::2");
    heard("heard");

    /* The carrier goes and comes: a route made without one is not
       RTNH_F_LINKDOWN of itself. */
    add(ctl, "2001:db8::2", 0, "through 2001:db8::2");
    drain(events);
    set_link(far, VB, 0, "down vb");
    /* Linux takes va's carrier away later, in linkwatch, which marks
       the hops of va RTNH_F_LINKDOWN before it tells of the link. */
    wait_for(NULL, VA, 0, "va's carrier gone");
    dump(RTM_GETROUTE, "routes with vb down");
    del(ctl, NULL, 0, "remove it");
    add(ctl, "2001:db8::2", VA, "through 2001:db8::2 with vb down");
    dump(RTM_GETROUTE, "routes made with vb down");
    drain(events);
    set_link(far, VB, 1, "up vb");
    wait_for(NULL, VA, 1, "va's carrier");
    dump(RTM_GETROUTE, "routes with vb up");
    set_link(ctl, VA, 0, "down va");
    heard("heard");
    dump(RTM_GETROUTE, "routes with va down");
    return 0;
}
