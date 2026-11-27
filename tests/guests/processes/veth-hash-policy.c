/* Which next hop each flow of a multipath route takes by each
   fib_multipath_hash_policy and fib_multipath_hash_fields, IPv4's and
   IPv6's (so as root): the routes of veth-hash-seed, through va (1000)
   and vc (1002) of weights 1 and 3, with net.ipv4.fib_multipath_hash_seed
   1, so that each flow's hop is known. RTM_GETROUTE's lookups name a
   protocol and ports; IPv4's hash them from the packet
   inet_rtm_getroute_build_skb makes, IPv6's from the flow. Unbound UDP
   sockets connected to each destination tell their hops only where the
   policy takes no ports, as such a socket's port is random (inet_autobind);
   UDP and TCP sockets bound to port 7100 tell theirs under every policy, as
   only one with no port yet hashes a random one (FLOWI_FLAG_ANY_SPORT).
   A send with no route leaves its socket bound. Then what the files take,
   and that a new namespace starts from policy 0 and fields 7. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dirent.h>
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
#include <sys/stat.h>
#include <sys/wait.h>
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
#define RTA_IP_PROTO 27
#define RTA_SPORT 28
#define RTA_DPORT 29
#define RTA_FLOWLABEL 31
#define VA 1000
#define VB 1001
#define VC 1002
#define VD 1003
#define COUNT 48
#define SEED "/proc/sys/net/ipv4/fib_multipath_hash_seed"
#define POLICY4 "/proc/sys/net/ipv4/fib_multipath_hash_policy"
#define FIELDS4 "/proc/sys/net/ipv4/fib_multipath_hash_fields"
#define POLICY6 "/proc/sys/net/ipv6/fib_multipath_hash_policy"
#define FIELDS6 "/proc/sys/net/ipv6/fib_multipath_hash_fields"

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
/* Adds a route to `dst`, of `len` bits, through `one` on va and `two` on
   vc, of weights 1 and 3. */
static void route(int fd, const char *dst, int len, const char *one, const char *two, const char *label) {
    int family = strchr(dst, ':') ? AF_INET6 : AF_INET;
    size_t size = family == AF_INET6 ? 16 : 4;
    struct body b = {0};
    const unsigned char rtm[12] = {(unsigned char)family, (unsigned char)len, 0, 0, 254, 3, 0, 1};
    const char *via[] = {one, two};
    const int oif[] = {VA, VC};
    unsigned char in[16];
    inet_pton(family, dst, in);
    raw(&b, rtm, sizeof rtm);
    put(&b, RTA_DST, in, size);
    size_t mp = begin(&b, RTA_MULTIPATH);
    for (int i = 0; i < 2; i++) {
        size_t at = b.len;
        unsigned char rtnh[8] = {0, 0, 0, i ? 2 : 0};
        memcpy(rtnh + 4, &oif[i], 4);
        raw(&b, rtnh, sizeof rtnh);
        inet_pton(family, via[i], in);
        put(&b, RTA_GATEWAY, in, size);
        unsigned short rlen = (unsigned short)(b.len - at);
        memcpy(b.bytes + at, &rlen, 2);
    }
    end(&b, mp);
    request(fd, RTM_NEWROUTE, NLM_F_CREATE | NLM_F_EXCL, &b, label);
}
/* The device of the lookup of `dst` from `src`, with the flow label
   `flowlabel`, the protocol `proto` (none for 0) and the ports `sport` and
   `dport` (none for 0). */
static int lookup(int fd, const char *dst, const char *src, unsigned flowlabel, int proto, int sport,
                  int dport) {
    int family = strchr(dst, ':') ? AF_INET6 : AF_INET, device = -1;
    size_t size = family == AF_INET6 ? 16 : 4;
    struct body b = {0};
    const unsigned char rtm[12] = {(unsigned char)family, (unsigned char)(size * 8),
                                   (unsigned char)(src ? size * 8 : 0)};
    unsigned char in[16], p = (unsigned char)proto;
    unsigned short port;
    raw(&b, rtm, sizeof rtm);
    inet_pton(family, dst, in);
    put(&b, RTA_DST, in, size);
    if (src) {
        inet_pton(family, src, in);
        put(&b, RTA_SRC, in, size);
    }
    if (proto) put(&b, RTA_IP_PROTO, &p, 1);
    if (sport) {
        port = htons((unsigned short)sport);
        put(&b, RTA_SPORT, &port, 2);
    }
    if (dport) {
        port = htons((unsigned short)dport);
        put(&b, RTA_DPORT, &port, 2);
    }
    if (flowlabel) put32(&b, RTA_FLOWLABEL, htonl(flowlabel));
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
    if (poll(&ready, 1, 2000) <= 0 || recv(fd, buf, sizeof buf, 0) < (long)sizeof *h + 4 || h->type != RTM_NEWROUTE)
        return -1;
    const unsigned char *at = (const unsigned char *)(h + 1);
    int len = (int)(h->len - sizeof *h);
    for (int a = 12; a + 4 <= len;) {
        unsigned short alen, kind;
        memcpy(&alen, at + a, 2);
        memcpy(&kind, at + a + 2, 2);
        if (alen < 4 || a + alen > len) break;
        if (kind == RTA_OIF && alen == 8) memcpy(&device, at + a + 4, 4);
        a += (alen + 3) & ~3;
    }
    return device;
}
/* The hops of COUNT lookups into `net`, a character each, shown. */
static void shown(int fd, const char *net, const char *src, unsigned flowlabel, int proto, int sport, int dport,
                  const char *label) {
    char out[COUNT + 1];
    for (int i = 0; i < COUNT; i++) {
        char dst[64];
        snprintf(dst, sizeof dst, strchr(net, ':') ? "%s%x" : "%s%d", net, i + 1);
        int device = lookup(fd, dst, src, flowlabel, proto, sport, dport);
        out[i] = device == VA ? 'a' : device == VC ? 'c' : '?';
    }
    out[COUNT] = 0;
    printf("%s: %s\n", label, out);
}
/* The sources of unbound UDP sockets connected to each destination, which
   tell the hops. */
static void connected(int family) {
    char out[COUNT + 1];
    for (int i = 0; i < COUNT; i++) {
        struct sockaddr_storage to = {0}, at = {0};
        socklen_t len = sizeof at, size;
        if (family == AF_INET) {
            struct sockaddr_in *in = (void *)&to;
            in->sin_family = AF_INET;
            in->sin_port = htons(7000);
            in->sin_addr.s_addr = htonl(0x0a020000u + (unsigned)i + 1);
            size = sizeof *in;
        } else {
            struct sockaddr_in6 *in = (void *)&to;
            char ip[64];
            in->sin6_family = AF_INET6;
            in->sin6_port = htons(7000);
            snprintf(ip, sizeof ip, "2001:db8:2::%x", i + 1);
            inet_pton(AF_INET6, ip, &in->sin6_addr);
            size = sizeof *in;
        }
        int s = socket(family, SOCK_DGRAM, 0);
        connect(s, (void *)&to, size);
        getsockname(s, (void *)&at, &len);
        close(s);
        char ip[64] = {0};
        if (family == AF_INET)
            inet_ntop(AF_INET, &((struct sockaddr_in *)&at)->sin_addr, ip, sizeof ip);
        else
            inet_ntop(AF_INET6, &((struct sockaddr_in6 *)&at)->sin6_addr, ip, sizeof ip);
        out[i] = !strcmp(ip, "10.0.0.1") || !strcmp(ip, "2001:db8::1")     ? 'a'
                 : !strcmp(ip, "10.1.0.1") || !strcmp(ip, "2001:db8:1::1") ? 'c'
                                                                            : '?';
    }
    out[COUNT] = 0;
    printf("%s connected: %s\n", family == AF_INET ? "IPv4" : "IPv6", out);
}
/* The sources of sockets of `type` bound to port 7100 and connected to
   port 7000 at each destination, which tell the hops. */
static void bound(int family, int type) {
    char out[COUNT + 1];
    for (int i = 0; i < COUNT; i++) {
        struct sockaddr_storage to = {0}, from = {0}, at = {0};
        socklen_t len = sizeof at, size;
        if (family == AF_INET) {
            struct sockaddr_in *in = (void *)&to, *own = (void *)&from;
            in->sin_family = own->sin_family = AF_INET;
            in->sin_port = htons(7000);
            own->sin_port = htons(7100);
            in->sin_addr.s_addr = htonl(0x0a020000u + (unsigned)i + 1);
            size = sizeof *in;
        } else {
            struct sockaddr_in6 *in = (void *)&to, *own = (void *)&from;
            char ip[64];
            in->sin6_family = own->sin6_family = AF_INET6;
            in->sin6_port = htons(7000);
            own->sin6_port = htons(7100);
            snprintf(ip, sizeof ip, "2001:db8:2::%x", i + 1);
            inet_pton(AF_INET6, ip, &in->sin6_addr);
            size = sizeof *in;
        }
        int s = socket(family, type | SOCK_NONBLOCK, 0), one = 1;
        setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
        long b = result(bind(s, (void *)&from, size));
        connect(s, (void *)&to, size);
        getsockname(s, (void *)&at, &len);
        close(s);
        char ip[64] = {0};
        if (family == AF_INET)
            inet_ntop(AF_INET, &((struct sockaddr_in *)&at)->sin_addr, ip, sizeof ip);
        else
            inet_ntop(AF_INET6, &((struct sockaddr_in6 *)&at)->sin6_addr, ip, sizeof ip);
        out[i] = b < 0                                                      ? 'b'
                 : !strcmp(ip, "10.0.0.1") || !strcmp(ip, "2001:db8::1")     ? 'a'
                 : !strcmp(ip, "10.1.0.1") || !strcmp(ip, "2001:db8:1::1") ? 'c'
                                                                            : '?';
    }
    out[COUNT] = 0;
    printf("%s %s from 7100: %s\n", family == AF_INET ? "IPv4" : "IPv6", type == SOCK_STREAM ? "TCP" : "UDP",
           out);
}
/* What each family's lookups give; `sockets` where the policy takes no
   ports, else TCP sockets bound to a port too. */
static void all(int fd, int sockets) {
    shown(fd, "10.2.0.", "10.5.0.1", 0, 0, 0, 0, "IPv4");
    shown(fd, "10.2.0.", NULL, 0, 0, 0, 0, "IPv4 from none");
    shown(fd, "10.2.0.", "10.5.0.1", 0, 17, 7000, 53, "IPv4 UDP 7000 to 53");
    shown(fd, "10.2.0.", "10.5.0.1", 0, 17, 53, 7000, "IPv4 UDP 53 to 7000");
    shown(fd, "10.2.0.", "10.5.0.1", 0, 0, 7001, 53, "IPv4 7001 to 53");
    shown(fd, "10.2.0.", "10.5.0.1", 0, 6, 7000, 80, "IPv4 TCP 7000 to 80");
    shown(fd, "10.2.0.", "10.5.0.1", 0, 1, 7000, 80, "IPv4 ICMP 7000 to 80");
    shown(fd, "10.2.0.", "10.5.0.1", 0, 1, 0, 0, "IPv4 ICMP");
    shown(fd, "2001:db8:2::", "2001:db8:5::1", 0, 0, 0, 0, "IPv6");
    shown(fd, "2001:db8:2::", "2001:db8:5::1", 0x12345, 17, 0, 0, "IPv6 UDP, a flow label");
    shown(fd, "2001:db8:2::", "2001:db8:5::1", 0, 17, 7000, 53, "IPv6 UDP 7000 to 53");
    shown(fd, "2001:db8:2::", "2001:db8:5::1", 0, 17, 53, 7000, "IPv6 UDP 53 to 7000");
    shown(fd, "2001:db8:2::", "2001:db8:5::1", 0, 6, 7000, 80, "IPv6 TCP 7000 to 80");
    shown(fd, "2001:db8:2::", "2001:db8:5::1", 0, 58, 7000, 80, "IPv6 ICMPv6 7000 to 80");
    shown(fd, "2001:db8:2::", "2001:db8:5::1", 0x12345, 58, 7000, 80, "IPv6 ICMPv6 7000 to 80, a flow label");
    if (sockets) {
        connected(AF_INET);
        connected(AF_INET6);
    }
    bound(AF_INET, SOCK_DGRAM);
    bound(AF_INET6, SOCK_DGRAM);
    if (!sockets) {
        bound(AF_INET, SOCK_STREAM);
        bound(AF_INET6, SOCK_STREAM);
    }
}
static void get(const char *path, const char *label) {
    char text[32] = {0};
    int fd = open(path, O_RDONLY);
    long n = result(fd < 0 ? fd : read(fd, text, sizeof text - 1));
    if (fd >= 0) close(fd);
    for (char *c = text; *c; c++)
        if (*c == '\n') *c = '|';
    printf("%s: read=%ld %s\n", label, n, text);
}
static long put_file(const char *path, const char *value) {
    int fd = open(path, O_WRONLY);
    long n = result(fd < 0 ? fd : write(fd, value, strlen(value)));
    if (fd >= 0) close(fd);
    return n;
}
/* Both families' policy `policy` and fields `fields` (none for NULL). */
static void both(const char *policy, const char *fields) {
    printf("== policy %s", policy);
    printf(" write=%ld %ld", put_file(POLICY4, policy), put_file(POLICY6, policy));
    if (fields) {
        printf(", fields %s", fields);
        printf(" write=%ld %ld", put_file(FIELDS4, fields), put_file(FIELDS6, fields));
    }
    printf("\n");
}
static void files(const char *label) {
    char at[64];
    const char *paths[] = {POLICY4, FIELDS4, POLICY6, FIELDS6};
    const char *names[] = {"IPv4 policy", "IPv4 fields", "IPv6 policy", "IPv6 fields"};
    for (int i = 0; i < 4; i++) {
        snprintf(at, sizeof at, "%s %s", label, names[i]);
        get(paths[i], at);
    }
}
/* The entries of `path` whose names begin fib_multipath_hash. */
static void listed(const char *path) {
    char line[512] = {0};
    DIR *d = opendir(path);
    struct dirent *e;
    while (d && (e = readdir(d)))
        if (!strncmp(e->d_name, "fib_multipath_hash", 18)) {
            strcat(line, " ");
            strcat(line, e->d_name);
        }
    if (d) closedir(d);
    printf("%s:%s\n", path, line);
}
/* Two pairs, their addresses and the routes. */
static int set_up(void) {
    int ctl = route_socket(0);
    events = route_socket(1 | 0x400);
    make_pair(ctl, VA, "va", VB, "vb", 0x0a);
    make_pair(ctl, VC, "vc", VD, "vd", 0x0c);
    sysctl("/proc/sys/net/ipv6/conf/va/accept_dad", "0");
    sysctl("/proc/sys/net/ipv6/conf/vc/accept_dad", "0");
    set_link(ctl, 1, 1, "up lo");
    set_link(ctl, VB, 1, "up vb");
    set_link(ctl, VD, 1, "up vd");
    up(ctl, VA, "fe80::ff:fe00:a", "up va");
    up(ctl, VC, "fe80::ff:fe00:c", "up vc");
    address4(ctl, VA, "10.0.0.1", 24, "add va's IPv4 address");
    address4(ctl, VC, "10.1.0.1", 24, "add vc's IPv4 address");
    address4(ctl, 1, "10.5.0.1", 32, "add 10.5.0.1/32");
    address6(ctl, VA, "2001:db8::1", 64, "add va's address");
    address6(ctl, VC, "2001:db8:1::1", 64, "add vc's address");
    address6(ctl, 1, "2001:db8:5::1", 128, "add 2001:db8:5::1/128");
    route(ctl, "10.2.0.0", 24, "10.0.0.2", "10.1.0.2", "10.2.0.0/24");
    route(ctl, "2001:db8:2::", 64, "2001:db8::2", "2001:db8:1::2", "2001:db8:2::/64");
    return ctl;
}

int main(int argc, char **argv) {
    if (argc < 2 || strcmp(argv[1], "veth-hash-policy")) return 99;
    setvbuf(stdout, NULL, _IOLBF, 0);
    printf("unshare=%ld\n", result(unshare(CLONE_NEWNET)));
    const char *paths[] = {POLICY4, FIELDS4, POLICY6, FIELDS6};
    for (int i = 0; i < 4; i++) {
        struct stat st = {0};
        long r = result(stat(paths[i], &st));
        printf("stat %s=%ld mode=%o uid=%d gid=%d\n", paths[i], r, st.st_mode, st.st_uid, st.st_gid);
    }
    listed("/proc/sys/net/ipv4");
    listed("/proc/sys/net/ipv6");
    files("built");
    int ctl = set_up();
    printf("seed write=%ld\n", put_file(SEED, "1"));

    both("0", NULL);
    all(ctl, 1);
    both("1", NULL);
    all(ctl, 0);
    both("2", NULL);
    all(ctl, 1);
    static const char *fields[] = {"7", "3", "2", "1", "4", "8", "64", "4032"};
    for (size_t i = 0; i < sizeof fields / sizeof fields[0]; i++) {
        both("3", fields[i]);
        all(ctl, 1);
    }
    static const char *with_ports[] = {"16", "32", "48", "55", "63", "4095"};
    for (size_t i = 0; i < sizeof with_ports / sizeof with_ports[0]; i++) {
        both("3", with_ports[i]);
        all(ctl, 0);
    }
    /* Each family's own: IPv4's policy 3 of its destination, IPv6's 0. */
    put_file(FIELDS4, "2");
    put_file(POLICY6, "0");
    printf("== IPv4 policy 3 fields 2, IPv6 policy 0\n");
    all(ctl, 1);
    files("each its own");

    /* A send's port comes before its route (inet_send_prepare): one that
       finds no route leaves the socket bound. */
    {
        int u = socket(AF_INET, SOCK_DGRAM, 0);
        struct sockaddr_in to = {.sin_family = AF_INET, .sin_port = htons(7000)}, at = {0};
        socklen_t len = sizeof at;
        to.sin_addr.s_addr = htonl(0x0a630001);
        printf("to 10.99.0.1: sendto=%ld\n", result(sendto(u, "x", 1, 0, (void *)&to, sizeof to)));
        getsockname(u, (void *)&at, &len);
        printf("after it: %s\n", at.sin_port ? "a port" : "no port");
        struct sockaddr_in any = {.sin_family = AF_INET, .sin_port = htons(7200)};
        printf("bind after it=%ld\n", result(bind(u, (void *)&any, sizeof any)));
        close(u);
    }

    /* What the files take. */
    static const char *policies[] = {"4", "-1", "256", "3 ", "0x1", "1x", " 2\n", "1"};
    for (size_t i = 0; i < sizeof policies / sizeof policies[0]; i++) {
        char label[32];
        snprintf(label, sizeof label, "policy %zu", i);
        printf("%s: write=%ld\n", label, put_file(POLICY4, policies[i]));
        get(POLICY4, label);
    }
    static const char *masks[] = {"0", "4096", "-1", "4095", "1", "4294967296", "12x"};
    for (size_t i = 0; i < sizeof masks / sizeof masks[0]; i++) {
        char label[32];
        snprintf(label, sizeof label, "fields %zu", i);
        printf("%s: write=%ld\n", label, put_file(FIELDS6, masks[i]));
        get(FIELDS6, label);
    }
    int fd = open(POLICY6, O_RDWR);
    /* Seeks first: a call's arguments may be evaluated in any order. */
    long seek = (long)lseek(fd, 1, SEEK_SET);
    printf("at 1: seek=%ld write=%ld\n", seek, result(write(fd, "2", 1)));
    close(fd);
    get(POLICY6, "at 1");

    printf("unshare=%ld\n", result(unshare(CLONE_NEWNET)));
    files("a new namespace");
    return 0;
}
