/* The source filters of multicast memberships, across a veth pair (so as
   root): one process makes a network namespace A and, with sockets kept
   there, another, B, and the pair va (1000, in A) to vb (1001, in B), with
   10.1.0.1, 10.1.0.2, 2001:db8:1::1 and ::2 on va, and 10.1.0.11 and
   2001:db8:1::11 on vb. First the options and their errors, of both
   families, over UDP and TCP sockets (which take them too): the IPv4
   IP_ADD_SOURCE_MEMBERSHIP, IP_DROP_SOURCE_MEMBERSHIP, IP_BLOCK_SOURCE,
   IP_UNBLOCK_SOURCE and IP_MSFILTER, and the MCAST_ ones, set and, of the
   filters, read. Then datagrams to a group from both addresses of va's, of
   which each of B's sockets, and A's own, shows those it takes as the
   filters change: those of the socket, and those of the device, which takes
   what some membership there does, for a socket that is no member and takes
   every group's too. Last, the routes that say whether the device takes a
   source (RTCF_LOCAL). A datagram to a group has been delivered as sendto
   returns. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <sched.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define NETLINK_ROUTE_ 0
#define RTM_NEWLINK 16
#define RTM_NEWADDR 20
#define RTM_NEWROUTE 24
#define RTM_GETROUTE 26
#define RTA_DST 1
#define RTA_SRC 2
#define RTA_IIF 3
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
#define IFA_LOCAL 2
#define IFA_F_NODAD 0x02
#define VA 1000
#define VB 1001

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
static void request(int fd, unsigned short type, unsigned short flags, const struct body *b, const char *label) {
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
            return;
        }
        long n = recv(fd, buf, sizeof buf, 0);
        if (n < (long)sizeof *h + 4) return;
        if (h->type == 2) {
            int error;
            memcpy(&error, buf + sizeof *h, 4);
            printf("%s: %s: error=%d\n", side, label, error);
            return;
        }
    }
}

static void set_link(int fd, int index, int up, const char *label) {
    struct body b = {0};
    info(&b, index, up ? IFF_UP : 0, IFF_UP);
    request(fd, RTM_NEWLINK, 0, &b, label);
}
/* The local IPv6 routes heard of, each of an address there. */
static unsigned char locals[64][16];
static int known;
/* Hears what comes to the member `links`, waiting up to 5 s: whether any
   did. */
static int hear(int links) {
    static unsigned char buf[65536];
    struct pollfd ready = {.fd = links, .events = POLLIN};
    if (poll(&ready, 1, 5000) <= 0) return 0;
    long n = recv(links, buf, sizeof buf, MSG_DONTWAIT);
    for (long at = 0; at + (long)sizeof(struct nl_header) <= n;) {
        const struct nl_header *h = (const void *)(buf + at);
        if (h->len < sizeof *h || at + h->len > n) break;
        const unsigned char *body = (const unsigned char *)(h + 1);
        int body_len = (int)(h->len - sizeof *h);
        int local = h->type == RTM_NEWROUTE && body_len >= 12 && body[0] == AF_INET6 && body[7] == 2;
        for (int a = 12; local && a + 4 <= body_len;) {
            unsigned short alen, kind;
            memcpy(&alen, body + a, 2);
            memcpy(&kind, body + a + 2, 2);
            if (alen < 4 || a + alen > body_len) break;
            if (kind == RTA_DST && alen == 20 && known < 64) memcpy(locals[known++], body + a + 4, 16);
            a += (alen + 3) & ~3;
        }
        at += (h->len + 3) & ~3u;
    }
    return n > 0;
}
/* Waits for the address `ip` to be there. */
static void address_up(int links, const char *ip) {
    unsigned char want[16];
    inet_pton(AF_INET6, ip, want);
    for (int seen = 0;;) {
        for (; seen < known; seen++)
            if (!memcmp(locals[seen], want, 16)) return;
        if (!hear(links)) {
            printf("%s: %s never came\n", side, ip);
            return;
        }
    }
}
/* Whether the devices from 1000 on were last heard of with their carrier
   (2) or without it (1). */
static int heard[6];
/* Waits, up to 5 s, until the member links hears, or has heard, that the
   device of `index` has its carrier, or has lost it. */
static void carrier(int links, int index, int want) {
    static unsigned char buf[65536];
    while (heard[index - 1000] != want + 1) {
        struct pollfd ready = {.fd = links, .events = POLLIN};
        if (poll(&ready, 1, 5000) <= 0) {
            printf("%s: no carrier change on %d\n", side, index);
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
                for (int a = 16; i.index >= 1000 && i.index < 1006 && a + 4 <= body_len;) {
                    unsigned short alen, kind;
                    memcpy(&alen, body + a, 2);
                    memcpy(&kind, body + a + 2, 2);
                    if (alen < 4 || a + alen > body_len) break;
                    if ((kind & 0x3fff) == IFLA_CARRIER && alen >= 5) heard[i.index - 1000] = body[a + 4] + 1;
                    a += (alen + 3) & ~3;
                }
            }
            at += (h->len + 3) & ~3u;
        }
    }
}

static void make_pair(int ctl, int ns, int own, const char *own_name, int theirs, const char *their_name) {
    struct body m = {0};
    unsigned char mac[6] = {2, 0, 0, 0, 0, (unsigned char)(own - 1000 + 10)};
    info(&m, own, 0, 0);
    put(&m, IFLA_IFNAME, own_name, strlen(own_name) + 1);
    put(&m, IFLA_ADDRESS, mac, 6);
    size_t link = begin(&m, IFLA_LINKINFO);
    put(&m, IFLA_INFO_KIND, "veth", 5);
    size_t data = begin(&m, IFLA_INFO_DATA);
    size_t peer = begin(&m, VETH_INFO_PEER);
    info(&m, theirs, 0, 0);
    put(&m, IFLA_IFNAME, their_name, strlen(their_name) + 1);
    mac[5]++;
    put(&m, IFLA_ADDRESS, mac, 6);
    put32(&m, IFLA_NET_NS_PID, (unsigned)ns);
    end(&m, peer);
    end(&m, data);
    end(&m, link);
    request(ctl, RTM_NEWLINK, NLM_F_CREATE | NLM_F_EXCL, &m, "make a pair");
}
/* The route to the group `ip`, out through `oif`, or in on `iif` from
   `src`: its type and flags. */
static void look_up(int ctl, const char *ip, int oif, int iif, const char *src, const char *label) {
    unsigned char buf[4096] = {0};
    struct body b = {0};
    const unsigned char m[12] = {AF_INET, 32, src ? 32 : 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    struct in_addr in;
    inet_pton(AF_INET, ip, &in);
    raw(&b, m, sizeof m);
    put(&b, RTA_DST, &in, 4);
    if (src) {
        inet_pton(AF_INET, src, &in);
        put(&b, RTA_SRC, &in, 4);
    }
    if (oif) put32(&b, RTA_OIF, (unsigned)oif);
    if (iif) put32(&b, RTA_IIF, (unsigned)iif);
    struct nl_header *h = (void *)buf;
    h->len = sizeof *h + b.len;
    h->type = RTM_GETROUTE;
    h->flags = NLM_F_REQUEST;
    h->seq = ++seq;
    memcpy(buf + sizeof *h, b.bytes, b.len);
    send(ctl, buf, h->len, 0);
    struct pollfd ready = {.fd = ctl, .events = POLLIN};
    if (poll(&ready, 1, 2000) <= 0 || recv(ctl, buf, sizeof buf, 0) < (long)sizeof *h + 4) {
        printf("%s: %s: no answer\n", side, label);
        return;
    }
    if (h->type == 2) {
        int error;
        memcpy(&error, buf + sizeof *h, 4);
        printf("%s: %s: error=%d\n", side, label, error);
        return;
    }
    unsigned flags;
    memcpy(&flags, buf + sizeof *h + 8, 4);
    printf("%s: %s: type=%d flags=%#x\n", side, label, buf[sizeof *h + 7], flags);
}

/* Adds `ip` to the device of `index`, with no duplicate address detection. */
static void address(int fd, int links, int index, const char *ip) {
    struct body b = {0};
    int six = strchr(ip, ':') != NULL;
    struct ifaddrmsg_ a = {.family = six ? AF_INET6 : AF_INET, .prefix = six ? 64 : 24, .index = index};
    if (six) a.flags = IFA_F_NODAD;
    unsigned char in[16];
    inet_pton(a.family, ip, in);
    raw(&b, &a, sizeof a);
    put(&b, IFA_LOCAL, in, six ? 16 : 4);
    put(&b, IFA_ADDRESS, in, six ? 16 : 4);
    request(fd, RTM_NEWADDR, NLM_F_CREATE | NLM_F_EXCL, &b, ip);
    if (six) address_up(links, ip);
}

static void show(const char *label, long r) { printf("%s=%ld\n", label, r); }
static struct sockaddr_storage at(const char *ip, int port) {
    struct sockaddr_storage s = {0};
    if (strchr(ip, ':')) {
        struct sockaddr_in6 *a = (void *)&s;
        a->sin6_family = AF_INET6;
        a->sin6_port = htons((unsigned short)port);
        inet_pton(AF_INET6, ip, &a->sin6_addr);
    } else {
        struct sockaddr_in *a = (void *)&s;
        a->sin_family = AF_INET;
        a->sin_port = htons((unsigned short)port);
        inet_pton(AF_INET, ip, &a->sin_addr);
    }
    return s;
}
static int level(const char *ip) { return strchr(ip, ':') ? IPPROTO_IPV6 : IPPROTO_IP; }
/* The MCAST_ options, by the device's index. */
static long group(int fd, int name, const char *group, int index) {
    struct group_req r = {.gr_interface = (unsigned)index, .gr_group = at(group, 0)};
    return result(setsockopt(fd, level(group), name, &r, sizeof r));
}
static long source(int fd, int name, const char *group, const char *source, int index) {
    struct group_source_req r = {.gsr_interface = (unsigned)index, .gsr_group = at(group, 0), .gsr_source = at(source, 0)};
    return result(setsockopt(fd, level(group), name, &r, sizeof r));
}
/* IPv4's own, by an address of the device. */
static long source4(int fd, int name, const char *group, const char *source, const char *address) {
    struct ip_mreq_source r = {0};
    inet_pton(AF_INET, group, &r.imr_multiaddr);
    inet_pton(AF_INET, source, &r.imr_sourceaddr);
    inet_pton(AF_INET, address, &r.imr_interface);
    return result(setsockopt(fd, IPPROTO_IP, name, &r, sizeof r));
}
/* A group_filter or an ip_msfilter of `n` sources, the strings after. */
static union {
    struct group_filter group;
    struct ip_msfilter ip;
    unsigned char bytes[(128 << 10) + 8];
} buf;
static socklen_t filter_of(const char *group, int index, unsigned mode, int n, va_list list) {
    memset(&buf, 0, sizeof buf);
    buf.group.gf_interface = (unsigned)index;
    buf.group.gf_group = at(group, 0);
    buf.group.gf_fmode = mode;
    buf.group.gf_numsrc = (unsigned)n;
    for (int i = 0; i < n; i++) ((struct sockaddr_storage *)(buf.bytes + 144))[i] = at(va_arg(list, char *), 0);
    return (socklen_t)(144 + n * 128);
}
static long filter(int fd, const char *group, int index, unsigned mode, int n, ...) {
    va_list list;
    va_start(list, n);
    socklen_t len = filter_of(group, index, mode, n, list);
    va_end(list);
    return result(setsockopt(fd, level(group), MCAST_MSFILTER, &buf, len));
}
static socklen_t filter4_of(const char *group, const char *address, unsigned mode, int n, va_list list) {
    memset(&buf, 0, sizeof buf);
    inet_pton(AF_INET, group, &buf.ip.imsf_multiaddr);
    inet_pton(AF_INET, address, &buf.ip.imsf_interface);
    buf.ip.imsf_fmode = mode;
    buf.ip.imsf_numsrc = (unsigned)n;
    for (int i = 0; i < n; i++) inet_pton(AF_INET, va_arg(list, char *), buf.bytes + 16 + 4 * i);
    return (socklen_t)(16 + n * 4);
}
static long filter4(int fd, const char *group, const char *address, unsigned mode, int n, ...) {
    va_list list;
    va_start(list, n);
    socklen_t len = filter4_of(group, address, mode, n, list);
    va_end(list);
    return result(setsockopt(fd, IPPROTO_IP, IP_MSFILTER, &buf, len));
}
/* Reads the filter of `ip` on the device of `index`, asking for `n` sources
   in `room` bytes. */
static void get(int fd, const char *ip, int index, unsigned n, socklen_t room) {
    memset(&buf, 0x55, sizeof buf);
    buf.group.gf_interface = (unsigned)index;
    buf.group.gf_group = at(ip, 5);
    buf.group.gf_fmode = 7;
    buf.group.gf_numsrc = n;
    long r = result(getsockopt(fd, level(ip), MCAST_MSFILTER, &buf, &room));
    printf("  get=%ld len=%u mode=%u sources=%u", r, room, buf.group.gf_fmode, buf.group.gf_numsrc);
    const struct sockaddr_storage *list = (void *)(buf.bytes + 144);
    for (int i = 0; i < 4 && list[i].ss_family != 0x5555; i++) {
        char text[64] = "?";
        const void *a = list[i].ss_family == AF_INET6 ? (void *)&((struct sockaddr_in6 *)&list[i])->sin6_addr
                                                      : (void *)&((struct sockaddr_in *)&list[i])->sin_addr;
        inet_ntop(list[i].ss_family, a, text, sizeof text);
        printf(" %s", text);
    }
    printf("\n");
}
static void get4(int fd, const char *ip, const char *address, unsigned n, socklen_t room) {
    memset(&buf, 0x55, sizeof buf);
    inet_pton(AF_INET, ip, &buf.ip.imsf_multiaddr);
    inet_pton(AF_INET, address, &buf.ip.imsf_interface);
    buf.ip.imsf_fmode = 7;
    buf.ip.imsf_numsrc = n;
    long r = result(getsockopt(fd, IPPROTO_IP, IP_MSFILTER, &buf, &room));
    printf("  get=%ld len=%u mode=%u sources=%u", r, room, buf.ip.imsf_fmode, buf.ip.imsf_numsrc);
    for (int i = 0; i < 4 && memcmp(buf.bytes + 16 + 4 * i, "UUUU", 4); i++) {
        char text[64];
        inet_ntop(AF_INET, buf.bytes + 16 + 4 * i, text, sizeof text);
        printf(" %s", text);
    }
    printf("\n");
}

/* A family: its group, va's two addresses, another, vb's. */
struct family {
    int af;
    const char *group, *one, *two, *three, *own;
};
static const struct family families[] = {
    {AF_INET, "239.1.2.3", "10.1.0.1", "10.1.0.2", "10.1.0.3", "10.1.0.11"},
    {AF_INET6, "ff05::1:3", "2001:db8:1::1", "2001:db8:1::2", "2001:db8:1::3", "2001:db8:1::11"},
};
static const struct {
    int name;
    const char *label;
} names[] = {
    {MCAST_JOIN_SOURCE_GROUP, "join a source"},
    {MCAST_LEAVE_SOURCE_GROUP, "leave a source"},
    {MCAST_BLOCK_SOURCE, "block"},
    {MCAST_UNBLOCK_SOURCE, "unblock"},
};

/* The options of a family and their errors, over a socket of B's. */
static void options(const struct family *f, int type) {
    int fd = socket(f->af, type, 0), l = level(f->group);
    void *const nowhere = (void *)8;
    printf("options of family %d type %d\n", f->af, type);
    show("join a group", group(fd, MCAST_JOIN_GROUP, f->group, VB));
    show("join it again", group(fd, MCAST_JOIN_GROUP, f->group, VB));
    show("join on no device", group(fd, MCAST_JOIN_GROUP, f->group, 99));
    show("join on -1", group(fd, MCAST_JOIN_GROUP, f->group, -1));
    show("join on lo", group(fd, MCAST_JOIN_GROUP, f->group, 1));
    show("join no group", group(fd, MCAST_JOIN_GROUP, f->one, VB));
    struct group_req r = {.gr_interface = VB, .gr_group = at(f->group, 0)};
    show("join in 135 bytes", result(setsockopt(fd, l, MCAST_JOIN_GROUP, &r, 135)));
    show("join in 200 bytes", result(setsockopt(fd, l, MCAST_JOIN_GROUP, memcpy(&buf, &r, sizeof r), 200)));
    show("join from nowhere", result(setsockopt(fd, l, MCAST_JOIN_GROUP, nowhere, sizeof r)));
    show("join from NULL", result(setsockopt(fd, l, MCAST_JOIN_GROUP, NULL, sizeof r)));
    show("join in -1 bytes", result(setsockopt(fd, l, MCAST_JOIN_GROUP, &r, (socklen_t)-1)));
    r.gr_group.ss_family = AF_UNIX;
    show("join of another family", result(setsockopt(fd, l, MCAST_JOIN_GROUP, &r, sizeof r)));
    show("leave of another family", result(setsockopt(fd, l, MCAST_LEAVE_GROUP, &r, sizeof r)));
    show("leave on lo", group(fd, MCAST_LEAVE_GROUP, f->group, 1));
    show("leave on lo again", group(fd, MCAST_LEAVE_GROUP, f->group, 1));
    show("leave on no device", group(fd, MCAST_LEAVE_GROUP, f->group, 99));
    show("leave no group", group(fd, MCAST_LEAVE_GROUP, f->one, VB));
    struct group_source_req s = {.gsr_interface = VB, .gsr_group = at(f->group, 0), .gsr_source = at(f->one, 0)};
    for (int i = 0; i < 4; i++) {
        int name = names[i].name;
        printf("%s:\n", names[i].label);
        show(" no member of it", source(fd, name, name == MCAST_JOIN_SOURCE_GROUP ? f->one : f->af == AF_INET ? "239.9.9.9" : "ff05::9", f->one, VB));
        show(" on no device", source(fd, name, f->group, f->one, 99));
        show(" no group", source(fd, name, f->one, f->one, VB));
        show(" in 263 bytes", result(setsockopt(fd, l, name, &s, 263)));
        show(" in 265 bytes", result(setsockopt(fd, l, name, memcpy(&buf, &s, sizeof s), 265)));
        show(" from nowhere", result(setsockopt(fd, l, name, nowhere, sizeof s)));
        show(" from NULL", result(setsockopt(fd, l, name, NULL, sizeof s)));
        s.gsr_source.ss_family = AF_UNIX;
        show(" of another family", result(setsockopt(fd, l, name, &s, sizeof s)));
        s.gsr_source.ss_family = (unsigned short)f->af;
        s.gsr_group.ss_family = AF_UNIX;
        show(" of a group of another family", result(setsockopt(fd, l, name, &s, sizeof s)));
        s.gsr_group.ss_family = (unsigned short)f->af;
    }
    /* The modes. */
    get(fd, f->group, VB, 9, 144);
    show("unblock one not blocked", source(fd, MCAST_UNBLOCK_SOURCE, f->group, f->one, VB));
    get(fd, f->group, VB, 9, 144);
    show("block one", source(fd, MCAST_BLOCK_SOURCE, f->group, f->one, VB));
    show("block it again", source(fd, MCAST_BLOCK_SOURCE, f->group, f->one, VB));
    show("block another", source(fd, MCAST_BLOCK_SOURCE, f->group, f->two, VB));
    show("join one, blocking", source(fd, MCAST_JOIN_SOURCE_GROUP, f->group, f->three, VB));
    show("leave one, blocking", source(fd, MCAST_LEAVE_SOURCE_GROUP, f->group, f->one, VB));
    get(fd, f->group, VB, 9, 144);
    get(fd, f->group, VB, 9, 4096);
    get(fd, f->group, VB, 1, 144);
    get(fd, f->group, VB, 0, 144);
    get(fd, f->group, VB, 9, 143);
    get(fd, f->group, 1, 9, 144);
    get(fd, f->group, 99, 9, 144);
    get(fd, f->group, 0, 9, 144);
    get(fd, f->one, VB, 9, 144);
    socklen_t len = 144;
    show("get from nowhere", result(getsockopt(fd, l, MCAST_MSFILTER, nowhere, &len)));
    buf.group.gf_group.ss_family = AF_UNIX;
    show("get of another family", result(getsockopt(fd, l, MCAST_MSFILTER, &buf, &len)));
    show("unblock one", source(fd, MCAST_UNBLOCK_SOURCE, f->group, f->one, VB));
    show("unblock it again", source(fd, MCAST_UNBLOCK_SOURCE, f->group, f->one, VB));
    get(fd, f->group, VB, 9, 144);
    /* The most. */
    int most = f->af == AF_INET ? 10 : 64;
    for (int i = 2; i <= most + 1; i++) {
        char ip[64];
        snprintf(ip, sizeof ip, f->af == AF_INET ? "10.2.0.%d" : "2001:db8:2::%d", i);
        long e = source(fd, MCAST_BLOCK_SOURCE, f->group, ip, VB);
        if (e || i >= most) show(ip, e);
    }
    show("block one more there already", source(fd, MCAST_BLOCK_SOURCE, f->group, f->two, VB));
    /* Whole filters. */
    show("filter no group", filter(fd, f->one, VB, MCAST_EXCLUDE, 0));
    show("filter of mode 2", filter(fd, f->group, VB, 2, 0));
    show("filter on no device", filter(fd, f->group, 99, MCAST_EXCLUDE, 0));
    show("filter on lo", filter(fd, f->group, 1, MCAST_EXCLUDE, 1, f->one));
    show("filter on none", filter(fd, f->group, 0, MCAST_EXCLUDE, 1, f->one));
    show("filter", filter(fd, f->group, VB, MCAST_INCLUDE, 3, f->two, f->one, f->two));
    get(fd, f->group, VB, 9, 144);
    show("block, including", source(fd, MCAST_BLOCK_SOURCE, f->group, f->three, VB));
    show("leave a source", source(fd, MCAST_LEAVE_SOURCE_GROUP, f->group, f->two, VB));
    get(fd, f->group, VB, 9, 144);
    show("filter of another family", filter(fd, f->group, VB, MCAST_EXCLUDE, 2, f->one, f->af == AF_INET ? "::1" : "1.2.3.4"));
    get(fd, f->group, VB, 9, 144);
    buf.group.gf_fmode = MCAST_EXCLUDE;
    buf.group.gf_interface = VB;
    buf.group.gf_group = at(f->group, 0);
    for (unsigned i = 0; i < 4; i++) {
        const unsigned counts[] = {1, (unsigned)most, (unsigned)most + 1, 0x80000000u};
        buf.group.gf_numsrc = counts[i];
        printf("%u sources in 144 bytes=%ld\n", counts[i], result(setsockopt(fd, l, MCAST_MSFILTER, &buf, 144)));
    }
    buf.group.gf_numsrc = 0;
    show("filter in 143 bytes", result(setsockopt(fd, l, MCAST_MSFILTER, &buf, 143)));
    show("filter in 128 KiB", result(setsockopt(fd, l, MCAST_MSFILTER, &buf, 128 << 10)));
    show("filter in more", result(setsockopt(fd, l, MCAST_MSFILTER, &buf, (128 << 10) + 1)));
    show("filter from nowhere", result(setsockopt(fd, l, MCAST_MSFILTER, nowhere, 144)));
    get(fd, f->group, VB, 9, 144);
    show("empty including, on none", filter(fd, f->group, 0, MCAST_INCLUDE, 0));
    show("empty including", filter(fd, f->group, VB, MCAST_INCLUDE, 0));
    show("empty including again", filter(fd, f->group, VB, MCAST_INCLUDE, 0));
    get(fd, f->group, VB, 9, 144);
    /* With no prior join. */
    show("join a source", source(fd, MCAST_JOIN_SOURCE_GROUP, f->group, f->one, VB));
    show("join it again", source(fd, MCAST_JOIN_SOURCE_GROUP, f->group, f->one, VB));
    show("join its group", group(fd, MCAST_JOIN_GROUP, f->group, VB));
    show("join another", source(fd, MCAST_JOIN_SOURCE_GROUP, f->group, f->two, VB));
    get(fd, f->group, VB, 9, 144);
    show("leave one", source(fd, MCAST_LEAVE_SOURCE_GROUP, f->group, f->one, VB));
    show("leave the other", source(fd, MCAST_LEAVE_SOURCE_GROUP, f->group, f->two, VB));
    get(fd, f->group, VB, 9, 144);
    show("join a group", group(fd, MCAST_JOIN_GROUP, f->group, VB));
    show("join a source of it", source(fd, MCAST_JOIN_SOURCE_GROUP, f->group, f->one, VB));
    get(fd, f->group, VB, 9, 144);
    show("leave the group", group(fd, MCAST_LEAVE_GROUP, f->group, VB));
    get(fd, f->group, VB, 9, 144);
    close(fd);
}
/* IPv4's own, over a socket of `family`. */
static void options4(int family) {
    int fd = socket(family, SOCK_DGRAM, 0);
    const char *g = "239.1.2.3", *own = "10.1.0.11", *a = "10.1.0.1", *b = "10.1.0.2";
    void *const nowhere = (void *)8;
    struct ip_mreq_source r = {0};
    printf("IPv4's own of family %d\n", family);
    const int each[] = {IP_ADD_SOURCE_MEMBERSHIP, IP_DROP_SOURCE_MEMBERSHIP, IP_BLOCK_SOURCE, IP_UNBLOCK_SOURCE};
    for (int i = 0; i < 4; i++) {
        printf("option %d:\n", each[i]);
        show(" no group", source4(fd, each[i], a, a, own));
        show(" of no such address", source4(fd, each[i], g, a, "10.9.9.9"));
        show(" of none", source4(fd, each[i], "240.0.0.1", a, "0.0.0.0"));
        show(" in 11 bytes", result(setsockopt(fd, IPPROTO_IP, each[i], &r, 11)));
        show(" in 13 bytes", result(setsockopt(fd, IPPROTO_IP, each[i], memset(&buf, 0, 16), 13)));
        show(" from nowhere", result(setsockopt(fd, IPPROTO_IP, each[i], nowhere, 12)));
    }
    show("block, no member", source4(fd, IP_BLOCK_SOURCE, g, a, own));
    show("add a source", source4(fd, IP_ADD_SOURCE_MEMBERSHIP, g, a, own));
    show("add it again", source4(fd, IP_ADD_SOURCE_MEMBERSHIP, g, a, own));
    show("add another", source4(fd, IP_ADD_SOURCE_MEMBERSHIP, g, b, own));
    get4(fd, g, own, 9, 16);
    get4(fd, g, own, 1, 400);
    get4(fd, g, own, 0, 16);
    get4(fd, g, own, 9, 15);
    get4(fd, g, "10.9.9.9", 9, 16);
    get4(fd, "239.9.9.9", own, 9, 16);
    get4(fd, a, own, 9, 16);
    get(fd, g, VB, 9, 144);
    socklen_t len = 16;
    show("get from nowhere", result(getsockopt(fd, IPPROTO_IP, IP_MSFILTER, nowhere, &len)));
    show("block", source4(fd, IP_BLOCK_SOURCE, g, a, own));
    show("drop a source", source4(fd, IP_DROP_SOURCE_MEMBERSHIP, g, a, own));
    show("drop it again", source4(fd, IP_DROP_SOURCE_MEMBERSHIP, g, a, own));
    show("drop the other", source4(fd, IP_DROP_SOURCE_MEMBERSHIP, g, b, own));
    show("drop it again", source4(fd, IP_DROP_SOURCE_MEMBERSHIP, g, b, own));
    show("filter, no member", filter4(fd, g, own, MCAST_EXCLUDE, 1, a));
    show("join", group(fd, MCAST_JOIN_GROUP, g, VB));
    show("filter", filter4(fd, g, own, MCAST_EXCLUDE, 2, b, a));
    get4(fd, g, own, 9, 16);
    show("filter of mode 2", filter4(fd, g, own, 2, 0));
    show("filter no group", filter4(fd, a, own, MCAST_EXCLUDE, 0));
    show("filter of no such address", filter4(fd, g, "10.9.9.9", MCAST_EXCLUDE, 0));
    show("filter of 10", filter4(fd, g, own, MCAST_INCLUDE, 10, "1.1.1.1", "1.1.1.2", "1.1.1.3", "1.1.1.4", "1.1.1.5",
                                 "1.1.1.6", "1.1.1.7", "1.1.1.8", "1.1.1.9", "1.1.1.10"));
    show("filter of 11", filter4(fd, g, own, MCAST_INCLUDE, 11, "1.1.1.1", "1.1.1.2", "1.1.1.3", "1.1.1.4", "1.1.1.5",
                                 "1.1.1.6", "1.1.1.7", "1.1.1.8", "1.1.1.9", "1.1.1.10", "1.1.1.11"));
    buf.ip.imsf_numsrc = 2;
    show("filter in 23 bytes", result(setsockopt(fd, IPPROTO_IP, IP_MSFILTER, &buf, 23)));
    show("filter in 15 bytes", result(setsockopt(fd, IPPROTO_IP, IP_MSFILTER, &buf, 15)));
    show("filter in too many", result(setsockopt(fd, IPPROTO_IP, IP_MSFILTER, &buf, (128 << 10) + 1)));
    show("filter from nowhere", result(setsockopt(fd, IPPROTO_IP, IP_MSFILTER, nowhere, 16)));
    get4(fd, g, own, 3, 16);
    show("exclude none", filter4(fd, g, own, MCAST_EXCLUDE, 0));
    get4(fd, g, own, 3, 16);
    show("include none", filter4(fd, g, own, MCAST_INCLUDE, 0));
    get4(fd, g, own, 3, 16);
    /* With its last source unblocked, a filter stays of its mode. */
    show("join", group(fd, MCAST_JOIN_GROUP, g, VB));
    show("block", source4(fd, IP_BLOCK_SOURCE, g, a, own));
    show("unblock", source4(fd, IP_UNBLOCK_SOURCE, g, a, own));
    show("add a source", source4(fd, IP_ADD_SOURCE_MEMBERSHIP, g, a, own));
    get4(fd, g, own, 3, 16);
    show("exclude none", filter4(fd, g, own, MCAST_EXCLUDE, 0));
    show("add a source", source4(fd, IP_ADD_SOURCE_MEMBERSHIP, g, a, own));
    get4(fd, g, own, 3, 16);
    close(fd);
}

static struct {
    int fd;
    const char *label;
} sockets[8];
static int count;
static int watch(int fd, const char *label) {
    sockets[count].fd = fd;
    sockets[count++].label = label;
    return fd;
}
/* A UDP socket with SO_REUSEADDR on `ip` at `port`. */
static int udp(const char *ip, int port) {
    struct sockaddr_storage a = at(ip, port);
    int fd = socket(a.ss_family, SOCK_DGRAM, 0), on = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on);
    long r = result(bind(fd, (void *)&a, sizeof a));
    if (r) printf("bind %s=%ld\n", ip, r);
    return fd;
}
/* Sends "1" to the group from the one address of A's and "2" from the other,
   and shows which of them each socket got. */
static void both(const struct family *f, const int *from, const char *label) {
    struct sockaddr_storage to = at(f->group, 7000);
    printf("%s:", label);
    for (int i = 0; i < 2; i++) {
        long r = result(sendto(from[i], i ? "2" : "1", 1, 0, (void *)&to, sizeof to));
        if (r != 1) printf(" sendto=%ld", r);
    }
    for (int i = 0; i < count; i++) {
        char got[2];
        printf(" %s \"", sockets[i].label);
        while (recv(sockets[i].fd, got, sizeof got, MSG_DONTWAIT) > 0) printf("%c", got[0]);
        printf("\"");
    }
    printf("\n");
}
static void delivery(const struct family *f, const int *from, int own, int ctl_a, int ctl_b) {
    const char *g = f->group, *any = f->af == AF_INET ? "0.0.0.0" : "::";
    printf("delivery of family %d\n", f->af);
    count = 0;
    watch(own, "A's");
    int m = watch(udp(any, 7000), "m"), n = watch(udp(any, 7000), "n");
    watch(udp(any, 7000), "other");
    both(f, from, "no member");
    show("m joins one", source(m, MCAST_JOIN_SOURCE_GROUP, g, f->one, VB));
    both(f, from, "m includes one");
    show("n joins", group(n, MCAST_JOIN_GROUP, g, VB));
    both(f, from, "n is any's");
    show("n blocks one", source(n, MCAST_BLOCK_SOURCE, g, f->one, VB));
    both(f, from, "n blocks one");
    show("n blocks two", source(n, MCAST_BLOCK_SOURCE, g, f->two, VB));
    both(f, from, "n blocks both");
    show("m leaves one", source(m, MCAST_LEAVE_SOURCE_GROUP, g, f->one, VB));
    both(f, from, "m has left");
    show("m joins", group(m, MCAST_JOIN_GROUP, g, VB));
    both(f, from, "m is any's");
    show("m blocks two", source(m, MCAST_BLOCK_SOURCE, g, f->two, VB));
    both(f, from, "both block two");
    show("n unblocks two", source(n, MCAST_UNBLOCK_SOURCE, g, f->two, VB));
    both(f, from, "one each");
    show("m's filter", filter(m, g, VB, MCAST_INCLUDE, 2, f->two, f->three));
    both(f, from, "m includes two");
    show("n's filter", filter(n, g, VB, MCAST_INCLUDE, 1, f->three));
    both(f, from, "n includes neither");
    show("m's filter", filter(m, g, VB, MCAST_EXCLUDE, 2, f->two, f->two));
    both(f, from, "m excludes two");
    show("m unblocks two", source(m, MCAST_UNBLOCK_SOURCE, g, f->two, VB));
    both(f, from, "m excludes two");
    if (f->af == AF_INET) {
        look_up(ctl_b, g, 0, VB, f->one, "in from one");
        look_up(ctl_b, g, 0, VB, f->two, "in from two");
        look_up(ctl_b, g, 0, VB, f->three, "in from three");
    }
    show("n leaves", group(n, MCAST_LEAVE_GROUP, g, VB));
    both(f, from, "n has left");
    if (f->af == AF_INET) {
        look_up(ctl_b, g, 0, VB, f->two, "in from two");
        look_up(ctl_b, g, 0, VB, f->three, "in from three");
    }
    show("m's filter", filter(m, g, VB, MCAST_EXCLUDE, 0));
    both(f, from, "m is any's");
    close(m);
    count = 1;
    both(f, from, "m is closed");
    watch(n, "n");
    /* A's own copies. */
    show("A's joins one", source(own, MCAST_JOIN_SOURCE_GROUP, g, f->one, VA));
    both(f, from, "A's includes one");
    if (f->af == AF_INET) {
        look_up(ctl_a, g, VA, 0, NULL, "out");
        look_up(ctl_a, g, VA, 0, f->one, "out from one");
        look_up(ctl_a, g, VA, 0, f->two, "out from two");
    }
    show("A's joins two", source(own, MCAST_JOIN_SOURCE_GROUP, g, f->two, VA));
    both(f, from, "A's includes both");
    show("A's leaves one", source(own, MCAST_LEAVE_SOURCE_GROUP, g, f->one, VA));
    both(f, from, "A's includes two");
    if (f->af == AF_INET) look_up(ctl_a, g, VA, 0, NULL, "out");
    show("A's filter", filter(own, g, VA, MCAST_EXCLUDE, 1, f->two));
    both(f, from, "A's excludes two");
    close(n);
}

int main(int argc, char **argv) {
    if (argc < 2 || strcmp(argv[1], "multicast-sources")) return 99;
    setvbuf(stdout, NULL, _IOLBF, 0);
    if (unshare(CLONE_NEWNET) < 0) return 98;
    int ctl_a = route_socket(0), links_a = route_socket(0x400), state_a = route_socket(1);
    int from[2][2], own[2];
    for (int i = 0; i < 2; i++) {
        const struct family *f = &families[i];
        from[i][0] = socket(f->af, SOCK_DGRAM, 0);
        from[i][1] = socket(f->af, SOCK_DGRAM, 0);
        own[i] = udp(i ? "::" : "0.0.0.0", 7000);
    }
    if (unshare(CLONE_NEWNET) < 0) return 97;
    int ctl_b = route_socket(0), links_b = route_socket(0x400), state_b = route_socket(1);
    make_pair(ctl_a, getpid(), VA, "va", VB, "vb");
    set_link(ctl_b, 1, 1, "up lo");
    set_link(ctl_a, VA, 1, "up va");
    set_link(ctl_b, VB, 1, "up vb");
    carrier(state_a, VA, 1);
    carrier(state_b, VB, 1);
    for (int i = 0; i < 2; i++) {
        address(ctl_a, links_a, VA, families[i].one);
        address(ctl_a, links_a, VA, families[i].two);
        address(ctl_b, links_b, VB, families[i].own);
    }
    options(&families[0], SOCK_DGRAM);
    options(&families[0], SOCK_STREAM);
    options(&families[1], SOCK_DGRAM);
    options(&families[1], SOCK_STREAM);
    options4(AF_INET);
    options4(AF_INET6);
    for (int i = 0; i < 2; i++) {
        const struct family *f = &families[i];
        for (int j = 0; j < 2; j++) {
            int through = VA;
            struct sockaddr_storage a = at(j ? f->two : f->one, 7001);
            show("bind", result(bind(from[i][j], (void *)&a, sizeof a)));
            struct ip_mreqn m = {.imr_ifindex = VA};
            show("through va", result(i ? setsockopt(from[i][j], IPPROTO_IPV6, IPV6_MULTICAST_IF, &through, sizeof through)
                                        : setsockopt(from[i][j], IPPROTO_IP, IP_MULTICAST_IF, &m, sizeof m)));
        }
        delivery(f, from[i], own[i], ctl_a, ctl_b);
    }
    return 0;
}
