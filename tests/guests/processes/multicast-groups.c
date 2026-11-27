/* The IPv4 groups of a network namespace's devices, as netlink shows them
   (so as root): RTM_GETMULTICAST's dump (inet_dump_ifmcaddr), each
   device's by index, the newest first, of one device or all, its checks,
   and the RTM_NEWMULTICAST and RTM_DELMULTICAST of RTNLGRP_IPV4_MCADDR as
   a device joins a group anew or leaves it for good
   (inet_ifmcaddr_notify): lo's all-hosts group as it comes up, after its
   address and before IPv6's, and as it goes down; sockets' memberships,
   counted as users, the group told of as its first joins and its last
   leaves; a veth pair, "va" (1000) and "vb" (1001), up, down and
   deleted. IFA_MC_USERS, of Linux master only, is not shown. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define NETLINK_ROUTE_ 0
#define SOL_NETLINK_ 270
#define NETLINK_ADD_MEMBERSHIP_ 1
#define NETLINK_EXT_ACK_ 11
#define NETLINK_GET_STRICT_CHK_ 12
#define NLMSG_ERROR_ 2
#define NLMSG_DONE_ 3
#define NLM_F_REQUEST 1
#define NLM_F_MULTI 2
#define NLM_F_ACK 4
#define NLM_F_DUMP 0x300
#define NLM_F_DUMP_FILTERED 0x20
#define NLM_F_ACK_TLVS 0x200
#define NLM_F_EXCL 0x200
#define NLM_F_CREATE 0x400
#define RTM_NEWLINK 16
#define RTM_DELLINK 17
#define RTM_NEWADDR 20
#define RTM_NEWROUTE 24
#define RTM_NEWMULTICAST 56
#define RTM_DELMULTICAST 57
#define RTM_GETMULTICAST 58
#define IFLA_ADDRESS 1
#define IFLA_IFNAME 3
#define IFLA_LINKINFO 18
#define IFLA_INFO_KIND 1
#define IFLA_INFO_DATA 2
#define VETH_INFO_PEER 1
#define IFA_LABEL 3
#define IFA_CACHEINFO 6
#define IFA_MULTICAST 7
#define IFA_MC_USERS 12
#define RTNLGRP_LINK 1
#define RTNLGRP_IPV4_IFADDR 5
#define RTNLGRP_IPV4_ROUTE 7
#define RTNLGRP_IPV6_IFADDR 9
#define RTNLGRP_IPV4_MCADDR 37
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
struct ifam {
    unsigned char family, prefix, flags, scope;
    int index;
};
struct body {
    unsigned char bytes[1024];
    size_t len;
};

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
static int route_socket(void) {
    int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE_);
    struct nl_address at = {.family = AF_NETLINK};
    bind(fd, (void *)&at, sizeof at);
    return fd;
}
static void join(int fd, int group) {
    long r = result(setsockopt(fd, SOL_NETLINK_, NETLINK_ADD_MEMBERSHIP_, &group, sizeof group));
    if (r) printf("join %d=%ld\n", group, r);
}
static void send_request(int fd, unsigned short type, unsigned short flags, const struct body *b) {
    unsigned char buf[2048] = {0};
    struct nl_header *h = (void *)buf;
    h->len = sizeof *h + b->len;
    h->type = type;
    h->flags = NLM_F_REQUEST | flags;
    h->seq = ++seq;
    memcpy(buf + sizeof *h, b->bytes, b->len);
    struct nl_address kernel = {.family = AF_NETLINK};
    if (sendto(fd, buf, h->len, 0, (void *)&kernel, sizeof kernel) < 0) printf("send=%d\n", -errno);
}
/* A request acknowledged; prints its error unless it is 0. */
static void request(int fd, unsigned short type, unsigned short flags, const struct body *b, const char *label) {
    static unsigned char buf[65536];
    send_request(fd, type, NLM_F_ACK | flags, b);
    for (;;) {
        struct pollfd ready = {.fd = fd, .events = POLLIN};
        if (poll(&ready, 1, 2000) <= 0) {
            printf("%s: no answer\n", label);
            return;
        }
        long n = recv(fd, buf, sizeof buf, 0);
        const struct nl_header *h = (const void *)buf;
        if (n < (long)sizeof *h + 4) return;
        if (h->type == NLMSG_ERROR_) {
            int error;
            memcpy(&error, buf + sizeof *h, 4);
            if (error) printf("%s: error=%d\n", label, error);
            return;
        }
    }
}
static void set_link(int fd, int index, int up) {
    struct body b = {0};
    info(&b, index, up ? IFF_UP : 0, IFF_UP);
    request(fd, RTM_NEWLINK, 0, &b, up ? "up" : "down");
}
static void make_pair(int fd) {
    struct body m = {0};
    const unsigned char mac_a[6] = {2, 0, 0, 0, 0, 1}, mac_b[6] = {2, 0, 0, 0, 0, 2};
    info(&m, VA, 0, 0);
    put(&m, IFLA_IFNAME, "va", 3);
    put(&m, IFLA_ADDRESS, mac_a, 6);
    size_t link = begin(&m, IFLA_LINKINFO);
    put(&m, IFLA_INFO_KIND, "veth", 5);
    size_t data = begin(&m, IFLA_INFO_DATA);
    size_t peer = begin(&m, VETH_INFO_PEER);
    info(&m, VB, 0, 0);
    put(&m, IFLA_IFNAME, "vb", 3);
    put(&m, IFLA_ADDRESS, mac_b, 6);
    end(&m, peer);
    end(&m, data);
    end(&m, link);
    request(fd, RTM_NEWLINK, NLM_F_CREATE | NLM_F_EXCL, &m, "make a pair");
}
static void delete_link(int fd, int index) {
    struct body b = {0};
    info(&b, index, 0, 0);
    request(fd, RTM_DELLINK, 0, &b, "delete");
}

static const char *device(int index) {
    static char name[16];
    switch (index) {
    case 1:
        return "lo";
    case VA:
        return "va";
    case VB:
        return "vb";
    }
    snprintf(name, sizeof name, "%d", index);
    return name;
}
/* A group's message: its type, flags but NLM_F_MULTI's, header, group,
   users and lifetimes, and whether its two times are one. */
static void group(const struct nl_header *h, const char *label) {
    const unsigned char *body = (const unsigned char *)(h + 1);
    int len = (int)(h->len - sizeof *h);
    struct ifam ifa;
    memcpy(&ifa, body, sizeof ifa);
    const char *type = h->type == RTM_NEWMULTICAST   ? "new"
                       : h->type == RTM_DELMULTICAST ? "del"
                       : h->type == RTM_GETMULTICAST ? "get"
                                                     : "?";
    printf("  %s %s flags=%#x family=%d prefix=%d ifa_flags=%#x scope=%d on %s:", label, type, h->flags & ~NLM_F_MULTI,
           ifa.family, ifa.prefix, ifa.flags, ifa.scope, device(ifa.index));
    for (int a = (int)sizeof ifa; a + 4 <= len;) {
        unsigned short alen, kind;
        memcpy(&alen, body + a, 2);
        memcpy(&kind, body + a + 2, 2);
        if (alen < 4 || a + alen > len) break;
        const unsigned char *v = body + a + 4;
        if (kind == IFA_MULTICAST && alen == 8) {
            char text[16];
            inet_ntop(AF_INET, v, text, sizeof text);
            printf(" %s", text);
        } else if (kind == IFA_MC_USERS) {
            /* Linux master's users (Linux 7.0, CI's, has none): left out,
               as what is told shows them. */
        } else if (kind == IFA_CACHEINFO && alen == 20) {
            unsigned c[4];
            memcpy(c, v, 16);
            printf(" life=%#x/%#x %s", c[0], c[1], c[2] == c[3] ? "stamps one" : "stamps two");
        } else {
            printf(" [%u:%u]", kind, alen);
        }
        a += (alen + 3) & ~3;
    }
    printf("\n");
}
/* What the monitor has heard since: each group's message, and of the
   others their type alone. */
static void heard(int fd, const char *label) {
    static unsigned char buf[65536];
    printf("%s:", label);
    int none = 1;
    long n;
    while ((n = recv(fd, buf, sizeof buf, MSG_DONTWAIT)) > 0) {
        for (long at = 0; at + (long)sizeof(struct nl_header) <= n;) {
            const struct nl_header *h = (const void *)(buf + at);
            if (h->len < sizeof *h || at + h->len > n) break;
            if (none) printf("\n");
            none = 0;
            if (h->type == RTM_NEWMULTICAST || h->type == RTM_DELMULTICAST) {
                group(h, "heard");
            } else {
                int family = ((const unsigned char *)(h + 1))[0];
                printf("  heard %d family %d\n", h->type, family);
            }
            at += (h->len + 3) & ~3u;
        }
    }
    printf("%s\n", none ? " nothing" : "");
}
/* A dump of the groups of `family`, of `index`, its header's other bytes
   `prefix` and `scope`, with `extra`'s attributes, and how it ends. */
static void dump(int fd, unsigned char family, int index, unsigned char prefix, unsigned char scope,
                 const struct body *extra, int short_header, const char *label) {
    static unsigned char buf[65536];
    struct body b = {0};
    if (short_header) {
        raw(&b, &family, 1);
    } else {
        struct ifam ifa = {.family = family, .prefix = prefix, .scope = scope, .index = index};
        raw(&b, &ifa, sizeof ifa);
        if (extra) {
            memcpy(b.bytes + b.len, extra->bytes, extra->len);
            b.len += extra->len;
        }
    }
    send_request(fd, RTM_GETMULTICAST, NLM_F_DUMP, &b);
    printf("%s:\n", label);
    for (int reads = 0; reads < 16; reads++) {
        struct pollfd ready = {.fd = fd, .events = POLLIN};
        if (poll(&ready, 1, 2000) <= 0) {
            printf("  no answer\n");
            return;
        }
        long n = recv(fd, buf, sizeof buf, 0);
        int count = 0;
        for (long at = 0; at + (long)sizeof(struct nl_header) <= n;) {
            const struct nl_header *h = (const void *)(buf + at);
            if (h->len < sizeof *h || at + h->len > n) break;
            count++;
            if (h->type == NLMSG_DONE_ || h->type == NLMSG_ERROR_) {
                int error;
                memcpy(&error, h + 1, 4);
                printf("  read %d: %s flags=%#x error=%d", count, h->type == NLMSG_DONE_ ? "done" : "error", h->flags,
                       error);
                long first = h->type == NLMSG_DONE_ ? 4 : (long)h->len;
                const unsigned char *body = (const unsigned char *)(h + 1);
                for (long a = first; a + 4 <= (long)(h->len - sizeof *h);) {
                    unsigned short alen, kind;
                    memcpy(&alen, body + a, 2);
                    memcpy(&kind, body + a + 2, 2);
                    if (alen < 4) break;
                    if (kind == 1) printf(" \"%.*s\"", alen - 5, (const char *)body + a + 4);
                    a += (alen + 3) & ~3;
                }
                printf("\n");
                return;
            }
            group(h, "dumped");
            at += (h->len + 3) & ~3u;
        }
        printf("  read %d\n", count);
    }
}
static void dump_all(int fd, const char *label) { dump(fd, AF_INET, 0, 0, 0, NULL, 0, label); }

static int membership(int s, int option, const char *group_ip, int index) {
    struct ip_mreqn m = {.imr_ifindex = index};
    inet_pton(AF_INET, group_ip, &m.imr_multiaddr);
    return (int)result(setsockopt(s, IPPROTO_IP, option, &m, sizeof m));
}
static int source(int s, int option, const char *group_ip, const char *source_ip) {
    struct ip_mreq_source m = {0};
    inet_pton(AF_INET, group_ip, &m.imr_multiaddr);
    inet_pton(AF_INET, source_ip, &m.imr_sourceaddr);
    inet_pton(AF_INET, "127.0.0.1", &m.imr_interface);
    return (int)result(setsockopt(s, IPPROTO_IP, option, &m, sizeof m));
}

int main(int argc, char **argv) {
    if (argc < 2 || strcmp(argv[1], "multicast-groups")) return 99;
    setvbuf(stdout, NULL, _IOLBF, 0);
    printf("unshare=%ld\n", result(unshare(CLONE_NEWNET)));
    int ctl = route_socket();
    int dumps = route_socket();
    int on = 1;
    setsockopt(dumps, SOL_NETLINK_, NETLINK_EXT_ACK_, &on, sizeof on);
    /* What lo's coming up tells, in its order. */
    int order = route_socket();
    join(order, RTNLGRP_LINK);
    join(order, RTNLGRP_IPV4_IFADDR);
    join(order, RTNLGRP_IPV4_ROUTE);
    join(order, RTNLGRP_IPV6_IFADDR);
    join(order, RTNLGRP_IPV4_MCADDR);
    int monitor = route_socket();
    join(monitor, RTNLGRP_IPV4_MCADDR);

    dump_all(dumps, "lo down");
    set_link(ctl, 1, 1);
    heard(order, "lo up, in order");
    close(order);
    heard(monitor, "lo up");
    dump_all(dumps, "lo up");

    int a = socket(AF_INET, SOCK_DGRAM, 0), b = socket(AF_INET, SOCK_DGRAM, 0);
    printf("a joins 239.1.2.3 on lo=%d\n", membership(a, IP_ADD_MEMBERSHIP, "239.1.2.3", 1));
    heard(monitor, "a joined");
    printf("b joins 239.1.2.3 on lo=%d\n", membership(b, IP_ADD_MEMBERSHIP, "239.1.2.3", 1));
    printf("b joins 224.0.0.1 on lo=%d\n", membership(b, IP_ADD_MEMBERSHIP, "224.0.0.1", 1));
    printf("b joins 239.4.4.4 on 9999=%d\n", membership(b, IP_ADD_MEMBERSHIP, "239.4.4.4", 9999));
    heard(monitor, "b joined");
    dump_all(dumps, "both joined");
    printf("a leaves 239.1.2.3=%d\n", membership(a, IP_DROP_MEMBERSHIP, "239.1.2.3", 1));
    heard(monitor, "a left");
    set_link(ctl, 1, 0);
    heard(monitor, "lo down with b in 224.0.0.1");
    dump_all(dumps, "lo down with b");
    set_link(ctl, 1, 1);
    heard(monitor, "lo up again");
    close(b);
    heard(monitor, "b closed");

    /* A source membership joins the group with its first source and
       leaves it with its last. */
    int c = socket(AF_INET, SOCK_DGRAM, 0);
    printf("c adds 10.9.9.9 to 239.5.5.5=%d\n", source(c, IP_ADD_SOURCE_MEMBERSHIP, "239.5.5.5", "10.9.9.9"));
    printf("c adds 10.9.9.8 to 239.5.5.5=%d\n", source(c, IP_ADD_SOURCE_MEMBERSHIP, "239.5.5.5", "10.9.9.8"));
    heard(monitor, "c's sources");
    printf("c drops 10.9.9.9=%d\n", source(c, IP_DROP_SOURCE_MEMBERSHIP, "239.5.5.5", "10.9.9.9"));
    heard(monitor, "c dropped one");
    printf("c drops 10.9.9.8=%d\n", source(c, IP_DROP_SOURCE_MEMBERSHIP, "239.5.5.5", "10.9.9.8"));
    heard(monitor, "c dropped the last");
    struct group_req g = {.gr_interface = 1};
    struct sockaddr_in *in = (void *)&g.gr_group;
    in->sin_family = AF_INET;
    inet_pton(AF_INET, "239.6.6.6", &in->sin_addr);
    printf("c MCAST_JOIN_GROUP 239.6.6.6=%ld\n", result(setsockopt(c, IPPROTO_IP, MCAST_JOIN_GROUP, &g, sizeof g)));
    heard(monitor, "c joined by MCAST_JOIN_GROUP");

    make_pair(ctl);
    heard(monitor, "a pair made");
    dump_all(dumps, "a pair down");
    set_link(ctl, VA, 1);
    heard(monitor, "va up");
    set_link(ctl, VB, 1);
    heard(monitor, "vb up");
    int d = socket(AF_INET, SOCK_DGRAM, 0);
    printf("d joins 239.7.7.7 on va=%d\n", membership(d, IP_ADD_MEMBERSHIP, "239.7.7.7", VA));
    printf("d joins 239.7.7.7 on vb=%d\n", membership(d, IP_ADD_MEMBERSHIP, "239.7.7.7", VB));
    heard(monitor, "d joined");
    dump_all(dumps, "all");
    dump(dumps, AF_INET, VA, 0, 0, NULL, 0, "va's, not strictly");
    setsockopt(dumps, SOL_NETLINK_, NETLINK_GET_STRICT_CHK_, &on, sizeof on);
    dump(dumps, AF_INET, VA, 0, 0, NULL, 0, "va's");
    dump(dumps, AF_INET, 0, 0, 0, NULL, 0, "all, strictly");
    dump(dumps, AF_INET, 9999, 0, 0, NULL, 0, "of none");
    dump(dumps, AF_INET, 0, 24, 0, NULL, 0, "a prefix");
    dump(dumps, AF_INET, 0, 0, 200, NULL, 0, "a scope");
    dump(dumps, AF_INET, 0, 0, 0, NULL, 1, "a short header");
    struct body label = {0};
    put(&label, IFA_LABEL, "lo", 3);
    dump(dumps, AF_INET, 0, 0, 0, &label, 0, "a label");
    dump(dumps, AF_UNSPEC, 0, 0, 0, NULL, 0, "AF_UNSPEC");
    set_link(ctl, VA, 0);
    heard(monitor, "va down");
    set_link(ctl, VA, 1);
    heard(monitor, "va up again");
    delete_link(ctl, VA);
    heard(monitor, "the pair deleted");
    close(d);
    heard(monitor, "d closed");
    close(c);
    heard(monitor, "c closed");
    close(a);
    dump_all(dumps, "at the end");
    return 0;
}
