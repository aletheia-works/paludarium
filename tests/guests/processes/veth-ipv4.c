/* IPv4 addresses and routes on veth ends (so as root): a child, B, makes a
   network namespace of its own and waits; the parent, A, makes another
   and a pair, its end "va" (1000) in A and "vb" (1001) in B. Each side
   shows what a member of RTNLGRP_IPV4_IFADDR and RTNLGRP_IPV4_ROUTE hears,
   and its IPv4 address and route dumps, as addresses come on an end that
   is down, the ends come up (without, then with their carrier), routes
   through an end are added and looked up, the ends go down and up again,
   and the pair is deleted with its addresses. Only IPv4 is looked at, as
   Linux gives an end up IPv6 link-local addresses of its own; the
   carrier, which Linux's link watch may change a little later, is waited
   for on RTNLGRP_LINK. lo stays down, so it has no routes. The two
   processes take turns through pipes, so their lines come in one order. */
#define _GNU_SOURCE
#include <errno.h>
#include <net/if.h>
#include <poll.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#define NETLINK_ROUTE_ 0
#define RTM_NEWLINK 16
#define RTM_NEWADDR 20
#define RTM_DELADDR 21
#define RTM_GETADDR 22
#define RTM_NEWROUTE 24
#define RTM_DELROUTE 25
#define RTM_GETROUTE 26
#define RTM_DELLINK 17
#define NLM_F_REQUEST 1
#define NLM_F_ACK 4
#define NLM_F_DUMP 0x300
#define NLM_F_EXCL 0x200
#define NLM_F_CREATE 0x400
#define NETLINK_GET_STRICT_CHK_ 12
#define SOL_NETLINK_ 270
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
#define IFA_LABEL 3
#define IFA_BROADCAST 4
#define IFA_FLAGS 8
#define RTA_DST 1
#define RTA_SRC 2
#define RTA_OIF 4
#define RTA_GATEWAY 5
#define RTA_PRIORITY 6
#define RTA_PREFSRC 7
#define RTA_TABLE 15
#define RTM_F_FIB_MATCH 0x2000
#define A_INDEX 1000
#define B_INDEX 1001
/* RTNLGRP_IPV4_IFADDR (5) and RTNLGRP_IPV4_ROUTE (7). */
#define IPV4_GROUPS 0x50

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
struct rtmsg_ {
    unsigned char family, dst_len, src_len, tos, table, protocol, scope, type;
    unsigned flags;
};
/* A request's payload, its attributes nested by begin and end. */
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
static void put_ip(struct body *b, unsigned short type, const char *ip) {
    unsigned char o[4];
    unsigned x[4];
    sscanf(ip, "%u.%u.%u.%u", &x[0], &x[1], &x[2], &x[3]);
    for (int i = 0; i < 4; i++) o[i] = (unsigned char)x[i];
    put(b, type, o, 4);
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

static int route_socket(unsigned groups) {
    int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE_);
    struct nl_address at = {.family = AF_NETLINK, .groups = groups};
    bind(fd, (void *)&at, sizeof at);
    return fd;
}
static void send_request(int fd, unsigned short type, unsigned short flags, const struct body *b) {
    unsigned char buf[2048] = {0};
    struct nl_header *h = (void *)buf;
    h->len = sizeof *h + b->len;
    h->type = type;
    h->flags = flags;
    h->seq = ++seq;
    memcpy(buf + sizeof *h, b->bytes, b->len);
    struct nl_address kernel = {.family = AF_NETLINK};
    if (sendto(fd, buf, h->len, 0, (void *)&kernel, sizeof kernel) < 0) printf("%s: send=%d\n", side, -errno);
}

static void show_ip(const char *name, const unsigned char *v, int len) {
    if (len == 4) printf(" %s=%u.%u.%u.%u", name, v[0], v[1], v[2], v[3]);
}
/* An address or route message's attributes that are the same from run to
   run: no lifetimes' times, no route cache's. */
static void show_attributes(unsigned short type, const unsigned char *body, int at, int len) {
    while (at + 4 <= len) {
        unsigned short alen, kind;
        memcpy(&alen, body + at, 2);
        memcpy(&kind, body + at + 2, 2);
        if (alen < 4 || at + alen > len) break;
        const unsigned char *v = body + at + 4;
        int vlen = alen - 4;
        unsigned value = 0;
        if (vlen >= 4) memcpy(&value, v, 4);
        kind &= 0x3fff;
        if (type == RTM_NEWADDR || type == RTM_DELADDR) {
            switch (kind) {
            case IFA_ADDRESS: show_ip("address", v, vlen); break;
            case IFA_LOCAL: show_ip("local", v, vlen); break;
            case IFA_BROADCAST: show_ip("broadcast", v, vlen); break;
            case IFA_LABEL: printf(" label=%.*s", vlen > 0 ? vlen - 1 : 0, v); break;
            case IFA_FLAGS: printf(" ifa-flags=%#x", value); break;
            }
        } else {
            switch (kind) {
            case RTA_DST: show_ip("dst", v, vlen); break;
            case RTA_SRC: show_ip("src", v, vlen); break;
            case RTA_OIF: printf(" oif=%u", value); break;
            case RTA_GATEWAY: show_ip("gateway", v, vlen); break;
            case RTA_PRIORITY: printf(" priority=%u", value); break;
            case RTA_PREFSRC: show_ip("prefsrc", v, vlen); break;
            case RTA_TABLE: printf(" table=%u", value); break;
            }
        }
        at += (alen + 3) & ~3;
    }
}
/* Prints the IPv4 address and route messages of the n bytes at buf, and
   the errors and ends; returns whether one ended a request. */
static int show(const unsigned char *buf, long n, const char *label) {
    int ended = 0;
    for (long at = 0; at + (long)sizeof(struct nl_header) <= n;) {
        const struct nl_header *h = (const void *)(buf + at);
        if (h->len < sizeof *h || at + h->len > n) break;
        const unsigned char *body = (const unsigned char *)(h + 1);
        int body_len = (int)(h->len - sizeof *h);
        if (h->type == 2 && body_len >= 4) {
            int error;
            memcpy(&error, body, 4);
            printf("%s: %s: error=%d\n", side, label, error);
            ended = 1;
        } else if (h->type == 3) {
            int error = 0;
            if (body_len >= 4) memcpy(&error, body, 4);
            printf("%s: %s: done=%d\n", side, label, error);
            ended = 1;
        } else if ((h->type == RTM_NEWADDR || h->type == RTM_DELADDR) && body_len >= 8 && body[0] == AF_INET) {
            struct ifaddrmsg_ a;
            memcpy(&a, body, sizeof a);
            printf("%s: %s: type=%u seq=%u prefix=%u flags=%#x scope=%u index=%d", side, label, h->type, h->seq,
                   a.prefix, a.flags, a.scope, a.index);
            show_attributes(h->type, body, 8, body_len);
            printf("\n");
        } else if ((h->type == RTM_NEWROUTE || h->type == RTM_DELROUTE) && body_len >= 12 && body[0] == AF_INET) {
            struct rtmsg_ r;
            memcpy(&r, body, sizeof r);
            printf("%s: %s: type=%u seq=%u flags=%#x len=%u tos=%u table=%u proto=%u scope=%u kind=%u "
                   "rtm-flags=%#x",
                   side, label, h->type, h->seq, h->flags, r.dst_len, r.tos, r.table, r.protocol, r.scope, r.type,
                   r.flags);
            show_attributes(h->type, body, 12, body_len);
            printf("\n");
        }
        at += (h->len + 3) & ~3u;
    }
    return ended;
}
/* Receives the answer to the last request on fd, until its error or end. */
static void answer(int fd, const char *label) {
    static unsigned char buf[65536];
    for (;;) {
        struct pollfd ready = {.fd = fd, .events = POLLIN};
        if (poll(&ready, 1, 2000) <= 0) {
            printf("%s: %s: no answer\n", side, label);
            return;
        }
        long n = recv(fd, buf, sizeof buf, 0);
        if (n <= 0) return;
        if (show(buf, n, label)) return;
    }
}
/* What the member mon hears, until none has come for 300 ms. */
static void heard(int mon, const char *label) {
    static unsigned char buf[65536];
    for (;;) {
        struct pollfd ready = {.fd = mon, .events = POLLIN};
        if (poll(&ready, 1, 300) <= 0) return;
        long n = recv(mon, buf, sizeof buf, MSG_DONTWAIT);
        if (n < 0) printf("%s: %s: recv=%d\n", side, label, -errno);
        if (n <= 0) return;
        show(buf, n, label);
    }
}
/* Waits, up to 5 s, until the member links hears that the device of
   `index` has its carrier, or has it not. */
static void carrier(int links, int index, int on) {
    static unsigned char buf[65536];
    for (;;) {
        struct pollfd ready = {.fd = links, .events = POLLIN};
        if (poll(&ready, 1, 5000) <= 0) {
            printf("%s: no carrier change of %d\n", side, index);
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
                    if ((kind & 0x3fff) == IFLA_CARRIER && alen >= 5 && body[a + 4] == on) return;
                    a += (alen + 3) & ~3;
                }
            }
            at += (h->len + 3) & ~3u;
        }
    }
}
static void request(int fd, unsigned short type, unsigned short flags, const struct body *b, const char *label) {
    send_request(fd, type, NLM_F_REQUEST | NLM_F_ACK | flags, b);
    answer(fd, label);
}
static void set_up(int fd, int index, int up, const char *label) {
    struct body b = {0};
    info(&b, index, up ? IFF_UP : 0, IFF_UP);
    request(fd, RTM_NEWLINK, 0, &b, label);
}
/* RTM_NEWADDR or RTM_DELADDR of `ip`/`prefix` on the device of `index`,
   with the broadcast address `broadcast` (none for NULL). */
static void address(int fd, unsigned short type, int index, const char *ip, int prefix, const char *broadcast,
                    const char *label) {
    struct body b = {0};
    struct ifaddrmsg_ a = {.family = AF_INET, .prefix = (unsigned char)prefix, .index = index};
    raw(&b, &a, sizeof a);
    put_ip(&b, IFA_LOCAL, ip);
    put_ip(&b, IFA_ADDRESS, ip);
    if (broadcast) put_ip(&b, IFA_BROADCAST, broadcast);
    request(fd, type, type == RTM_NEWADDR ? NLM_F_CREATE | NLM_F_EXCL : 0, &b, label);
}
/* A route request of `type` to `dst`/`len` through the device of `oif`
   (none for 0), of scope `scope`. */
static void route(int fd, unsigned short type, const char *dst, int len, int oif, int scope, const char *label) {
    struct body b = {0};
    struct rtmsg_ r = {.family = AF_INET,
                       .dst_len = (unsigned char)len,
                       .table = 254,
                       .protocol = 3,
                       .scope = (unsigned char)scope,
                       .type = 1};
    raw(&b, &r, sizeof r);
    put_ip(&b, RTA_DST, dst);
    if (oif) put32(&b, RTA_OIF, (unsigned)oif);
    request(fd, type, type == RTM_NEWROUTE ? NLM_F_CREATE | NLM_F_EXCL : 0, &b, label);
}
/* RTM_GETROUTE of `dst` (from `src`, if any, through `oif`, if any), with
   `flags`. */
static void lookup(int fd, const char *dst, const char *src, int oif, unsigned flags, const char *label) {
    struct body b = {0};
    struct rtmsg_ r = {.family = AF_INET, .dst_len = 32, .src_len = src ? 32 : 0, .flags = flags};
    raw(&b, &r, sizeof r);
    put_ip(&b, RTA_DST, dst);
    if (src) put_ip(&b, RTA_SRC, src);
    if (oif) put32(&b, RTA_OIF, (unsigned)oif);
    send_request(fd, RTM_GETROUTE, NLM_F_REQUEST | NLM_F_ACK, &b);
    answer(fd, label);
}
/* The IPv4 address dump, of the device of `index` (strictly, any for 0),
   then the IPv4 route dump, of the device of `oif` (strictly, any for 0). */
static void dumps(int fd, int index, int oif, const char *label) {
    char what[64];
    struct body b = {0};
    struct ifaddrmsg_ a = {.family = AF_INET, .index = index};
    raw(&b, &a, sizeof a);
    send_request(fd, RTM_GETADDR, NLM_F_REQUEST | NLM_F_DUMP, &b);
    snprintf(what, sizeof what, "%s addresses", label);
    answer(fd, what);
    b = (struct body){0};
    struct rtmsg_ r = {.family = AF_INET};
    raw(&b, &r, sizeof r);
    if (oif) put32(&b, RTA_OIF, (unsigned)oif);
    send_request(fd, RTM_GETROUTE, NLM_F_REQUEST | NLM_F_DUMP, &b);
    snprintf(what, sizeof what, "%s routes", label);
    answer(fd, what);
}
/* A strict socket for requests, as `ip` makes them. */
static int strict_socket(void) {
    int fd = route_socket(0), on = 1;
    if (setsockopt(fd, SOL_NETLINK_, NETLINK_GET_STRICT_CHK_, &on, sizeof on) < 0)
        printf("%s: strict=%d\n", side, -errno);
    return fd;
}

/* B: makes its namespace, then does what A writes to `in`, one letter at
   a time, writing back to `out` when done. */
static void child(int in, int out) {
    side = "B";
    if (unshare(CLONE_NEWNET) < 0) printf("B: unshare=%d\n", -errno);
    int ctl = strict_socket(), mon = route_socket(IPV4_GROUPS), links = route_socket(1);
    fflush(stdout);
    if (write(out, "r", 1) != 1) _exit(2);
    for (char command; read(in, &command, 1) == 1;) {
        if (command == 'p') {
            heard(mon, "heard");
            dumps(ctl, 0, 0, "dump");
        } else if (command == 'a') {
            address(ctl, RTM_NEWADDR, B_INDEX, "10.77.0.2", 24, NULL, "add 10.77.0.2/24");
            heard(mon, "heard");
        } else if (command == 'u') {
            set_up(ctl, B_INDEX, 1, "up vb");
            carrier(links, B_INDEX, 1);
            heard(mon, "heard");
            dumps(ctl, 0, 0, "dump up");
        } else if (command == 'c') {
            carrier(links, B_INDEX, 0);
            heard(mon, "heard");
            dumps(ctl, 0, 0, "dump without carrier");
        } else if (command == 'C') {
            carrier(links, B_INDEX, 1);
            heard(mon, "heard");
            dumps(ctl, 0, 0, "dump with carrier");
        } else if (command == 'x') {
            fflush(stdout);
            _exit(0);
        }
        fflush(stdout);
        if (write(out, "d", 1) != 1) _exit(2);
    }
    _exit(0);
}

int main(int argc, char **argv) {
    if (argc < 2 || strcmp(argv[1], "veth-ipv4")) return 99;
    setvbuf(stdout, NULL, _IOLBF, 0);
    int to_b[2], to_a[2];
    if (pipe(to_b) < 0 || pipe(to_a) < 0) return 98;
    fflush(stdout);
    pid_t b = fork();
    if (b == 0) {
        close(to_b[1]), close(to_a[0]);
        child(to_b[0], to_a[1]);
    }
    close(to_b[0]), close(to_a[1]);
    char ready;
    if (read(to_a[0], &ready, 1) != 1) return 97;
    /* Has B do `command` and waits until it has. */
#define B_DOES(command)                                                       \
    do {                                                                      \
        fflush(stdout);                                                       \
        if (write(to_b[1], command, 1) != 1 || read(to_a[0], &ready, 1) != 1) \
            printf("A: B gone\n");                                            \
    } while (0)
    printf("A: unshare=%ld\n", result(unshare(CLONE_NEWNET)));
    int ctl = strict_socket(), mon = route_socket(IPV4_GROUPS), links = route_socket(1);
    /* The pair, with its ends' names, indices and Ethernet addresses. */
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
    put32(&m, IFLA_NET_NS_PID, (unsigned)b);
    end(&m, peer);
    end(&m, data);
    end(&m, link);
    request(ctl, RTM_NEWLINK, NLM_F_CREATE | NLM_F_EXCL, &m, "make");
    /* Addresses on va, down: each has its local route alone. One names
       its broadcast address; 10.77.0.9 is in its subnet, so secondary. */
    address(ctl, RTM_NEWADDR, A_INDEX, "10.77.0.1", 24, "10.77.0.255", "add 10.77.0.1/24");
    heard(mon, "heard");
    address(ctl, RTM_NEWADDR, A_INDEX, "10.77.0.9", 24, NULL, "add 10.77.0.9/24");
    heard(mon, "heard");
    address(ctl, RTM_NEWADDR, A_INDEX, "10.66.0.1", 32, NULL, "add 10.66.0.1/32");
    heard(mon, "heard");
    address(ctl, RTM_NEWADDR, A_INDEX, "10.77.0.1", 24, NULL, "add 10.77.0.1/24 again");
    address(ctl, RTM_NEWADDR, B_INDEX, "10.77.0.3", 24, NULL, "add on 1001, in B");
    dumps(ctl, 0, 0, "dump down");
    dumps(ctl, A_INDEX, A_INDEX, "dump of va");
    dumps(ctl, 1, 1, "dump of lo");
    dumps(ctl, B_INDEX, 0, "dump of 1001");
    /* A route through va while it is down. */
    route(ctl, RTM_NEWROUTE, "10.88.0.0", 16, A_INDEX, 253, "route through va down");
    /* va up, vb down: no carrier, so its routes are RTNH_F_LINKDOWN. */
    set_up(ctl, A_INDEX, 1, "up va");
    heard(mon, "heard");
    dumps(ctl, 0, 0, "dump up");
    lookup(ctl, "10.77.0.2", NULL, 0, 0, "get 10.77.0.2");
    lookup(ctl, "10.77.0.2", NULL, 0, RTM_F_FIB_MATCH, "get 10.77.0.2 fib match");
    lookup(ctl, "10.77.0.255", NULL, 0, 0, "get 10.77.0.255");
    lookup(ctl, "10.77.0.9", NULL, 0, 0, "get 10.77.0.9");
    lookup(ctl, "10.66.0.1", NULL, 0, 0, "get 10.66.0.1");
    lookup(ctl, "10.55.0.1", NULL, 0, 0, "get 10.55.0.1");
    lookup(ctl, "10.55.0.1", NULL, A_INDEX, 0, "get 10.55.0.1 through va");
    lookup(ctl, "224.0.0.1", NULL, A_INDEX, 0, "get 224.0.0.1 through va");
    lookup(ctl, "10.77.0.2", "10.77.0.9", A_INDEX, 0, "get 10.77.0.2 from 10.77.0.9 through va");
    lookup(ctl, "10.77.0.2", NULL, 1, 0, "get 10.77.0.2 through lo");
    route(ctl, RTM_NEWROUTE, "10.88.0.0", 16, A_INDEX, 253, "route through va");
    heard(mon, "heard");
    route(ctl, RTM_NEWROUTE, "10.89.0.0", 16, A_INDEX + 5, 253, "route through 1005");
    route(ctl, RTM_NEWROUTE, "10.89.0.0", 16, 0, 253, "route through none");
    lookup(ctl, "10.88.1.1", NULL, 0, 0, "get 10.88.1.1");
    /* B's end up: both have their carrier. */
    B_DOES("a");
    B_DOES("u");
    carrier(links, A_INDEX, 1);
    heard(mon, "heard");
    dumps(ctl, 0, A_INDEX, "dump with carrier");
    route(ctl, RTM_DELROUTE, "10.88.0.0", 16, A_INDEX, 253, "delete route through va");
    heard(mon, "heard");
    /* The secondary, then the /32. */
    address(ctl, RTM_DELADDR, A_INDEX, "10.77.0.9", 24, NULL, "delete 10.77.0.9/24");
    heard(mon, "heard");
    address(ctl, RTM_DELADDR, A_INDEX, "10.66.0.1", 32, NULL, "delete 10.66.0.1/32");
    heard(mon, "heard");
    address(ctl, RTM_DELADDR, A_INDEX, "10.66.0.1", 32, NULL, "delete 10.66.0.1/32 again");
    /* va down: its routes but the local one go without a word, and vb
       loses its carrier. */
    set_up(ctl, A_INDEX, 0, "down va");
    heard(mon, "heard");
    dumps(ctl, 0, 0, "dump down again");
    B_DOES("c");
    /* Up again: its routes come back; vb has its carrier again. */
    set_up(ctl, A_INDEX, 1, "up va again");
    heard(mon, "heard");
    B_DOES("C");
    dumps(ctl, 0, 0, "dump up again");
    /* Deleting va takes vb, each with its addresses. */
    m = (struct body){0};
    info(&m, A_INDEX, 0, 0);
    request(ctl, RTM_DELLINK, 0, &m, "delete va");
    heard(mon, "heard");
    dumps(ctl, 0, 0, "dump deleted");
    B_DOES("p");
    fflush(stdout);
    if (write(to_b[1], "x", 1) != 1) printf("A: B gone\n");
    int status = 0;
    waitpid(b, &status, 0);
    printf("A: B exited=%d\n", WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    return 0;
}
