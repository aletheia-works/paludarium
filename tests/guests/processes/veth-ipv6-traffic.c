/* IPv6 across a veth pair, and its neighbours (so as root): a child, B,
   makes a network namespace of its own and waits; the parent, A, makes
   another and a pair, its end "va" (1000, 02:00:00:00:00:0a) in A and
   "vb" (1001, 02:00:00:00:00:0b) in B. Each end checks no address for
   duplicates (accept_dad 0) and has 2001:db8::1/64 or 2001:db8::2/64,
   IFA_F_NODAD. A UDP datagram to B is answered: va's neighbour of
   2001:db8::2 is resolved by neighbour discovery, its solicitation going
   to that address's solicited-node group, and B learns va's address from
   it, delaying at once as its advertisement goes out through it. Then
   TCP connects and talks, a closed port refuses, a connected UDP socket
   learns of a port unreachable, a datagram over 65527 bytes is EMSGSIZE,
   a group takes UDP but not TCP (ENETUNREACH), and what leaves from ::1
   goes out and is dropped. Neighbours of an end are added, asked for,
   used and removed by requests; an end without IPv6 (an MTU of 1000)
   makes none (EINVAL). va going down takes its neighbours, IPv4's first,
   and vb losing its carrier all but the permanent ones. Last, an address
   of the subnet nobody has gives EHOSTUNREACH once neighbour discovery
   gives up, about 3 s later, to a blocking connect and to a nonblocking
   one. Connected UDP sockets show the sources groups of each scope
   take, before and after a site-local address comes (EINVAL for the
   node's and the link's, as for a link-local peer, without a scope ID),
   and the newer of two addresses of a subnet winning their tie. The two processes take turns through pipes, so their lines come
   in one order. What Linux does in its work queue or link watch (an
   address done, a carrier) and the advertisement that resolves a
   datagram's neighbour are waited for on netlink. Neighbours are dumped
   sorted, as Linux dumps them in the order of a randomly keyed hash;
   the ones of ff02::2 and ff02::16, which router solicitation and MLD
   make, and those of link-local addresses, which a probe 5 s after
   neighbour discovery makes, are not shown. */
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
#define RTM_NEWNEIGH 28
#define RTM_DELNEIGH 29
#define RTM_GETNEIGH 30
#define RTM_GETNEIGHTBL 66
#define NDTA_PARMS 6
#define NDTPA_IFINDEX 1
#define NLM_F_REQUEST 1
#define NLM_F_ACK 4
#define NLM_F_DUMP 0x300
#define NLM_F_EXCL 0x200
#define NLM_F_CREATE 0x400
#define IFLA_ADDRESS 1
#define IFLA_IFNAME 3
#define IFLA_MTU 4
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
#define NDA_DST 1
#define NDA_LLADDR 2
#define NDA_PROBES 4
#define NDA_IFINDEX 8
#define NTF_USE 0x01
#define NUD_REACHABLE 0x02
#define NUD_FAILED 0x20
#define NUD_PERMANENT 0x80
#define A_INDEX 1000
#define B_INDEX 1001
#define C_INDEX 1002
#define D_INDEX 1003

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
struct ndmsg_ {
    unsigned char family, pad1;
    unsigned short pad2;
    int index;
    unsigned short state;
    unsigned char flags, type;
};
struct body {
    unsigned char bytes[1024];
    size_t len;
};

static const char *side = "A";
static unsigned seq;
/* RTNLGRP_LINK and RTNLGRP_IPV6_ROUTE, and RTNLGRP_NEIGH, what is waited
   for; and RTNLGRP_NEIGH, what is shown. */
static int events = -1, resolved = -1, neighbours = -1;

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
static void set_link(int fd, int index, int up, const char *label) {
    struct body b = {0};
    info(&b, index, up ? IFF_UP : 0, IFF_UP);
    request(fd, RTM_NEWLINK, 0, &b, label);
}
static void sysctl(const char *path, const char *value) {
    int fd = open(path, O_WRONLY);
    long r = result(fd < 0 ? fd : write(fd, value, strlen(value)));
    printf("%s: %s=%ld\n", side, path, r);
    if (fd >= 0) close(fd);
}
static void drain(int fd) {
    static unsigned char buf[65536];
    while (recv(fd, buf, sizeof buf, MSG_DONTWAIT) > 0) {
    }
}
static unsigned char wanted[16];
/* Whether `h` is what is waited for: the local route of `wanted` (an
   address done), the RTM_NEWLINK of the device of `index` with its
   carrier `carrier`, or the neighbour `wanted` in the state `state`. */
static int is(const struct nl_header *h, int index, int carrier, int state) {
    const unsigned char *body = (const unsigned char *)(h + 1);
    int len = (int)(h->len - sizeof *h);
    int start;
    if (state) {
        struct ndmsg_ n;
        if (h->type != RTM_NEWNEIGH || len < (int)sizeof n) return 0;
        memcpy(&n, body, sizeof n);
        if (n.family != AF_INET6 || n.state != state) return 0;
        start = (int)sizeof n;
    } else if (index) {
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
        if (!index && kind == 1 && alen == 20) return !memcmp(body + a + 4, wanted, 16);
        if (index && (kind & 0x3fff) == IFLA_CARRIER && alen >= 5) return body[a + 4] == carrier;
        a += (alen + 3) & ~3;
    }
    return 0;
}
/* Waits, up to 5 s however much else comes, on `fd` for what `is` says. */
static void wait_for(int fd, const char *ip, int index, int carrier, int state, const char *label) {
    static unsigned char buf[65536];
    memset(wanted, 0, sizeof wanted);
    if (ip) inet_pton(AF_INET6, ip, wanted);
    struct timespec start, now;
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (;;) {
        clock_gettime(CLOCK_MONOTONIC, &now);
        long left = 5000 - ((now.tv_sec - start.tv_sec) * 1000 + (now.tv_nsec - start.tv_nsec) / 1000000);
        if (left <= 0) break;
        struct pollfd ready = {.fd = fd, .events = POLLIN};
        if (poll(&ready, 1, (int)(left < 1000 ? left : 1000)) <= 0) continue;
        long n;
        while ((n = recv(fd, buf, sizeof buf, MSG_DONTWAIT)) > 0)
            for (long at = 0; at + (long)sizeof(struct nl_header) <= n;) {
                const struct nl_header *h = (const void *)(buf + at);
                if (h->len < sizeof *h || at + h->len > n) break;
                if (is(h, index, carrier, state)) return;
                at += (h->len + 3) & ~3u;
            }
    }
    printf("%s: %s: never came\n", side, label);
}
static void address6(int fd, int index, const char *ip, const char *label) {
    struct body b = {0};
    const unsigned char m[8] = {AF_INET6, 64, IFA_F_NODAD, 0, (unsigned char)index, (unsigned char)(index >> 8), 0, 0};
    unsigned char in[16];
    inet_pton(AF_INET6, ip, in);
    raw(&b, m, sizeof m);
    put(&b, IFA_LOCAL, in, 16);
    put32(&b, IFA_FLAGS, IFA_F_NODAD);
    drain(events);
    if (request(fd, RTM_NEWADDR, NLM_F_CREATE | NLM_F_EXCL, &b, label) == 0)
        wait_for(events, ip, 0, 0, 0, label);
}

/* Whether a neighbour's key is shown: not a link-local address, ff02::2
   or ff02::16. */
static int shown(const unsigned char *ip, int family) {
    if (family != AF_INET6) return 1;
    if (ip[0] == 0xfe && (ip[1] & 0xc0) == 0x80) return 0;
    static const unsigned char routers[16] = {0xff, 2, [15] = 2}, reports[16] = {0xff, 2, [15] = 0x16};
    return memcmp(ip, routers, 16) && memcmp(ip, reports, 16);
}
/* Describes a neighbour message: device, key, state, flags, type,
   link-layer address (or -) and probes; 0 for one not shown. */
static int describe(const unsigned char *body, int len, char *line, size_t size) {
    struct ndmsg_ n;
    memcpy(&n, body, sizeof n);
    char ip[64] = "?", ll[32] = "-";
    unsigned probes = 0;
    int show = 1;
    for (int a = (int)sizeof n; a + 4 <= len;) {
        unsigned short alen, kind;
        memcpy(&alen, body + a, 2);
        memcpy(&kind, body + a + 2, 2);
        if (alen < 4 || a + alen > len) break;
        const unsigned char *v = body + a + 4;
        if (kind == NDA_DST && (alen == 8 || alen == 20)) {
            inet_ntop(alen == 8 ? AF_INET : AF_INET6, v, ip, sizeof ip);
            show = shown(v, alen == 8 ? AF_INET : AF_INET6);
        }
        if (kind == NDA_LLADDR && alen == 10)
            snprintf(ll, sizeof ll, "%02x:%02x:%02x:%02x:%02x:%02x", v[0], v[1], v[2], v[3], v[4], v[5]);
        if (kind == NDA_PROBES && alen == 8) memcpy(&probes, v, 4);
        a += (alen + 3) & ~3;
    }
    snprintf(line, size, "dev=%d %s state=0x%x flags=0x%x type=%u lladdr=%s probes=%u", n.index, ip, n.state, n.flags,
             n.type, ll, probes);
    return show;
}
/* Dumps the neighbours of the device of `index`, of `family` (0 for
   both), sorted. */
static void dump(int fd, int family, int index, const char *label) {
    static unsigned char buf[65536];
    struct {
        struct nl_header h;
        struct ndmsg_ n;
        unsigned short alen, kind;
        unsigned value;
    } ask = {{sizeof ask, RTM_GETNEIGH, NLM_F_REQUEST | NLM_F_DUMP, ++seq, 0},
             {.family = (unsigned char)family},
             8,
             NDA_IFINDEX,
             (unsigned)index};
    struct nl_address kernel = {.family = AF_NETLINK};
    sendto(fd, &ask, sizeof ask, 0, (void *)&kernel, sizeof kernel);
    static char lines[64][160];
    int count = 0;
    for (;;) {
        struct pollfd ready = {.fd = fd, .events = POLLIN};
        if (poll(&ready, 1, 2000) <= 0) break;
        long n = recv(fd, buf, sizeof buf, 0);
        if (n <= 0) break;
        for (long at = 0; at + (long)sizeof(struct nl_header) <= n;) {
            const struct nl_header *h = (const void *)(buf + at);
            if (h->len < sizeof *h || at + h->len > n) break;
            if (h->type == 3) {
                qsort(lines, (size_t)count, sizeof lines[0], (int (*)(const void *, const void *))strcmp);
                for (int i = 0; i < count; i++) printf("%s: %s: %s\n", side, label, lines[i]);
                printf("%s: %s: %d\n", side, label, count);
                return;
            }
            if (h->type == 2) {
                int error;
                memcpy(&error, h + 1, 4);
                printf("%s: %s: error=%d\n", side, label, error);
                return;
            }
            if (h->type == RTM_NEWNEIGH && count < 64 &&
                describe((const unsigned char *)(h + 1), (int)(h->len - sizeof *h), lines[count], sizeof lines[0]))
                count++;
            at += (h->len + 3) & ~3u;
        }
    }
    printf("%s: %s: no end\n", side, label);
}
/* Prints what the member `neighbours` heard since, in its order. */
static void heard(const char *label) {
    static unsigned char buf[65536];
    for (;;) {
        long n = recv(neighbours, buf, sizeof buf, MSG_DONTWAIT);
        if (n <= 0) return;
        for (long at = 0; at + (long)sizeof(struct nl_header) <= n;) {
            const struct nl_header *h = (const void *)(buf + at);
            if (h->len < sizeof *h || at + h->len > n) break;
            char line[160];
            if ((h->type == RTM_NEWNEIGH || h->type == RTM_DELNEIGH) &&
                describe((const unsigned char *)(h + 1), (int)(h->len - sizeof *h), line, sizeof line))
                printf("%s: %s: %s %s\n", side, label, h->type == RTM_NEWNEIGH ? "new" : "del", line);
            at += (h->len + 3) & ~3u;
        }
    }
}
/* Asks for, adds or removes the neighbour `ip` (IPv6, or IPv4 with
   `v4`) of the device of `index`, with `state`, `flags` and the
   link-layer address 02:00:00:00:00:`last` (none for 0). */
static void neighbour(int fd, unsigned short type, unsigned short request_flags, int v4, int index, const char *ip,
                      unsigned short state, unsigned char flags, int last, const char *label) {
    struct body b = {0};
    struct ndmsg_ n = {
        .family = (unsigned char)(v4 ? AF_INET : AF_INET6), .index = index, .state = state, .flags = flags};
    unsigned char in[16];
    inet_pton(v4 ? AF_INET : AF_INET6, ip, in);
    raw(&b, &n, sizeof n);
    put(&b, NDA_DST, in, v4 ? 4 : 16);
    if (last) {
        const unsigned char ll[6] = {2, 0, 0, 0, 0, (unsigned char)last};
        put(&b, NDA_LLADDR, ll, 6);
    }
    if (type != RTM_GETNEIGH) {
        request(fd, type, request_flags, &b, label);
        return;
    }
    unsigned char buf[4096] = {0};
    struct nl_header *h = (void *)buf;
    h->len = sizeof *h + b.len;
    h->type = RTM_GETNEIGH;
    h->flags = NLM_F_REQUEST;
    h->seq = ++seq;
    memcpy(buf + sizeof *h, b.bytes, b.len);
    struct nl_address kernel = {.family = AF_NETLINK};
    sendto(fd, buf, h->len, 0, (void *)&kernel, sizeof kernel);
    struct pollfd ready = {.fd = fd, .events = POLLIN};
    if (poll(&ready, 1, 2000) <= 0 || recv(fd, buf, sizeof buf, 0) < (long)sizeof *h + 4) {
        printf("%s: %s: no answer\n", side, label);
    } else if (h->type == 2) {
        int error;
        memcpy(&error, buf + sizeof *h, 4);
        printf("%s: %s: error=%d\n", side, label, error);
    } else {
        char line[160];
        describe(buf + sizeof *h, (int)(h->len - sizeof *h), line, sizeof line);
        printf("%s: %s: %s\n", side, label, line);
    }
}

/* Dumps neighbour discovery's table: the devices that have parameters,
   the newest first, after the table's own (0). */
static void tables(int fd, const char *label) {
    static unsigned char buf[65536];
    struct {
        struct nl_header h;
        unsigned char family, pad[3];
    } ask = {{sizeof ask, RTM_GETNEIGHTBL, NLM_F_REQUEST | NLM_F_DUMP, ++seq, 0}, AF_INET6, {0}};
    struct nl_address kernel = {.family = AF_NETLINK};
    sendto(fd, &ask, sizeof ask, 0, (void *)&kernel, sizeof kernel);
    for (;;) {
        struct pollfd ready = {.fd = fd, .events = POLLIN};
        if (poll(&ready, 1, 2000) <= 0) break;
        long n = recv(fd, buf, sizeof buf, 0);
        if (n <= 0) break;
        for (long at = 0; at + (long)sizeof(struct nl_header) <= n;) {
            const struct nl_header *h = (const void *)(buf + at);
            if (h->len < sizeof *h || at + h->len > n) break;
            if (h->type == 3 || h->type == 2) return;
            const unsigned char *body = (const unsigned char *)(h + 1);
            int len = (int)(h->len - sizeof *h);
            for (int a = 4; a + 4 <= len;) {
                unsigned short alen, kind;
                memcpy(&alen, body + a, 2);
                memcpy(&kind, body + a + 2, 2);
                if (alen < 4 || a + alen > len) break;
                if ((kind & 0x3fff) == NDTA_PARMS) {
                    int index = 0;
                    for (int p = a + 4; p + 4 <= a + alen;) {
                        unsigned short plen, pkind;
                        memcpy(&plen, body + p, 2);
                        memcpy(&pkind, body + p + 2, 2);
                        if (plen < 4 || p + plen > a + alen) break;
                        if (pkind == NDTPA_IFINDEX) memcpy(&index, body + p + 4, 4);
                        p += (plen + 3) & ~3;
                    }
                    printf("%s: %s: dev=%d\n", side, label, index);
                }
                a += (alen + 3) & ~3;
            }
            at += (h->len + 3) & ~3u;
        }
    }
    printf("%s: %s: no end\n", side, label);
}

static struct sockaddr_in6 at(const char *ip, int port) {
    struct sockaddr_in6 a = {.sin6_family = AF_INET6, .sin6_port = htons((unsigned short)port)};
    inet_pton(AF_INET6, ip, &a.sin6_addr);
    return a;
}
/* The address of a socket's end, without its port where `port` is 0. */
static void show_name(int fd, int peer, int port, const char *label) {
    struct sockaddr_in6 a = {0};
    socklen_t len = sizeof a;
    long r = result(peer ? getpeername(fd, (void *)&a, &len) : getsockname(fd, (void *)&a, &len));
    char ip[64] = "?";
    inet_ntop(AF_INET6, &a.sin6_addr, ip, sizeof ip);
    if (port)
        printf("%s: %s=%ld %s:%u\n", side, label, r, ip, ntohs(a.sin6_port));
    else
        printf("%s: %s=%ld %s\n", side, label, r, ip);
}
static double seconds(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec + (double)t.tv_nsec / 1e9;
}
/* How long something took, in whole seconds, between 2 and 5 or not. */
static const char *about_three(double took) { return took >= 2.0 && took < 5.0 ? "about 3 s" : "not 3 s"; }
static void receive(int fd, const char *label) {
    char buf[64] = {0};
    struct pollfd ready = {.fd = fd, .events = POLLIN};
    if (poll(&ready, 1, 2000) <= 0) {
        printf("%s: %s: nothing\n", side, label);
        return;
    }
    struct sockaddr_in6 from = {0};
    socklen_t len = sizeof from;
    long n = result(recvfrom(fd, buf, sizeof buf - 1, 0, (void *)&from, &len));
    char ip[64] = "-";
    if (from.sin6_family == AF_INET6) inet_ntop(AF_INET6, &from.sin6_addr, ip, sizeof ip);
    printf("%s: %s=%ld \"%s\" from %s\n", side, label, n, n > 0 ? buf : "", ip);
}
/* Brings the end of `index` up with `ip`, both loopbacks being up, and
   waits for its carrier and its link-local address `ll`. */
static void end_up(int ctl, int index, const char *ip, const char *ll) {
    drain(events);
    set_link(ctl, index, 1, "up the end");
    wait_for(events, NULL, index, 1, 0, "the carrier");
    wait_for(events, ll, 0, 0, 0, "the link-local address");
    address6(ctl, index, ip, "add its address");
}

/* B: makes its namespace, then does what A writes to `in`, one letter at
   a time, writing back to `out` when done. */
static void child(int in, int out) {
    side = "B";
    if (unshare(CLONE_NEWNET) < 0) printf("B: unshare=%d\n", -errno);
    int ctl = route_socket(0);
    events = route_socket(1 | 0x400);
    neighbours = route_socket(4);
    int listener = -1, conn = -1, udp = -1;
    fflush(stdout);
    if (write(out, "r", 1) != 1) _exit(2);
    for (char command; read(in, &command, 1) == 1;) {
        if (command == 'u') {
            sysctl("/proc/sys/net/ipv6/conf/vb/accept_dad", "0");
            set_link(ctl, 1, 1, "up lo");
            /* Its carrier comes with va's, which A waits for. */
            drain(events);
            set_link(ctl, B_INDEX, 1, "up the end");
            address6(ctl, B_INDEX, "2001:db8::2", "add its address");
            listener = socket(AF_INET6, SOCK_STREAM, 0);
            struct sockaddr_in6 any = at("::", 5000);
            printf("B: bind=%ld\n", result(bind(listener, (void *)&any, sizeof any)));
            printf("B: listen=%ld\n", result(listen(listener, 4)));
            udp = socket(AF_INET6, SOCK_DGRAM, 0);
            any = at("::", 6000);
            printf("B: bind udp=%ld\n", result(bind(udp, (void *)&any, sizeof any)));
            heard("heard");
        } else if (command == 'd') {
            receive(udp, "udp recvfrom");
            struct sockaddr_in6 back = at("2001:db8::1", 6100);
            printf("B: udp reply=%ld\n", result(sendto(udp, "back", 4, 0, (void *)&back, sizeof back)));
        } else if (command == 'm') {
            dump(ctl, AF_INET6, B_INDEX, "neighbours");
            heard("heard");
        } else if (command == 'a') {
            conn = (int)result(accept(listener, NULL, NULL));
            printf("B: accept=%d\n", conn >= 0 ? 0 : conn);
            show_name(conn, 0, 1, "accepted at");
            show_name(conn, 1, 0, "accepted from");
            char buf[16] = {0};
            printf("B: read=%ld \"%s\"\n", result(read(conn, buf, sizeof buf - 1)), buf);
            printf("B: write=%ld\n", result(write(conn, "pong", 4)));
        } else if (command == 'c') {
            printf("B: read at end=%ld\n", result(read(conn, (char[4]){0}, 4)));
            close(conn);
        } else if (command == 'n') {
            /* Nothing more came. */
            int none = (int)result(recv(udp, (char[8]){0}, 8, MSG_DONTWAIT));
            printf("B: udp nothing more=%d\n", none);
        } else if (command == 'v') {
            neighbour(ctl, RTM_NEWNEIGH, NLM_F_CREATE, 1, B_INDEX, "10.77.0.8", NUD_REACHABLE, 0, 8,
                      "add IPv4's 10.77.0.8");
            neighbour(ctl, RTM_NEWNEIGH, NLM_F_CREATE, 0, B_INDEX, "2001:db8::9", NUD_PERMANENT, 0, 9,
                      "add 2001:db8::9 permanent");
            heard("heard");
            drain(events);
        } else if (command == 'l') {
            /* vb loses its carrier: its neighbours go first. */
            wait_for(events, NULL, B_INDEX, 0, 0, "vb's carrier gone");
            heard("heard");
            dump(ctl, 0, B_INDEX, "neighbours left");
        } else if (command == 'x') {
            fflush(stdout);
            _exit(0);
        }
        fflush(stdout);
        if (write(out, "d", 1) != 1) _exit(2);
    }
    _exit(0);
}

static void make_pair(int ctl, int a, const char *an, int b, const char *bn, int ns, unsigned mtu) {
    struct body m = {0};
    const unsigned char mac_a[6] = {2, 0, 0, 0, 0, (unsigned char)(a - A_INDEX + 0x0a)},
                        mac_b[6] = {2, 0, 0, 0, 0, (unsigned char)(b - A_INDEX + 0x0a)};
    info(&m, a, 0, 0);
    put(&m, IFLA_IFNAME, an, strlen(an) + 1);
    put(&m, IFLA_ADDRESS, mac_a, 6);
    if (mtu) put32(&m, IFLA_MTU, mtu);
    size_t link = begin(&m, IFLA_LINKINFO);
    put(&m, IFLA_INFO_KIND, "veth", 5);
    size_t data = begin(&m, IFLA_INFO_DATA);
    size_t peer = begin(&m, VETH_INFO_PEER);
    info(&m, b, 0, 0);
    put(&m, IFLA_IFNAME, bn, strlen(bn) + 1);
    put(&m, IFLA_ADDRESS, mac_b, 6);
    if (mtu) put32(&m, IFLA_MTU, mtu);
    if (ns) put32(&m, IFLA_NET_NS_PID, (unsigned)ns);
    end(&m, peer);
    end(&m, data);
    end(&m, link);
    request(ctl, RTM_NEWLINK, NLM_F_CREATE | NLM_F_EXCL, &m, "make a pair");
}

int main(int argc, char **argv) {
    if (argc < 2 || strcmp(argv[1], "veth-ipv6-traffic")) return 99;
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
#define B_DOES(command)                                                       \
    do {                                                                      \
        fflush(stdout);                                                       \
        if (write(to_b[1], command, 1) != 1 || read(to_a[0], &ready, 1) != 1) \
            printf("A: B gone\n");                                            \
    } while (0)
    printf("A: unshare=%ld\n", result(unshare(CLONE_NEWNET)));
    int ctl = route_socket(0);
    events = route_socket(1 | 0x400);
    resolved = route_socket(4);
    neighbours = route_socket(4);
    make_pair(ctl, A_INDEX, "va", B_INDEX, "vb", b, 0);
    sysctl("/proc/sys/net/ipv6/conf/va/accept_dad", "0");
    set_link(ctl, 1, 1, "up lo");
    B_DOES("u");
    end_up(ctl, A_INDEX, "2001:db8::1", "fe80::ff:fe00:a");

    /* A datagram to B, and its answer: neighbour discovery first. */
    int u = socket(AF_INET6, SOCK_DGRAM, 0);
    struct sockaddr_in6 mine = at("::", 6100);
    printf("A: bind udp=%ld\n", result(bind(u, (void *)&mine, sizeof mine)));
    struct sockaddr_in6 to = at("2001:db8::2", 6000);
    drain(resolved);
    printf("A: udp sendto=%ld\n", result(sendto(u, "hello", 5, 0, (void *)&to, sizeof to)));
    wait_for(resolved, "2001:db8::2", 0, 0, NUD_REACHABLE, "2001:db8::2 reachable");
    heard("heard");
    B_DOES("d");
    receive(u, "udp recvfrom");
    dump(ctl, AF_INET6, A_INDEX, "neighbours");
    B_DOES("m");

    /* A connection to B's listener, and a few bytes each way. */
    int c = socket(AF_INET6, SOCK_STREAM, 0);
    to = at("2001:db8::2", 5000);
    printf("A: connect=%ld\n", result(connect(c, (void *)&to, sizeof to)));
    show_name(c, 0, 0, "connected from");
    show_name(c, 1, 1, "connected to");
    printf("A: write=%ld\n", result(write(c, "ping", 4)));
    B_DOES("a");
    char buf[16] = {0};
    printf("A: read=%ld \"%s\"\n", result(read(c, buf, sizeof buf - 1)), buf);
    close(c);
    B_DOES("c");
    /* A port nobody listens on: B answers with a reset. */
    c = socket(AF_INET6, SOCK_STREAM, 0);
    to = at("2001:db8::2", 5001);
    printf("A: connect to a closed port=%ld\n", result(connect(c, (void *)&to, sizeof to)));
    close(c);

    /* Connected to a port nobody has: the port unreachable comes back. */
    int cu = socket(AF_INET6, SOCK_DGRAM, 0);
    to = at("2001:db8::2", 6001);
    printf("A: udp connect=%ld\n", result(connect(cu, (void *)&to, sizeof to)));
    show_name(cu, 0, 0, "udp connected from");
    printf("A: udp send=%ld\n", result(send(cu, "x", 1, 0)));
    struct pollfd p = {.fd = cu, .events = POLLIN};
    printf("A: poll=%d\n", poll(&p, 1, 2000));
    printf("A: revents=%#x\n", p.revents);
    printf("A: udp send again=%ld\n", result(send(cu, "x", 1, 0)));
    close(cu);
    /* What a datagram holds: 65535 bytes less IPv6's UDP header. */
    static char big[65536];
    to = at("2001:db8::2", 6003);
    printf("A: udp sendto 65528 bytes=%ld\n", result(sendto(u, big, 65528, 0, (void *)&to, sizeof to)));
    printf("A: udp sendto 65527 bytes=%ld\n", result(sendto(u, big, 65527, 0, (void *)&to, sizeof to)));
    /* A group: UDP's goes, TCP's does not. Nobody listens on 6002. */
    to = at("ff02::1", 6002);
    printf("A: udp sendto ff02::1=%ld\n", result(sendto(u, "all", 3, 0, (void *)&to, sizeof to)));
    c = socket(AF_INET6, SOCK_STREAM, 0);
    to = at("ff02::1", 5000);
    printf("A: connect to ff02::1=%ld\n", result(connect(c, (void *)&to, sizeof to)));
    close(c);
    /* From ::1: it goes out, and B drops it. */
    int lo = socket(AF_INET6, SOCK_DGRAM, 0);
    struct sockaddr_in6 one = at("::1", 0);
    printf("A: bind ::1=%ld\n", result(bind(lo, (void *)&one, sizeof one)));
    to = at("2001:db8::2", 6000);
    printf("A: udp sendto from ::1=%ld\n", result(sendto(lo, "one", 3, 0, (void *)&to, sizeof to)));
    close(lo);
    c = socket(AF_INET6, SOCK_STREAM | SOCK_NONBLOCK, 0);
    printf("A: bind ::1=%ld\n", result(bind(c, (void *)&one, sizeof one)));
    to = at("2001:db8::2", 5000);
    printf("A: connect from ::1=%ld\n", result(connect(c, (void *)&to, sizeof to)));
    close(c);
    B_DOES("n");
    dump(ctl, AF_INET6, A_INDEX, "neighbours");
    heard("heard");

    /* Neighbours a request adds, asks for, uses and removes. */
    neighbour(ctl, RTM_NEWNEIGH, NLM_F_CREATE | NLM_F_EXCL, 0, A_INDEX, "2001:db8::5", NUD_PERMANENT, 0, 5,
              "add 2001:db8::5 permanent");
    neighbour(ctl, RTM_GETNEIGH, 0, 0, A_INDEX, "2001:db8::5", 0, 0, 0, "get 2001:db8::5");
    neighbour(ctl, RTM_GETNEIGH, 0, 0, A_INDEX, "2001:db8::2", 0, 0, 0, "get 2001:db8::2");
    neighbour(ctl, RTM_GETNEIGH, 0, 0, A_INDEX, "2001:db8::8", 0, 0, 0, "get 2001:db8::8");
    drain(resolved);
    neighbour(ctl, RTM_NEWNEIGH, NLM_F_CREATE, 0, A_INDEX, "2001:db8::6", 0, NTF_USE, 0, "use 2001:db8::6");
    neighbour(ctl, RTM_NEWNEIGH, NLM_F_CREATE, 0, A_INDEX, "2001:db8::2", 0, NTF_USE, 0, "use 2001:db8::2");
    neighbour(ctl, RTM_NEWNEIGH, NLM_F_CREATE, 0, A_INDEX, "2001:db8::7", NUD_REACHABLE, 0, 7,
              "add 2001:db8::7 reachable");
    neighbour(ctl, RTM_DELNEIGH, 0, 0, A_INDEX, "2001:db8::7", 0, 0, 0, "remove 2001:db8::7");
    neighbour(ctl, RTM_DELNEIGH, 0, 0, A_INDEX, "2001:db8::7", 0, 0, 0, "remove it again");
    neighbour(ctl, RTM_NEWNEIGH, NLM_F_CREATE, 1, A_INDEX, "10.77.0.9", NUD_PERMANENT, 0, 9,
              "add IPv4's 10.77.0.9 permanent");
    make_pair(ctl, C_INDEX, "vc", D_INDEX, "vd", 0, 1000);
    neighbour(ctl, RTM_NEWNEIGH, NLM_F_CREATE, 0, C_INDEX, "2001:db8::5", NUD_PERMANENT, 0, 5,
              "add one to vc, without IPv6");
    neighbour(ctl, RTM_NEWNEIGH, NLM_F_CREATE, 1, C_INDEX, "10.77.0.5", NUD_PERMANENT, 0, 5, "add IPv4's to vc");
    tables(ctl, "neighbour discovery's table");
    /* Nobody answers for 2001:db8::6: dumped once it has failed, its
       probes are done. */
    wait_for(resolved, "2001:db8::6", 0, 0, NUD_FAILED, "2001:db8::6 failed");
    dump(ctl, 0, A_INDEX, "neighbours");
    heard("heard");

    /* va going down takes its neighbours; vb, losing its carrier, all but
       the permanent ones. */
    B_DOES("v");
    drain(events);
    set_link(ctl, A_INDEX, 0, "down va");
    heard("heard");
    dump(ctl, 0, A_INDEX, "neighbours left");
    B_DOES("l");
    end_up(ctl, A_INDEX, "2001:db8::1", "fe80::ff:fe00:a");

    /* An address of the subnet nobody has: neighbour discovery gives
       up. */
    c = socket(AF_INET6, SOCK_STREAM, 0);
    to = at("2001:db8::3", 5000);
    double start = seconds();
    printf("A: connect to nobody=%ld\n", result(connect(c, (void *)&to, sizeof to)));
    printf("A: it took %s\n", about_three(seconds() - start));
    close(c);
    c = socket(AF_INET6, SOCK_STREAM | SOCK_NONBLOCK, 0);
    to = at("2001:db8::4", 5000);
    start = seconds();
    printf("A: nonblocking connect to nobody=%ld\n", result(connect(c, (void *)&to, sizeof to)));
    p = (struct pollfd){.fd = c, .events = POLLIN | POLLOUT};
    printf("A: poll=%d\n", poll(&p, 1, 10000));
    printf("A: revents=%#x, it took %s\n", p.revents, about_three(seconds() - start));
    int error = 0;
    socklen_t len = sizeof error;
    getsockopt(c, SOL_SOCKET, SO_ERROR, &error, &len);
    printf("A: SO_ERROR=%d\n", error);
    close(c);
    heard("heard");
    dump(ctl, AF_INET6, A_INDEX, "neighbours");
    close(u);

    /* The source a connected UDP socket takes: a group's scope is its
       scope nibble, and of two addresses that tie the newer wins. */
    const char *groups[] = {"ff00::1", "ff01::1", "ff02::1", "ff05::1", "ff0e::1"};
    for (int round = 0; round < 2; round++) {
        if (round) address6(ctl, A_INDEX, "fec0::1", "add a site-local address");
        for (size_t i = 0; i < sizeof groups / sizeof *groups; i++) {
            cu = socket(AF_INET6, SOCK_DGRAM, 0);
            to = at(groups[i], 6004);
            char label[64];
            snprintf(label, sizeof label, "udp connect to %s", groups[i]);
            printf("A: %s=%ld\n", label, result(connect(cu, (void *)&to, sizeof to)));
            show_name(cu, 0, 0, "from");
            close(cu);
        }
    }
    /* A link-local peer without a scope ID: no interface to go out of. */
    cu = socket(AF_INET6, SOCK_DGRAM, 0);
    to = at("fe80::ff:fe00:b", 6004);
    printf("A: udp connect to fe80::ff:fe00:b=%ld\n", result(connect(cu, (void *)&to, sizeof to)));
    close(cu);
    c = socket(AF_INET6, SOCK_STREAM, 0);
    to = at("fe80::ff:fe00:b", 5000);
    printf("A: connect to fe80::ff:fe00:b=%ld\n", result(connect(c, (void *)&to, sizeof to)));
    close(c);
    address6(ctl, A_INDEX, "2001:db8::11", "add a second address of the subnet");
    cu = socket(AF_INET6, SOCK_DGRAM, 0);
    to = at("2001:db8::2", 6004);
    printf("A: udp connect to 2001:db8::2=%ld\n", result(connect(cu, (void *)&to, sizeof to)));
    show_name(cu, 0, 0, "from");
    close(cu);

    fflush(stdout);
    if (write(to_b[1], "x", 1) != 1) printf("A: B gone\n");
    int status = 0;
    waitpid(b, &status, 0);
    printf("A: B exited=%d\n", WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    return 0;
}
