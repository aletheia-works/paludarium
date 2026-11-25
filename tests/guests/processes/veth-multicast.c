/* IPv4 multicast groups across two veth pairs (so as root): a child, B,
   makes a network namespace of its own and waits; the parent, A, makes
   another and the pairs, va (1000, 10.77.0.1/24) to vb (1001, 10.77.0.2/24)
   and vc (1002, 10.78.0.1/24) to vd (1003, 10.78.0.2/24), with va and vc in
   A. First the options and their errors (IP_MULTICAST_IF, IP_MULTICAST_TTL,
   IP_MULTICAST_LOOP, IP_MULTICAST_ALL, IP_ADD_MEMBERSHIP,
   IP_DROP_MEMBERSHIP), over UDP, TCP and IPv6 sockets. Then datagrams to
   groups, through a device named by its index, by an address of it, by the
   socket's own address, by its device and by a route: B's sockets get each
   that came in on a device that has joined the group, whichever socket
   joined it, unless IP_MULTICAST_ALL is off and they did not join there, or
   they are bound to another group, address or device, or are IPV6_V6ONLY; A's own
   sockets get a copy too where its device has joined, not with
   IP_MULTICAST_LOOP off, and with a time to live of 0 only they do. Through
   lo too. Leaving, closing, a device going down and one going away end
   memberships. A looked-up route is local where the device has joined.
   Last, in a namespace of no address, the ends ve (1004) and vf (1005) of a
   pair: what goes out through ve, from 0.0.0.0, comes in on vf of the same
   namespace, beside the sender's own copy, which a socket filter that keeps
   as many bytes as its packet type tells apart (PACKET_LOOPBACK is 5,
   PACKET_MULTICAST 2, PACKET_BROADCAST 1).
   For each send every socket that got it is shown, and "nobody" where none
   did. A datagram to a group has been delivered as sendto returns, as a
   broadcast, so each side looks after A has sent; the carrier is waited for
   on RTNLGRP_LINK. */
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
#define RTM_GETROUTE 26
#define RTM_DELLINK 17
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
#define VA 1000
#define VB 1001
#define VC 1002
#define VD 1003
#define VE 1004
#define VF 1005
#define SO_BINDTOIFINDEX_ 62

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
static void address(int fd, int index, const char *ip, const char *label) {
    struct body b = {0};
    struct ifaddrmsg_ a = {.family = AF_INET, .prefix = 24, .index = index};
    struct in_addr in;
    inet_pton(AF_INET, ip, &in);
    raw(&b, &a, sizeof a);
    put(&b, IFA_LOCAL, &in, 4);
    put(&b, IFA_ADDRESS, &in, 4);
    request(fd, RTM_NEWADDR, NLM_F_CREATE | NLM_F_EXCL, &b, label);
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
/* Adds the route 239.0.0.0/8 through the device of `index`. */
static void route(int ctl, int index, const char *label) {
    struct body b = {0};
    const unsigned char m[12] = {AF_INET, 8, 0, 0, 254, 4, 253, 1, 0, 0, 0, 0}, dst[4] = {239, 0, 0, 0};
    raw(&b, m, sizeof m);
    put(&b, RTA_DST, dst, 4);
    put32(&b, RTA_OIF, (unsigned)index);
    request(ctl, RTM_NEWROUTE, NLM_F_CREATE | NLM_F_EXCL, &b, label);
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

static struct sockaddr_in at(const char *ip, int port) {
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons((unsigned short)port)};
    inet_pton(AF_INET, ip, &a.sin_addr);
    return a;
}
static struct ip_mreqn mreq(const char *group, const char *address, int index) {
    struct ip_mreqn m = {.imr_ifindex = index};
    inet_pton(AF_INET, group, &m.imr_multiaddr);
    if (address) inet_pton(AF_INET, address, &m.imr_address);
    return m;
}
static long set(int fd, int name, const void *value, socklen_t len) {
    return result(setsockopt(fd, IPPROTO_IP, name, value, len));
}
static long set_int(int fd, int name, int value) { return set(fd, name, &value, sizeof value); }
static void show(const char *label, long r) { printf("%s: %s=%ld\n", side, label, r); }
static long join(int fd, const char *group, const char *address, int index) {
    struct ip_mreqn m = mreq(group, address, index);
    return set(fd, IP_ADD_MEMBERSHIP, &m, sizeof m);
}
static long leave(int fd, const char *group, const char *address, int index) {
    struct ip_mreqn m = mreq(group, address, index);
    return set(fd, IP_DROP_MEMBERSHIP, &m, sizeof m);
}
static long through(int fd, const char *address, int index) {
    struct ip_mreqn m = mreq("0.0.0.0", address, index);
    return set(fd, IP_MULTICAST_IF, &m, sizeof m);
}
static void get(int fd, int name, socklen_t len, const char *label) {
    unsigned char v[8] = {0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa};
    long r = result(getsockopt(fd, IPPROTO_IP, name, v, &len));
    printf("%s: %s: getsockopt=%ld len=%u %02x %02x %02x %02x\n", side, label, r, len, v[0], v[1], v[2], v[3]);
}
static void options(void) {
    int u = socket(AF_INET, SOCK_DGRAM, 0), t = socket(AF_INET, SOCK_STREAM, 0), six = socket(AF_INET6, SOCK_DGRAM, 0);
    unsigned char byte = 7;
    struct in_addr in = {0};
    struct ip_mreqn m;
    void *const nowhere = (void *)8;
    /* IP_MULTICAST_TTL. */
    get(u, IP_MULTICAST_TTL, 4, "ttl unset");
    show("ttl 5", set_int(u, IP_MULTICAST_TTL, 5));
    get(u, IP_MULTICAST_TTL, 4, "ttl");
    get(u, IP_MULTICAST_TTL, 2, "ttl in 2 bytes");
    get(u, IP_MULTICAST_TTL, 0, "ttl in none");
    get(u, IP_MULTICAST_TTL, 8, "ttl in 8 bytes");
    show("ttl 256", set_int(u, IP_MULTICAST_TTL, 256));
    show("ttl -2", set_int(u, IP_MULTICAST_TTL, -2));
    show("ttl -1", set_int(u, IP_MULTICAST_TTL, -1));
    get(u, IP_MULTICAST_TTL, 4, "ttl");
    show("ttl 0", set_int(u, IP_MULTICAST_TTL, 0));
    show("ttl in a byte", set(u, IP_MULTICAST_TTL, &byte, 1));
    show("ttl in 3 bytes", set(u, IP_MULTICAST_TTL, "\11\0", 3));
    get(u, IP_MULTICAST_TTL, 4, "ttl");
    show("ttl in none", set(u, IP_MULTICAST_TTL, &byte, 0));
    show("ttl from nowhere", set(u, IP_MULTICAST_TTL, nowhere, 4));
    show("ttl of TCP", set_int(t, IP_MULTICAST_TTL, 5));
    show("ttl of TCP from nowhere", set(t, IP_MULTICAST_TTL, nowhere, 4));
    get(t, IP_MULTICAST_TTL, 4, "ttl of TCP");
    show("ttl of IPv6", set_int(six, IP_MULTICAST_TTL, 9));
    get(six, IP_MULTICAST_TTL, 4, "ttl of IPv6");
    /* IP_MULTICAST_LOOP and IP_MULTICAST_ALL. */
    get(u, IP_MULTICAST_LOOP, 4, "loop unset");
    show("loop 5", set_int(u, IP_MULTICAST_LOOP, 5));
    get(u, IP_MULTICAST_LOOP, 4, "loop");
    show("loop 0", set_int(u, IP_MULTICAST_LOOP, 0));
    get(u, IP_MULTICAST_LOOP, 1, "loop in a byte");
    show("loop in none", set(u, IP_MULTICAST_LOOP, &byte, 0));
    show("loop of TCP", set_int(t, IP_MULTICAST_LOOP, 0));
    get(u, IP_MULTICAST_ALL, 4, "all unset");
    show("all 2", set_int(u, IP_MULTICAST_ALL, 2));
    show("all 0", set_int(u, IP_MULTICAST_ALL, 0));
    get(u, IP_MULTICAST_ALL, 4, "all");
    show("all in a byte", set(u, IP_MULTICAST_ALL, "\1", 1));
    show("all in none", set(u, IP_MULTICAST_ALL, &byte, 0));
    get(u, IP_MULTICAST_ALL, 4, "all");
    /* IP_MULTICAST_IF. */
    get(u, IP_MULTICAST_IF, 4, "if unset");
    show("if va by index", through(u, NULL, VA));
    get(u, IP_MULTICAST_IF, 4, "if");
    show("if vc by address", through(u, "10.78.0.1", 0));
    get(u, IP_MULTICAST_IF, 4, "if");
    get(u, IP_MULTICAST_IF, 2, "if in 2 bytes");
    get(u, IP_MULTICAST_IF, 12, "if in 12 bytes");
    show("if va by index, with another address", through(u, "10.78.0.1", VA));
    get(u, IP_MULTICAST_IF, 4, "if");
    inet_pton(AF_INET, "10.77.0.1", &in);
    show("if va in 4 bytes", set(u, IP_MULTICAST_IF, &in, sizeof in));
    get(u, IP_MULTICAST_IF, 4, "if");
    m = mreq("239.1.2.3", "10.78.0.1", 0);
    show("if vc in 8 bytes", set(u, IP_MULTICAST_IF, &m, 8));
    get(u, IP_MULTICAST_IF, 4, "if");
    show("if 127.0.0.5", through(u, "127.0.0.5", 0));
    show("if of no device", through(u, NULL, 999));
    show("if of no address", through(u, "10.99.0.1", 0));
    show("if none", through(u, NULL, 0));
    get(u, IP_MULTICAST_IF, 4, "if");
    show("if in 3 bytes", set(u, IP_MULTICAST_IF, &m, 3));
    show("if from nowhere", set(u, IP_MULTICAST_IF, nowhere, 12));
    show("if of TCP", through(t, NULL, VA));
    int device = VA;
    show("to va", result(setsockopt(u, SOL_SOCKET, SO_BINDTOIFINDEX_, &device, sizeof device)));
    show("if vc, on va", through(u, NULL, VC));
    show("if va, on va", through(u, NULL, VA));
    show("if none, on va", through(u, NULL, 0));
    /* Memberships. */
    show("join on va", join(u, "239.1.2.3", NULL, VA));
    show("join on va again", join(u, "239.1.2.3", NULL, VA));
    show("join by va's address", join(u, "239.1.2.3", "10.77.0.1", 0));
    show("join on vc", join(u, "239.1.2.3", NULL, VC));
    show("join another on va", join(u, "239.1.2.4", NULL, VA));
    show("join by no route", join(u, "239.1.2.3", NULL, 0));
    show("join on no device", join(u, "239.1.2.3", NULL, 999));
    show("join by no address", join(u, "239.1.2.3", "10.99.0.1", 0));
    show("join no group", join(u, "10.77.0.2", NULL, VA));
    m = mreq("239.1.2.5", "10.78.0.1", VA);
    show("join in 8 bytes", set(u, IP_ADD_MEMBERSHIP, &m, 8));
    show("join in 7 bytes", set(u, IP_ADD_MEMBERSHIP, &m, 7));
    show("join from nowhere", set(u, IP_ADD_MEMBERSHIP, nowhere, 12));
    show("join of TCP", join(t, "239.1.2.3", NULL, VA));
    show("join of TCP in 1 byte", set(t, IP_ADD_MEMBERSHIP, &m, 1));
    show("join of IPv6", join(six, "239.1.2.3", NULL, VA));
    show("leave on lo", leave(u, "239.1.2.3", NULL, 1));
    show("leave another group", leave(u, "239.9.9.9", NULL, VA));
    show("leave by no route", leave(u, "239.1.2.3", NULL, 0));
    show("leave on no device", leave(u, "239.1.2.3", NULL, 999));
    show("leave by no address", leave(u, "239.1.2.3", "10.99.0.1", 0));
    show("leave no group", leave(u, "10.77.0.2", NULL, VA));
    show("leave by va's address", leave(u, "239.1.2.3", "10.77.0.1", 0));
    show("leave again", leave(u, "239.1.2.3", "10.77.0.1", 0));
    show("leave of TCP", leave(t, "239.1.2.3", NULL, VA));
    show("leave in 8 bytes", set(u, IP_DROP_MEMBERSHIP, &m, 8));
    int many = socket(AF_INET, SOCK_DGRAM, 0);
    for (int i = 1; i <= 21; i++) {
        char group[32], label[32];
        snprintf(group, sizeof group, "239.2.0.%d", i);
        snprintf(label, sizeof label, "join number %d", i);
        long r = join(many, group, NULL, VA);
        if (i >= 20) show(label, r);
    }
    close(many), close(u), close(t), close(six);
    /* A TCP socket accepted. */
    int l = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = at("127.0.0.1", 7100);
    bind(l, (void *)&a, sizeof a);
    listen(l, 1);
    t = socket(AF_INET, SOCK_STREAM, 0);
    show("connect", result(connect(t, (void *)&a, sizeof a)));
    int got = accept(l, NULL, NULL);
    get(t, IP_MULTICAST_TTL, 4, "ttl of the connected");
    get(got, IP_MULTICAST_TTL, 4, "ttl of the accepted");
    get(got, IP_MULTICAST_IF, 4, "if of the accepted");
    close(got), close(t), close(l);
}

/* A UDP socket of `family` with SO_REUSEADDR on `ip` at `port`. */
static int udp(int family, const char *ip, int port) {
    int fd = socket(family, SOCK_DGRAM, 0), on = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on);
    long r;
    if (family == AF_INET6) {
        struct sockaddr_in6 a = {.sin6_family = AF_INET6, .sin6_port = htons((unsigned short)port)};
        inet_pton(AF_INET6, ip, &a.sin6_addr);
        r = result(bind(fd, (void *)&a, sizeof a));
    } else {
        struct sockaddr_in a = at(ip, port);
        r = result(bind(fd, (void *)&a, sizeof a));
    }
    if (r) printf("%s: bind %s=%ld\n", side, ip, r);
    return fd;
}
#define MOST 16
static struct {
    int fd;
    const char *label;
} sockets[MOST];
static int count;
static int watch(int fd, const char *label) {
    sockets[count].fd = fd;
    sockets[count++].label = label;
    return fd;
}
/* Shows every datagram the sockets watched have, or "nobody". */
static void look(void) {
    int any = 0;
    for (int i = 0; i < count; i++) {
        char buf[64] = {0};
        struct sockaddr_in6 from = {0};
        socklen_t len = sizeof from;
        long n;
        while (sockets[i].fd >= 0 &&
               (n = recvfrom(sockets[i].fd, buf, sizeof buf - 1, MSG_DONTWAIT, (void *)&from, &len)) >= 0) {
            char ip[64] = "-";
            if (from.sin6_family == AF_INET)
                inet_ntop(AF_INET, &((struct sockaddr_in *)&from)->sin_addr, ip, sizeof ip);
            else
                inet_ntop(AF_INET6, &from.sin6_addr, ip, sizeof ip);
            printf("%s:   %s: \"%.*s\" from %s port %u\n", side, sockets[i].label, (int)n, buf, ip,
                   ntohs(from.sin6_port));
            any = 1;
            len = sizeof from;
        }
    }
    if (!any) printf("%s:   nobody\n", side);
}
static int to_b, from_b;
/* Has B do `command`. */
static void b_does(char command) {
    char ready;
    fflush(stdout);
    if (write(to_b, &command, 1) != 1 || read(from_b, &ready, 1) != 1) printf("A: B gone\n");
}
/* Sends `what` to `group` at port 7000 from `fd`, and shows who got it. */
static void send_to(int fd, const char *group, const char *what) {
    struct sockaddr_in to = at(group, 7000);
    printf("A: \"%s\" to %s: sendto=%ld\n", what, group,
           result(sendto(fd, what, strlen(what), 0, (void *)&to, sizeof to)));
    look();
    b_does('r');
}

/* B: makes its namespace, then does what A writes to `in`, one letter at
   a time, writing back to `out` when done. */
static void child(int in, int out) {
    side = "B";
    if (unshare(CLONE_NEWNET) < 0) printf("B: unshare=%d\n", -errno);
    int ctl = route_socket(0), links = route_socket(1);
    int member = -1, on_vd = -1, device = VD, only = 1;
    fflush(stdout);
    if (write(out, "r", 1) != 1) _exit(2);
    for (char command; read(in, &command, 1) == 1;) {
        if (command == 'u') {
            set_link(ctl, 1, 1, "up lo");
            address(ctl, VB, "10.77.0.2", "add 10.77.0.2/24");
            address(ctl, VD, "10.78.0.2", "add 10.78.0.2/24");
            set_link(ctl, VB, 1, "up vb");
            set_link(ctl, VD, 1, "up vd");
            carrier(links, VB, 1);
            carrier(links, VD, 1);
        } else if (command == 's') {
            member = watch(udp(AF_INET, "0.0.0.0", 7000), "member on vb");
            show("join on vb", join(member, "239.1.2.3", NULL, VB));
            watch(udp(AF_INET, "0.0.0.0", 7000), "no member");
            int fd = watch(udp(AF_INET, "0.0.0.0", 7000), "no member, all off");
            set_int(fd, IP_MULTICAST_ALL, 0);
            watch(udp(AF_INET, "239.1.2.3", 7000), "bound to 239.1.2.3");
            watch(udp(AF_INET, "239.1.2.4", 7000), "bound to 239.1.2.4");
            on_vd = watch(udp(AF_INET, "0.0.0.0", 7000), "member on vd, all off");
            set_int(on_vd, IP_MULTICAST_ALL, 0);
            show("join on vd", join(on_vd, "239.1.2.3", "10.78.0.2", 0));
            fd = watch(udp(AF_INET6, "::", 7000), "dual-stack, all off");
            set_int(fd, IP_MULTICAST_ALL, 0);
            show("join of IPv6", join(fd, "239.1.2.3", NULL, VB));
            fd = socket(AF_INET6, SOCK_DGRAM, 0);
            setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &only, sizeof only);
            setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &only, sizeof only);
            struct sockaddr_in6 a = {.sin6_family = AF_INET6, .sin6_port = htons(7000)};
            bind(fd, (void *)&a, sizeof a);
            watch(fd, "v6only");
            fd = watch(udp(AF_INET, "0.0.0.0", 7000), "bound to vd");
            setsockopt(fd, SOL_SOCKET, SO_BINDTOIFINDEX_, &device, sizeof device);
            watch(udp(AF_INET, "10.77.0.2", 7000), "unicast");
            fd = watch(udp(AF_INET, "239.1.2.3", 7000), "connected to 10.77.0.1 7001");
            struct sockaddr_in to = at("10.77.0.1", 7001);
            show("connect", result(connect(fd, (void *)&to, sizeof to)));
        } else if (command == 'r') {
            look();
        } else if (command == 'l') {
            show("leave on vb", leave(member, "239.1.2.3", NULL, VB));
        } else if (command == 'c') {
            close(on_vd);
            for (int i = 0; i < count; i++)
                if (sockets[i].fd == on_vd) sockets[i].fd = -1;
        } else if (command == 'b') {
            /* Back to A. */
            int fd = udp(AF_INET, "0.0.0.0", 7002);
            struct sockaddr_in to = at("239.1.2.3", 7000);
            show("if vb", through(fd, NULL, VB));
            show("\"back\" to 239.1.2.3: sendto", result(sendto(fd, "back", 4, 0, (void *)&to, sizeof to)));
            close(fd);
            look();
        } else if (command == 'w') {
            set_link(ctl, VB, 0, "down vb");
        } else if (command == 'x') {
            fflush(stdout);
            _exit(0);
        }
        fflush(stdout);
        if (write(out, "d", 1) != 1) _exit(2);
    }
    _exit(0);
}

/* Both ends of a pair in one namespace. */
static void one_namespace(void) {
    printf("A: unshare=%ld\n", result(unshare(CLONE_NEWNET)));
    int ctl = route_socket(0), links = route_socket(1);
    make_pair(ctl, getpid(), VE, "ve", VF, "vf");
    set_link(ctl, VE, 1, "up ve");
    set_link(ctl, VF, 1, "up vf");
    carrier(links, VE, 1);
    carrier(links, VF, 1);
    /* ldb [SKF_AD_OFF + SKF_AD_PKTTYPE]; add #8, the UDP header; ret a */
    const struct {
        unsigned short code;
        unsigned char jt, jf;
        unsigned k;
    } code[] = {{0x30, 0, 0, 0xfffff004u}, {0x04, 0, 0, 8}, {0x16, 0, 0, 0}};
    const struct {
        unsigned short len;
        const void *filter;
    } program = {3, code};
    const int devices[] = {VE, VF, 0};
    const char *const labels[] = {"member on ve, all off", "member on vf, all off", "no member"};
    for (int i = 0; i < 3; i++) {
        int fd = watch(udp(AF_INET, "0.0.0.0", 7000), labels[i]);
        show("filter", result(setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &program, sizeof program)));
        if (!devices[i]) continue;
        set_int(fd, IP_MULTICAST_ALL, 0);
        show("join", join(fd, "224.0.0.77", NULL, devices[i]));
    }
    int s = udp(AF_INET, "0.0.0.0", 7001), on = 1, device = VE;
    show("if ve", through(s, NULL, VE));
    struct sockaddr_in to = at("224.0.0.77", 7000);
    show("\"1234567\" to 224.0.0.77: sendto", result(sendto(s, "1234567", 7, 0, (void *)&to, sizeof to)));
    look();
    setsockopt(s, SOL_SOCKET, SO_BROADCAST, &on, sizeof on);
    show("to ve", result(setsockopt(s, SOL_SOCKET, SO_BINDTOIFINDEX_, &device, sizeof device)));
    to = at("255.255.255.255", 7000);
    show("\"1234567\" to 255.255.255.255: sendto", result(sendto(s, "1234567", 7, 0, (void *)&to, sizeof to)));
    look();
}

int main(int argc, char **argv) {
    if (argc < 2 || strcmp(argv[1], "veth-multicast")) return 99;
    setvbuf(stdout, NULL, _IOLBF, 0);
    int down[2], up[2];
    if (pipe(down) < 0 || pipe(up) < 0) return 98;
    fflush(stdout);
    pid_t b = fork();
    if (b == 0) {
        close(down[1]), close(up[0]);
        child(down[0], up[1]);
    }
    close(down[0]), close(up[1]);
    to_b = down[1], from_b = up[0];
    char ready;
    if (read(from_b, &ready, 1) != 1) return 97;
    printf("A: unshare=%ld\n", result(unshare(CLONE_NEWNET)));
    int ctl = route_socket(0), links = route_socket(1);
    make_pair(ctl, b, VA, "va", VB, "vb");
    make_pair(ctl, b, VC, "vc", VD, "vd");
    set_link(ctl, 1, 1, "up lo");
    address(ctl, VA, "10.77.0.1", "add 10.77.0.1/24");
    address(ctl, VC, "10.78.0.1", "add 10.78.0.1/24");
    look_up(ctl, "224.0.0.1", VA, 0, NULL, "224.0.0.1 through va, down");
    set_link(ctl, VA, 1, "up va");
    set_link(ctl, VC, 1, "up vc");
    b_does('u');
    carrier(links, VA, 1);
    carrier(links, VC, 1);
    options();

    b_does('s');
    int member = watch(udp(AF_INET, "0.0.0.0", 7000), "member on va");
    show("join on va", join(member, "239.1.2.3", "10.77.0.1", 0));
    watch(udp(AF_INET, "0.0.0.0", 7000), "no member");
    int off = watch(udp(AF_INET, "0.0.0.0", 7000), "no member, all off");
    set_int(off, IP_MULTICAST_ALL, 0);
    int on_lo = watch(udp(AF_INET, "0.0.0.0", 7000), "member on lo, all off");
    set_int(on_lo, IP_MULTICAST_ALL, 0);
    show("join on lo", join(on_lo, "239.1.2.5", "127.0.0.1", 0));
    look_up(ctl, "239.1.2.3", VA, 0, NULL, "239.1.2.3 through va");
    look_up(ctl, "239.1.2.3", VC, 0, NULL, "239.1.2.3 through vc");
    look_up(ctl, "239.1.2.3", 0, VA, "10.77.0.2", "239.1.2.3 in on va");
    look_up(ctl, "239.1.2.3", 0, VC, "10.78.0.2", "239.1.2.3 in on vc");
    look_up(ctl, "239.1.2.5", 1, 0, NULL, "239.1.2.5 through lo");
    look_up(ctl, "224.0.0.1", VA, 0, NULL, "224.0.0.1 through va");

    int s = udp(AF_INET, "0.0.0.0", 7001);
    send_to(s, "239.1.2.3", "no device");
    show("if va", through(s, NULL, VA));
    send_to(s, "239.1.2.3", "through va");
    send_to(s, "239.1.2.4", "another group");
    send_to(s, "224.0.0.77", "a local group");
    send_to(s, "224.0.0.1", "all hosts");
    show("if vc by address", through(s, "10.78.0.1", 0));
    send_to(s, "239.1.2.3", "through vc");
    show("if va, with vc's address", through(s, "10.78.0.1", VA));
    send_to(s, "239.1.2.3", "through va from vc");
    show("if va, with no one's address", through(s, "10.99.0.1", VA));
    send_to(s, "239.1.2.3", "from nobody");
    show("if va", through(s, "10.77.0.1", 0));
    show("loop 0", set_int(s, IP_MULTICAST_LOOP, 0));
    send_to(s, "239.1.2.3", "no loop");
    show("loop 1", set_int(s, IP_MULTICAST_LOOP, 1));
    show("ttl 0", set_int(s, IP_MULTICAST_TTL, 0));
    send_to(s, "239.1.2.3", "no hops");
    show("ttl 1", set_int(s, IP_MULTICAST_TTL, 1));
    b_does('b');
    look();
    /* Through lo. */
    show("if lo", through(s, "127.0.0.1", 0));
    send_to(s, "239.1.2.5", "through lo");
    send_to(s, "239.1.2.3", "through lo, another group");
    show("loop 0", set_int(s, IP_MULTICAST_LOOP, 0));
    send_to(s, "239.1.2.5", "through lo, no loop");
    show("if lo by index", through(s, NULL, 1));
    send_to(s, "239.1.2.5", "through lo by index");
    close(s);
    s = udp(AF_INET, "127.0.0.1", 7001);
    send_to(s, "239.1.2.5", "from lo");
    show("if va", through(s, NULL, VA));
    send_to(s, "239.1.2.5", "from lo through va");
    close(s);
    /* By the socket's address, and by its device. */
    s = udp(AF_INET, "10.78.0.1", 7001);
    send_to(s, "239.1.2.3", "from vc's address");
    close(s);
    int device = VA;
    s = udp(AF_INET, "0.0.0.0", 7001);
    show("if vc", through(s, NULL, VC));
    show("to va", result(setsockopt(s, SOL_SOCKET, SO_BINDTOIFINDEX_, &device, sizeof device)));
    send_to(s, "239.1.2.3", "on va");
    close(s);
    /* Connected. */
    s = udp(AF_INET, "0.0.0.0", 7001);
    struct sockaddr_in group = at("239.1.2.3", 7000), name = {0};
    socklen_t len = sizeof name;
    show("connect with no device", result(connect(s, (void *)&group, sizeof group)));
    show("if vc", through(s, "10.78.0.1", 0));
    show("connect", result(connect(s, (void *)&group, sizeof group)));
    getsockname(s, (void *)&name, &len);
    char ip[32];
    printf("A: its name=%s\n", inet_ntop(AF_INET, &name.sin_addr, ip, sizeof ip));
    show("\"connected\": send", result(send(s, "connected", 9, 0)));
    look();
    b_does('r');
    close(s);
    /* An IPv6 socket, which IP_MULTICAST_LOOP does not stop. */
    s = udp(AF_INET6, "::", 7001);
    show("if va of IPv6", through(s, NULL, VA));
    show("loop 0 of IPv6", set_int(s, IP_MULTICAST_LOOP, 0));
    struct sockaddr_in6 mapped = {.sin6_family = AF_INET6, .sin6_port = htons(7000)};
    inet_pton(AF_INET6, "::ffff:239.1.2.3", &mapped.sin6_addr);
    show("\"mapped\": sendto", result(sendto(s, "mapped", 6, 0, (void *)&mapped, sizeof mapped)));
    look();
    b_does('r');
    close(s);
    /* By a route. */
    route(ctl, VA, "239.0.0.0/8 through va");
    s = udp(AF_INET, "0.0.0.0", 7001);
    send_to(s, "239.1.2.3", "by the route");
    show("join by the route", join(s, "239.1.2.9", NULL, 0));
    show("leave on va", leave(s, "239.1.2.9", NULL, VA));
    /* Leaving and closing. */
    b_does('l');
    send_to(s, "239.1.2.3", "one left");
    show("if vc", through(s, NULL, VC));
    send_to(s, "239.1.2.3", "before a close");
    b_does('c');
    send_to(s, "239.1.2.3", "after a close");
    show("leave on va", leave(member, "239.1.2.3", NULL, VA));
    show("if va", through(s, NULL, VA));
    send_to(s, "239.1.2.3", "A has left");
    show("join again", join(member, "239.1.2.3", NULL, VA));
    /* B's end down: A's copy alone; then up again. */
    b_does('w');
    carrier(links, VA, 0);
    send_to(s, "239.1.2.3", "no carrier");
    set_link(ctl, VA, 0, "down va");
    send_to(s, "239.1.2.3", "va down");
    look_up(ctl, "224.0.0.1", VA, 0, NULL, "224.0.0.1 through va, down");
    look_up(ctl, "239.1.2.3", VA, 0, NULL, "239.1.2.3 through va, down");
    /* vc goes, and B's vd with it. */
    show("join on vc", join(member, "239.1.2.3", NULL, VC));
    struct body gone = {0};
    info(&gone, VC, 0, 0);
    request(ctl, RTM_DELLINK, 0, &gone, "delete vc");
    show("join on vc, gone", join(member, "239.1.2.3", NULL, VC));
    show("leave on vc, gone", leave(member, "239.1.2.3", NULL, VC));
    show("leave on vc again", leave(member, "239.1.2.3", NULL, VC));
    show("if vc, gone", through(s, NULL, VC));
    b_does('x');
    int status = 0;
    waitpid(b, &status, 0);
    printf("A: B exited=%d\n", WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    for (int i = 0; i < count; i++) close(sockets[i].fd);
    close(s), close(ctl), close(links);
    count = 0;
    one_namespace();
    return 0;
}
