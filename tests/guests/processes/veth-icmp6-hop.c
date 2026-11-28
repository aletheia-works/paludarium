/* Which next hop of an IPv6 multipath route ICMPv6's port unreachable
   takes back (so as root): veth-icmp-hop's namespaces, of IPv6 alone: "va"
   (1000, 2001:db8::1/64) and "vc" (1002, 2001:db8:1::1/64), whose peers
   "vb" and "vd", in another, have 2001:db8::2 and 2001:db8:1::2, and
   2001:db8:2::1/64 on its lo, which routes 2001:db8:5::/64 back through
   2001:db8::1 on vb and 2001:db8:1::1 on vd by
   net.ipv4.fib_multipath_hash_seed 1. UDP datagrams from 2001:db8:5::1
   go to a closed port there through va alone, and which of va and vc
   takes in each error (/proc/net/dev) tells its hop. Linux hashes the
   error's route with the packet it tells of (icmp6_send,
   rt6_multipath_hash), so that each net.ipv6.fib_multipath_hash_policy
   hashes that packet: its addresses, flow label and protocol (0), its
   addresses, protocol and ports (1), or the fields named (3). A connected
   socket's packets carry its random flow hash, which policy 1 takes before
   all else; which hops such sockets take is not printed, as the
   differential harness's host gives every socket the same random bytes.
   So that nothing else comes in, no address is checked for duplicates, no
   router is solicited, each neighbour is permanent and, a while after the
   links come up, their group reports are done. No flow label is made up
   (auto_flowlabels 0), and no error is rate limited (icmp's ratemask);
   Linux alone has these and router_solicitations. */
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
#define RTM_GETROUTE 26
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
#define IFA_LOCAL 2
#define IFA_ADDRESS_ 1
#define IFA_FLAGS 8
#define IFA_F_NODAD 0x02
#define RTM_NEWNEIGH 28
#define NDA_DST 1
#define NDA_LLADDR 2
#define NUD_PERMANENT 0x80
#define RTA_DST 1
#define RTA_SRC 2
#define RTA_OIF 4
#define RTA_GATEWAY 5
#define RTA_MULTIPATH 9
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
/* RTNLGRP_LINK of the first namespace, where carriers are waited for. */
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
/* Adds the IPv6 address `ip`/`prefix` of the device of `index`,
   IFA_F_NODAD. */
static void address6(int fd, int index, const char *ip, int prefix, const char *label) {
    struct body b = {0};
    const unsigned char m[8] = {AF_INET6, (unsigned char)prefix, IFA_F_NODAD, 0, (unsigned char)index,
                                (unsigned char)(index >> 8), 0, 0};
    unsigned char in[16];
    inet_pton(AF_INET6, ip, in);
    raw(&b, m, sizeof m);
    put(&b, IFA_LOCAL, in, 16);
    put32(&b, IFA_FLAGS, IFA_F_NODAD);
    request(fd, RTM_NEWADDR, NLM_F_CREATE | NLM_F_EXCL, &b, label);
}
/* Adds the permanent neighbour `ip`, of the link address 02:00:00:00:00:
   `last`, of the device of `index`. */
static void neighbour6(int fd, int index, const char *ip, unsigned char last, const char *label) {
    struct body b = {0};
    unsigned char m[12] = {AF_INET6, 0, 0, 0, (unsigned char)index, (unsigned char)(index >> 8), 0, 0,
                           NUD_PERMANENT, 0, 0, 0};
    const unsigned char mac[6] = {2, 0, 0, 0, 0, last};
    unsigned char in[16];
    inet_pton(AF_INET6, ip, in);
    raw(&b, m, sizeof m);
    put(&b, NDA_DST, in, 16);
    put(&b, NDA_LLADDR, mac, 6);
    request(fd, RTM_NEWNEIGH, NLM_F_CREATE | NLM_F_EXCL, &b, label);
}
/* Makes the pair of `a` and, in this process's namespace, `b`. */
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

/* A next hop of an RTA_MULTIPATH request. */
struct hop {
    const char *via;
    int oif;
};
/* Adds a route to `dst`/64 of the two next hops `hops`. */
static void route6(int fd, const char *dst, const struct hop *hops, const char *label) {
    struct body b = {0};
    const unsigned char rtm[12] = {AF_INET6, 64, 0, 0, 254, 3, 0, 1};
    unsigned char in[16];
    inet_pton(AF_INET6, dst, in);
    raw(&b, rtm, sizeof rtm);
    put(&b, RTA_DST, in, 16);
    size_t mp = begin(&b, RTA_MULTIPATH);
    for (int i = 0; i < 2; i++) {
        size_t at = b.len;
        unsigned char rtnh[8] = {0};
        memcpy(rtnh + 4, &hops[i].oif, 4);
        raw(&b, rtnh, sizeof rtnh);
        inet_pton(AF_INET6, hops[i].via, in);
        put(&b, RTA_GATEWAY, in, 16);
        unsigned short len = (unsigned short)(b.len - at);
        memcpy(b.bytes + at, &len, 2);
    }
    end(&b, mp);
    request(fd, RTM_NEWROUTE, NLM_F_CREATE | NLM_F_EXCL, &b, label);
}
/* Adds a route to `dst`/64 through `via` on the device of `oif`. */
static void route_via(int fd, const char *dst, const char *via, int oif, const char *label) {
    struct body b = {0};
    const unsigned char rtm[12] = {AF_INET6, 64, 0, 0, 254, 3, 0, 1};
    unsigned char in[16];
    raw(&b, rtm, sizeof rtm);
    inet_pton(AF_INET6, dst, in);
    put(&b, RTA_DST, in, 16);
    inet_pton(AF_INET6, via, in);
    put(&b, RTA_GATEWAY, in, 16);
    put32(&b, RTA_OIF, (unsigned)oif);
    request(fd, RTM_NEWROUTE, NLM_F_CREATE | NLM_F_EXCL, &b, label);
}

#define PORTS 32
#define SEND 1
#define CONNECTED 2
#define DISCONNECTED 3

/* The packets va and vc have taken in, from /proc/net/dev. */
static void taken(long *a, long *c) {
    char line[512];
    *a = *c = -1;
    FILE *f = fopen("/proc/net/dev", "r");
    while (f && fgets(line, sizeof line, f)) {
        char name[32];
        long bytes, packets;
        if (sscanf(line, " %31[^:]: %ld %ld", name, &bytes, &packets) != 3) continue;
        if (!strcmp(name, "va")) *a = packets;
        if (!strcmp(name, "vc")) *c = packets;
    }
    if (f) fclose(f);
}
/* Sends a datagram from `s` (to `to`, or its peer for NULL) and waits up
   to a second for an error to come in: 'a' for va, 'c' for vc, '?' for
   both or none. A connected socket's error is taken (SO_ERROR). */
static char hop(int s, const struct sockaddr_in6 *to) {
    long a, c, a2, c2;
    taken(&a, &c);
    long r = to ? sendto(s, "x", 1, 0, (const void *)to, sizeof *to) : send(s, "x", 1, 0);
    if (r < 0) return 'e';
    struct timespec start, now, pause = {0, 1000000};
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (;;) {
        taken(&a2, &c2);
        if (a2 + c2 > a + c) break;
        clock_gettime(CLOCK_MONOTONIC, &now);
        if ((now.tv_sec - start.tv_sec) * 1000 + (now.tv_nsec - start.tv_nsec) / 1000000 > 1000) break;
        nanosleep(&pause, NULL);
    }
    /* A connected socket's error comes after the packet is counted. */
    struct pollfd ready = {.fd = s, .events = POLLERR};
    if (!to) poll(&ready, 1, 1000);
    int error = 0;
    socklen_t len = sizeof error;
    getsockopt(s, SOL_SOCKET, SO_ERROR, &error, &len);
    return a2 > a && c2 == c ? 'a' : c2 > c && a2 == a ? 'c' : '?';
}
static int from_port(int port) {
    struct sockaddr_in6 at = {.sin6_family = AF_INET6, .sin6_port = htons((unsigned short)port)};
    inet_pton(AF_INET6, "2001:db8:5::1", &at.sin6_addr);
    int s = socket(AF_INET6, SOCK_DGRAM, 0), one = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    if (bind(s, (void *)&at, sizeof at) < 0) printf("bind %d=%d\n", port, -errno);
    return s;
}
/* The hops of the errors of datagrams from ports 7100 on, `how` sent. A
   connected socket sends three, and its line tells whether each socket's
   took one hop, and whether those hops are the ones the ports took when
   last sent with no connect. */
static void errors(int how, const char *label) {
    struct sockaddr_in6 to = {.sin6_family = AF_INET6, .sin6_port = htons(9)};
    inet_pton(AF_INET6, "2001:db8:2::1", &to.sin6_addr);
    static char sent[PORTS + 1];
    char out[PORTS + 1] = {0};
    int same = 0;
    for (int i = 0; i < PORTS; i++) {
        int s = from_port(7100 + i);
        if (how == SEND) {
            out[i] = hop(s, &to);
        } else {
            connect(s, (void *)&to, sizeof to);
            char first = hop(s, NULL), second = hop(s, NULL), third;
            if (how == DISCONNECTED) {
                struct sockaddr none = {.sa_family = AF_UNSPEC};
                connect(s, &none, sizeof none);
                third = hop(s, &to);
            } else {
                third = hop(s, NULL);
            }
            out[i] = first;
            same += first == second && second == third;
        }
        close(s);
    }
    if (how == SEND) {
        memcpy(sent, out, sizeof sent);
        if (label) printf("%s: %s\n", label, out);
    } else if (label) {
        printf("%s: %d of %d the same, %s as their ports' were\n", label, same, PORTS,
               strcmp(out, sent) ? "not" : "just");
    }
}
/* The connected sockets' hops, where they are not random. */
static void connected(const char *label) {
    struct sockaddr_in6 to = {.sin6_family = AF_INET6, .sin6_port = htons(9)};
    inet_pton(AF_INET6, "2001:db8:2::1", &to.sin6_addr);
    char out[PORTS + 1] = {0};
    for (int i = 0; i < PORTS; i++) {
        int s = from_port(7100 + i);
        connect(s, (void *)&to, sizeof to);
        out[i] = hop(s, NULL);
        close(s);
    }
    printf("%s: %s\n", label, out);
}
static void file(const char *path, const char *value) {
    int fd = open(path, O_WRONLY);
    if (fd >= 0) {
        if (write(fd, value, strlen(value)) < 0) printf("%s: %d\n", path, -errno);
        close(fd);
    }
}
/* The other namespace's policy `policy` and fields `fields`. */
static void policy(int ns, int home, const char *policy, const char *fields) {
    setns(ns, CLONE_NEWNET);
    sysctl("/proc/sys/net/ipv6/fib_multipath_hash_policy", policy);
    if (fields) sysctl("/proc/sys/net/ipv6/fib_multipath_hash_fields", fields);
    setns(home, CLONE_NEWNET);
}

/* This namespace's devices to come: no duplicate checks, no router
   solicitations, no flow labels made up. */
static void quiet(void) {
    sysctl("/proc/sys/net/ipv6/conf/default/accept_dad", "0");
    file("/proc/sys/net/ipv6/conf/default/router_solicitations", "0");
    file("/proc/sys/net/ipv6/auto_flowlabels", "0");
}

int main(int argc, char **argv) {
    if (argc < 2 || strcmp(argv[1], "veth-icmp6-hop")) return 99;
    setvbuf(stdout, NULL, _IOLBF, 0);
    printf("unshare=%ld\n", result(unshare(CLONE_NEWNET)));
    int ctl = route_socket(0);
    events = route_socket(1);
    int home = open("/proc/self/ns/net", O_RDONLY);
    quiet();
    printf("unshare=%ld\n", result(unshare(CLONE_NEWNET)));
    int far = route_socket(0);
    int ns = open("/proc/self/ns/net", O_RDONLY);
    quiet();
    sysctl("/proc/sys/net/ipv4/fib_multipath_hash_seed", "1");
    /* Linux's alone: here no error is rate limited. */
    file("/proc/sys/net/ipv6/icmp/ratemask", "0");
    make_pair(ctl, VA, "va", VB, "vb", 0x0a);
    make_pair(ctl, VC, "vc", VD, "vd", 0x0c);
    set_link(ctl, 1, 1, "up lo");
    set_link(far, 1, 1, "up the other lo");
    set_link(far, VB, 1, "up vb");
    set_link(far, VD, 1, "up vd");
    drain(events);
    set_link(ctl, VA, 1, "up va");
    wait_carrier(VA, 1, "va's carrier");
    drain(events);
    set_link(ctl, VC, 1, "up vc");
    wait_carrier(VC, 1, "vc's carrier");
    address6(ctl, VA, "2001:db8::1", 64, "add va's address");
    address6(ctl, VC, "2001:db8:1::1", 64, "add vc's address");
    address6(ctl, 1, "2001:db8:5::1", 128, "add 2001:db8:5::1/128");
    address6(far, VB, "2001:db8::2", 64, "add vb's address");
    address6(far, VD, "2001:db8:1::2", 64, "add vd's address");
    address6(far, 1, "2001:db8:2::1", 64, "add 2001:db8:2::1/64");
    neighbour6(ctl, VA, "2001:db8::2", 0x0b, "va's neighbour");
    neighbour6(far, VB, "2001:db8::1", 0x0a, "vb's neighbour");
    neighbour6(far, VD, "2001:db8:1::1", 0x0c, "vd's neighbour");
    const struct hop back[] = {{"2001:db8::1", VB}, {"2001:db8:1::1", VD}};
    route6(far, "2001:db8:5::", back, "2001:db8:5::/64 through vb and vd");
    route_via(ctl, "2001:db8:2::", "2001:db8::2", VA, "2001:db8:2::/64 through va");
    /* The links' group reports are done in a few seconds. */
    struct timespec reports = {3, 0};
    nanosleep(&reports, NULL);
    printf("setns=%ld\n", result(setns(home, CLONE_NEWNET)));

    /* A round first, so that only errors come in. */
    errors(SEND, NULL);

    policy(ns, home, "0", NULL);
    errors(SEND, "policy 0");
    connected("policy 0 connected");
    policy(ns, home, "1", NULL);
    errors(SEND, "policy 1");
    errors(CONNECTED, "policy 1 connected");
    errors(DISCONNECTED, "policy 1 disconnected");
    static const char *fields[] = {"55", "48", "16", "15", "7", "3"};
    for (size_t i = 0; i < sizeof fields / sizeof fields[0]; i++) {
        char label[64];
        policy(ns, home, "3", fields[i]);
        snprintf(label, sizeof label, "policy 3 fields %s", fields[i]);
        errors(SEND, label);
        snprintf(label, sizeof label, "policy 3 fields %s connected", fields[i]);
        connected(label);
    }
    return 0;
}
