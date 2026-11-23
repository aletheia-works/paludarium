/* IPv6 scope IDs across a veth pair (so as root): a child, B, makes a
   network namespace of its own and waits; the parent, A, makes another and
   a pair, its end "va" (1000, 02:00:00:00:00:0a, so fe80::ff:fe00:a) in A
   and "vb" (1001, fe80::ff:fe00:b) in B, with 2001:db8::1/64 and
   2001:db8::2/64, IFA_F_NODAD. A binds link-local addresses: without a
   scope ID, or in a 24-byte address, EINVAL; a scope ID of no device here
   ENODEV, of lo EADDRNOTAVAIL, which stays the socket's device for its next
   bind, until another scope ID replaces it; va's takes. A socket's device
   keeps it from binding ::1 but not a global address, and a scope ID does
   not count for an address that needs none. Groups of the node or link need
   one too, and a TCP socket takes no group. getsockname gives the device as
   the scope ID of an address that needs one. UDP sendto a link-local
   address goes through the scope ID's device, even one not the socket's,
   else the socket's, else the first route's; B's recvfrom gives the device
   it came in on as the sender's scope ID, and A's of B's answer va's.
   connect takes a scope ID as sendto does, which must be the socket's
   device if it has one; a TCP socket keeps it though the connect fails.
   (Linux master puts a UDP socket's back, which kernels without its fix
   do not, so no line here depends on it.) The two processes take
   turns through pipes, so their lines come in one order; an address done
   and a neighbour resolved are waited for on netlink. */
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
#define RTM_DELROUTE 25
#define RTM_GETROUTE 26
#define RTM_NEWNEIGH 28
#define NLM_F_REQUEST 1
#define NLM_F_ACK 4
#define NLM_F_DUMP 0x300
#define NLM_F_REPLACE 0x100
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
#define RTA_IIF 3
#define RTA_OIF 4
#define RTA_GATEWAY 5
#define RTA_PRIORITY 6
#define RTA_PREFSRC 7
#define RTA_TABLE 15
#define RTNH_F_ONLINK 4
#define RTM_F_FIB_MATCH 0x2000
#define NUD_REACHABLE 0x02
#define A_INDEX 1000
#define B_INDEX 1001


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
   for. */
static int events = -1, resolved = -1;

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
    if (request(fd, RTM_NEWADDR, NLM_F_CREATE | NLM_F_EXCL, &b, label) == 0)
        wait_for(events, ip, 0, 0, 0, label);
}
static void make_pair(int ctl, int ns) {
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
    put32(&m, IFLA_NET_NS_PID, (unsigned)ns);
    end(&m, peer);
    end(&m, data);
    end(&m, link);
    request(ctl, RTM_NEWLINK, NLM_F_CREATE | NLM_F_EXCL, &m, "make a pair");
}

static struct sockaddr_in6 at(const char *ip, int port, unsigned scope) {
    struct sockaddr_in6 a = {.sin6_family = AF_INET6, .sin6_port = htons((unsigned short)port), .sin6_scope_id = scope};
    inet_pton(AF_INET6, ip, &a.sin6_addr);
    return a;
}
/* Binds `fd` to `ip`, port `port` and scope ID `scope`, giving `len` bytes. */
static long bind6(int fd, const char *ip, int port, unsigned scope, socklen_t len, const char *label) {
    struct sockaddr_in6 a = at(ip, port, scope);
    long r = result(bind(fd, (void *)&a, len));
    printf("%s: %s: bind=%ld\n", side, label, r);
    return r;
}
/* Shows `a`, its port only where it is `fixed` (an ephemeral one is
   "any"). */
static void show(const char *label, long r, const struct sockaddr_in6 *a, int fixed) {
    char ip[64] = "-", port[16] = "any";
    if (a->sin6_family == AF_INET6) inet_ntop(AF_INET6, &a->sin6_addr, ip, sizeof ip);
    if (fixed || !a->sin6_port) snprintf(port, sizeof port, "%u", ntohs(a->sin6_port));
    printf("%s: %s=%ld %s port=%s scope=%u\n", side, label, r, ip, port, a->sin6_scope_id);
}
static void name(int fd, int fixed, const char *label) {
    struct sockaddr_in6 a = {0};
    socklen_t len = sizeof a;
    long r = result(getsockname(fd, (void *)&a, &len));
    show(label, r, &a, fixed);
}
static int udp(void) { return socket(AF_INET6, SOCK_DGRAM, 0); }
static long connect6(int fd, const char *ip, int port, unsigned scope, const char *label) {
    struct sockaddr_in6 to = at(ip, port, scope);
    long r = result(connect(fd, (void *)&to, sizeof to));
    printf("%s: %s: connect=%ld\n", side, label, r);
    return r;
}
static void peer(int fd, const char *label) {
    struct sockaddr_in6 a = {0};
    socklen_t len = sizeof a;
    long r = result(getpeername(fd, (void *)&a, &len));
    show(label, r, &a, 1);
}
static long send_to(int fd, const char *ip, int port, unsigned scope, const char *what, const char *label) {
    struct sockaddr_in6 to = at(ip, port, scope);
    long r = result(sendto(fd, what, strlen(what), 0, (void *)&to, sizeof to));
    printf("%s: %s: sendto=%ld\n", side, label, r);
    return r;
}
/* Receives a datagram on `fd`, and gives where it came from. */
static struct sockaddr_in6 receive(int fd, const char *label) {
    char buf[64] = {0};
    struct sockaddr_in6 from = {0};
    struct pollfd ready = {.fd = fd, .events = POLLIN};
    if (poll(&ready, 1, 2000) <= 0) {
        printf("%s: %s: nothing\n", side, label);
        return from;
    }
    socklen_t len = sizeof from;
    long n = result(recvfrom(fd, buf, sizeof buf - 1, 0, (void *)&from, &len));
    char line[128];
    snprintf(line, sizeof line, "%s \"%s\" from", label, n > 0 ? buf : "");
    show(line, n, &from, 1);
    return from;
}

/* B: makes its namespace, then does what A writes to `in`, one letter at
   a time, writing back to `out` when done. */
static void child(int in, int out) {
    side = "B";
    if (unshare(CLONE_NEWNET) < 0) printf("B: unshare=%d\n", -errno);
    int ctl = route_socket(0);
    events = route_socket(1 | 0x400);
    int u = -1;
    fflush(stdout);
    if (write(out, "r", 1) != 1) _exit(2);
    for (char command; read(in, &command, 1) == 1;) {
        if (command == 'u') {
            sysctl("/proc/sys/net/ipv6/conf/vb/accept_dad", "0");
            set_link(ctl, 1, 1, "up lo");
            set_link(ctl, B_INDEX, 1, "up the end");
            address6(ctl, B_INDEX, "2001:db8::2", 64, "add its address");
            u = udp();
            bind6(u, "::", 6000, 0, sizeof(struct sockaddr_in6), "udp on 6000");
        } else if (command == 'd') {
            /* A datagram, answered where it came from. */
            struct sockaddr_in6 from = receive(u, "recvfrom");
            if (from.sin6_family == AF_INET6)
                printf("B: reply=%ld\n", result(sendto(u, "back", 4, 0, (void *)&from, sizeof from)));
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
    if (argc < 2 || strcmp(argv[1], "veth-ipv6-scope")) return 99;
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
    make_pair(ctl, b);
    sysctl("/proc/sys/net/ipv6/conf/va/accept_dad", "0");
    set_link(ctl, 1, 1, "up lo");
    B_DOES("u");
    drain(events);
    set_link(ctl, A_INDEX, 1, "up the end");
    wait_for(events, NULL, A_INDEX, 1, 0, "the carrier");
    wait_for(events, "fe80::ff:fe00:a", 0, 0, 0, "the link-local address");
    address6(ctl, A_INDEX, "2001:db8::1", 64, "add its address");

    const socklen_t whole = sizeof(struct sockaddr_in6), short_ = 24;
    const char *own = "fe80::ff:fe00:a";
    /* A link-local address needs its device. */
    int s = udp();
    bind6(s, own, 0, 0, whole, "link-local without a scope ID");
    close(s);
    s = udp();
    bind6(s, own, 0, A_INDEX, short_, "link-local in 24 bytes");
    close(s);
    s = udp();
    bind6(s, own, 0, 999, whole, "scope ID of no device");
    close(s);
    s = udp();
    bind6(s, own, 0, B_INDEX, whole, "scope ID of vb");
    close(s);
    /* lo's stays the socket's device, until va's replaces it. */
    s = udp();
    bind6(s, own, 0, 1, whole, "scope ID of lo");
    bind6(s, own, 0, 0, whole, "then without one");
    bind6(s, own, 0, A_INDEX, whole, "then va's");
    name(s, 0, "its name");
    close(s);
    s = udp();
    bind6(s, own, 6400, A_INDEX, whole, "va's");
    name(s, 1, "its name");
    int bound = s;
    /* A device keeps a socket from ::1, not from a global address. */
    s = udp();
    bind6(s, "fe80::ff:fe00:b", 0, A_INDEX, whole, "B's link-local address on va");
    bind6(s, "::1", 0, 0, whole, "then ::1");
    bind6(s, "2001:db8::1", 0, 0, whole, "then 2001:db8::1");
    name(s, 0, "its name");
    close(s);
    s = udp();
    bind6(s, "2001:db8::1", 0, 1, whole, "global with lo's scope ID");
    name(s, 0, "its name");
    close(s);
    /* Groups. */
    s = udp();
    bind6(s, "ff02::1", 0, 0, whole, "ff02::1 without a scope ID");
    close(s);
    s = udp();
    bind6(s, "ff01::1", 0, 0, whole, "ff01::1 without a scope ID");
    close(s);
    s = udp();
    bind6(s, "ff02::1", 0, A_INDEX, whole, "ff02::1 on va");
    name(s, 0, "its name");
    close(s);
    s = udp();
    bind6(s, "ff0e::1", 0, 0, whole, "ff0e::1");
    name(s, 0, "its name");
    close(s);
    s = socket(AF_INET6, SOCK_STREAM, 0);
    bind6(s, "ff02::1", 0, A_INDEX, whole, "tcp ff02::1 on va");
    close(s);
    s = socket(AF_INET6, SOCK_STREAM, 0);
    bind6(s, own, 0, 0, whole, "tcp link-local without a scope ID");
    bind6(s, own, 0, A_INDEX, whole, "tcp link-local on va");
    name(s, 0, "its name");
    close(s);
    /* Datagrams. */
    int any = udp();
    bind6(any, "::", 6100, 0, whole, "udp on 6100");
    send_to(any, "fe80::ff:fe00:b", 6000, 999, "x", "through no device");
    send_to(any, "fe80::ff:fe00:b", 6000, 1, "x", "through lo");
    drain(resolved);
    send_to(any, "fe80::ff:fe00:b", 6000, A_INDEX, "hello", "through va");
    wait_for(resolved, "fe80::ff:fe00:b", 0, 0, NUD_REACHABLE, "fe80::ff:fe00:b reachable");
    B_DOES("d");
    receive(any, "recvfrom");
    send_to(any, "fe80::ff:fe00:b", 6000, 0, "first", "without a scope ID");
    B_DOES("d");
    receive(any, "recvfrom");
    send_to(bound, "fe80::ff:fe00:b", 6000, 0, "bound", "from the bound one");
    send_to(bound, "fe80::ff:fe00:b", 6000, 1, "x", "from the bound one through lo");
    B_DOES("d");
    receive(bound, "recvfrom");
    send_to(any, "2001:db8::2", 6000, A_INDEX, "global", "global with a scope ID");
    B_DOES("d");
    receive(any, "recvfrom");
    /* Through lo, its device. */
    s = udp();
    bind6(s, own, 0, 1, whole, "scope ID of lo");
    send_to(s, "fe80::ff:fe00:b", 6000, 0, "x", "through its device");
    send_to(s, "2001:db8::2", 6000, 0, "x", "global through its device");
    close(s);
    /* To itself. */
    send_to(any, own, 6100, A_INDEX, "self", "to its own");
    receive(any, "recvfrom");
    /* Connects. */
    const char *b_ll = "fe80::ff:fe00:b";
    s = udp();
    connect6(s, b_ll, 6000, 0, "udp without a scope ID");
    peer(s, "its peer");
    connect6(s, b_ll, 6000, 999, "udp scope ID of no device");
    close(s);
    s = udp();
    bind6(s, "::", 6200, 0, whole, "udp on 6200");
    connect6(s, b_ll, 6000, A_INDEX, "udp through va");
    peer(s, "its peer");
    name(s, 0, "its name");
    printf("A: send=%ld\n", result(send(s, "conn", 4, 0)));
    B_DOES("d");
    receive(s, "recvfrom");
    connect6(s, b_ll, 6000, B_INDEX, "then through vb");
    connect6(s, b_ll, 6000, 0, "then without a scope ID");
    peer(s, "its peer");
    connect6(s, "2001:db8::2", 6000, 0, "then global");
    peer(s, "its peer");
    close(s);
    s = udp();
    bind6(s, own, 0, 1, whole, "scope ID of lo");
    connect6(s, b_ll, 6000, A_INDEX, "then through va");
    connect6(s, "2001:db8::2", 6000, 0, "then global");
    close(s);
    s = socket(AF_INET6, SOCK_STREAM, 0);
    connect6(s, b_ll, 7000, 0, "tcp without a scope ID");
    connect6(s, b_ll, 7000, A_INDEX, "tcp through va");
    connect6(s, b_ll, 7000, 0, "then without a scope ID");
    close(s);
    s = socket(AF_INET6, SOCK_STREAM, 0);
    bind6(s, own, 0, 1, whole, "tcp scope ID of lo");
    connect6(s, b_ll, 7000, A_INDEX, "then through va");
    close(s);
    B_DOES("x");
    int status = 0;
    waitpid(b, &status, 0);
    printf("A: B exited=%d\n", WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    return 0;
}
