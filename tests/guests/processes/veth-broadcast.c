/* UDP broadcasts across a veth pair (so as root): a child, B, makes a
   network namespace of its own and waits; the parent, A, makes another and
   a pair, its end "va" (1000, 10.77.0.1/24) in A and "vb" (1001,
   10.77.0.2/24) in B, and brings both ends and both loopbacks up. B binds
   UDP sockets to port 7000 in several ways, A two, and A sends with
   SO_BROADCAST to the subnet's broadcast address and to the limited one.
   Each socket that takes it gets a copy (__udp4_lib_mcast_deliver): one
   bound to the unspecified address or to the broadcast address the
   datagram has, a dual-stack IPv6 one, and one bound to the broadcast
   address and connected to the sender; not one bound to a unicast
   address, IPV6_V6ONLY, connected elsewhere, or connected while bound to
   the unspecified address, as connect gives it the route's source
   (__udp_is_mcast_sock checks that first). An IPv6 one bound to an
   IPv4-mapped broadcast address keeps it as its IPv4 source
   (__inet6_bind), so it connects and sends to IPv4 with ENETUNREACH, or
   EINVAL for the limited one, and stays unconnected.
   A's own sockets get a copy too, as ip_mc_output loops a broadcast back,
   even after B's end goes down and the carrier with it. A broadcast's
   sendto returns once it has been delivered, so B looks after A has sent;
   the carrier, which Linux's link watch may change a little later, is
   waited for on RTNLGRP_LINK. */
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
#define RTA_DST 1
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
/* Waits, up to 5 s, until the member links hears that the device of
   `index` has its carrier, or has lost it. */
static void carrier(int links, int index, int want) {
    static unsigned char buf[65536];
    for (;;) {
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
                for (int a = 16; i.index == index && a + 4 <= body_len;) {
                    unsigned short alen, kind;
                    memcpy(&alen, body + a, 2);
                    memcpy(&kind, body + a + 2, 2);
                    if (alen < 4 || a + alen > body_len) break;
                    if ((kind & 0x3fff) == IFLA_CARRIER && alen >= 5 && body[a + 4] == want) return;
                    a += (alen + 3) & ~3;
                }
            }
            at += (h->len + 3) & ~3u;
        }
    }
}

static struct sockaddr_in at(const char *ip, int port) {
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons((unsigned short)port)};
    inet_pton(AF_INET, ip, &a.sin_addr);
    return a;
}
/* A UDP socket of `family` with SO_REUSEADDR (and IPV6_V6ONLY where
   `only`), bound to `ip` port 7000, and connected to 10.77.0.1 port
   `peer` (its IPv4-mapped form for IPv6) unless it is 0. */
static int bound(int family, const char *ip, int only, int peer, const char *label) {
    int fd = socket(family, SOCK_DGRAM, 0), on = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on);
    long r;
    if (family == AF_INET6) {
        setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &only, sizeof only);
        struct sockaddr_in6 a = {.sin6_family = AF_INET6, .sin6_port = htons(7000)};
        inet_pton(AF_INET6, ip, &a.sin6_addr);
        r = result(bind(fd, (void *)&a, sizeof a));
    } else {
        struct sockaddr_in a = at(ip, 7000);
        r = result(bind(fd, (void *)&a, sizeof a));
    }
    printf("%s: bind %s=%ld\n", side, label, r);
    if (peer && family == AF_INET6) {
        struct sockaddr_in6 to = {.sin6_family = AF_INET6, .sin6_port = htons((unsigned short)peer)};
        inet_pton(AF_INET6, "::ffff:10.77.0.1", &to.sin6_addr);
        printf("%s: connect %s=%ld\n", side, label, result(connect(fd, (void *)&to, sizeof to)));
    } else if (peer) {
        struct sockaddr_in to = at("10.77.0.1", peer);
        printf("%s: connect %s=%ld\n", side, label, result(connect(fd, (void *)&to, sizeof to)));
    }
    return fd;
}
/* What a socket has: waiting up to 2 s where `wait`, else none. */
static void receive(int fd, int wait, const char *label) {
    char buf[64] = {0};
    struct pollfd ready = {.fd = fd, .events = POLLIN};
    if (poll(&ready, 1, wait ? 2000 : 0) <= 0) {
        printf("%s: %s: nothing\n", side, label);
        return;
    }
    struct sockaddr_in6 from = {0};
    socklen_t len = sizeof from;
    long n = result(recvfrom(fd, buf, sizeof buf - 1, 0, (void *)&from, &len));
    char ip[64] = "-";
    unsigned port = 0;
    if (from.sin6_family == AF_INET) {
        struct sockaddr_in *four = (void *)&from;
        inet_ntop(AF_INET, &four->sin_addr, ip, sizeof ip);
        port = ntohs(four->sin_port);
    } else if (from.sin6_family == AF_INET6) {
        inet_ntop(AF_INET6, &from.sin6_addr, ip, sizeof ip);
        port = ntohs(from.sin6_port);
    }
    printf("%s: %s=%ld \"%s\" from %s:%u\n", side, label, n, n > 0 ? buf : "", ip, port);
}

#define B_SOCKETS 15
static const char *const b_labels[B_SOCKETS] = {
    "any", "any again", "unicast", "broadcast", "connected", "connected elsewhere", "dual-stack", "v6only",
    "dual-stack connected", "dual-stack connected elsewhere", "broadcast connected",
    "broadcast connected elsewhere", "mapped broadcast connected", "mapped broadcast connected elsewhere", "mapped limited connected",
};

/* B: makes its namespace, then does what A writes to `in`, one letter at
   a time, writing back to `out` when done. */
static void child(int in, int out) {
    side = "B";
    if (unshare(CLONE_NEWNET) < 0) printf("B: unshare=%d\n", -errno);
    int ctl = route_socket(0), links = route_socket(1);
    int fds[B_SOCKETS] = {0};
    fflush(stdout);
    if (write(out, "r", 1) != 1) _exit(2);
    for (char command; read(in, &command, 1) == 1;) {
        if (command == 'u') {
            set_link(ctl, 1, 1, "up lo");
            address(ctl, B_INDEX, "10.77.0.2", "add 10.77.0.2/24");
            set_link(ctl, B_INDEX, 1, "up vb");
            carrier(links, B_INDEX, 1);
            fds[0] = bound(AF_INET, "0.0.0.0", 0, 0, b_labels[0]);
            fds[1] = bound(AF_INET, "0.0.0.0", 0, 0, b_labels[1]);
            fds[2] = bound(AF_INET, "10.77.0.2", 0, 0, b_labels[2]);
            fds[3] = bound(AF_INET, "10.77.0.255", 0, 0, b_labels[3]);
            fds[4] = bound(AF_INET, "0.0.0.0", 0, 7001, b_labels[4]);
            fds[5] = bound(AF_INET, "0.0.0.0", 0, 7009, b_labels[5]);
            fds[6] = bound(AF_INET6, "::", 0, 0, b_labels[6]);
            fds[7] = bound(AF_INET6, "::", 1, 0, b_labels[7]);
            fds[8] = bound(AF_INET6, "::", 0, 7001, b_labels[8]);
            fds[9] = bound(AF_INET6, "::", 0, 7009, b_labels[9]);
            fds[10] = bound(AF_INET, "10.77.0.255", 0, 7001, b_labels[10]);
            fds[11] = bound(AF_INET, "10.77.0.255", 0, 7009, b_labels[11]);
            fds[12] = bound(AF_INET6, "::ffff:10.77.0.255", 0, 7001, b_labels[12]);
            fds[13] = bound(AF_INET6, "::ffff:10.77.0.255", 0, 7009, b_labels[13]);
            fds[14] = bound(AF_INET6, "::ffff:255.255.255.255", 0, 7001, b_labels[14]);
            /* Its broadcast source fails a send as it failed connect. */
            struct sockaddr_in6 to = {.sin6_family = AF_INET6, .sin6_port = htons(7000)};
            inet_pton(AF_INET6, "::ffff:10.77.0.1", &to.sin6_addr);
            printf("B: sendto from mapped broadcast=%ld\n",
                   result(sendto(fds[12], "x", 1, 0, (void *)&to, sizeof to)));
            printf("B: sendto from mapped limited=%ld\n",
                   result(sendto(fds[14], "x", 1, 0, (void *)&to, sizeof to)));
            /* Neither connected. */
            printf("B: send from mapped broadcast=%ld\n", result(send(fds[12], "x", 1, 0)));
            printf("B: send from mapped limited=%ld\n", result(send(fds[14], "x", 1, 0)));
        } else if (command == 'r') {
            /* The first takes every broadcast that comes. */
            for (int i = 0; i < B_SOCKETS; i++) receive(fds[i], i == 0, b_labels[i]);
        } else if (command == 'w') {
            set_link(ctl, B_INDEX, 0, "down vb");
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
    if (argc < 2 || strcmp(argv[1], "veth-broadcast")) return 99;
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
    int ctl = route_socket(0), links = route_socket(1);
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
    set_link(ctl, 1, 1, "up lo");
    address(ctl, A_INDEX, "10.77.0.1", "add 10.77.0.1/24");
    set_link(ctl, A_INDEX, 1, "up va");
    B_DOES("u");
    carrier(links, A_INDEX, 1);

    int any = bound(AF_INET, "0.0.0.0", 0, 0, "any");
    int unicast = bound(AF_INET, "10.77.0.1", 0, 0, "unicast");
    int sender = socket(AF_INET, SOCK_DGRAM, 0), on = 1;
    struct sockaddr_in from = at("10.77.0.1", 7001);
    printf("A: bind sender=%ld\n", result(bind(sender, (void *)&from, sizeof from)));
    printf("A: SO_BROADCAST=%ld\n", result(setsockopt(sender, SOL_SOCKET, SO_BROADCAST, &on, sizeof on)));

    /* To the subnet's broadcast address. */
    struct sockaddr_in to = at("10.77.0.255", 7000);
    printf("A: sendto subnet=%ld\n", result(sendto(sender, "subnet", 6, 0, (void *)&to, sizeof to)));
    receive(any, 1, "any");
    receive(unicast, 0, "unicast");
    B_DOES("r");

    /* To the limited broadcast address, which needs no route from va's. */
    to = at("255.255.255.255", 7000);
    printf("A: sendto limited=%ld\n", result(sendto(sender, "limited", 7, 0, (void *)&to, sizeof to)));
    receive(any, 1, "any");
    receive(unicast, 0, "unicast");
    B_DOES("r");

    /* A connected one, from another port: no connected one takes it. */
    int linked = socket(AF_INET, SOCK_DGRAM, 0);
    from = at("10.77.0.1", 7002);
    printf("A: bind linked=%ld\n", result(bind(linked, (void *)&from, sizeof from)));
    setsockopt(linked, SOL_SOCKET, SO_BROADCAST, &on, sizeof on);
    to = at("10.77.0.255", 7000);
    printf("A: connect linked=%ld\n", result(connect(linked, (void *)&to, sizeof to)));
    printf("A: send linked=%ld\n", result(send(linked, "linked", 6, 0)));
    receive(any, 1, "any");
    B_DOES("r");
    close(linked);

    /* B's end down, and va's carrier with it: only A's own copy. */
    B_DOES("w");
    carrier(links, A_INDEX, 0);
    to = at("10.77.0.255", 7000);
    printf("A: sendto without carrier=%ld\n", result(sendto(sender, "alone", 5, 0, (void *)&to, sizeof to)));
    receive(any, 1, "any");
    receive(unicast, 0, "unicast");
    B_DOES("r");

    fflush(stdout);
    if (write(to_b[1], "x", 1) != 1) printf("A: B gone\n");
    int status = 0;
    waitpid(b, &status, 0);
    printf("A: B exited=%d\n", WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    return 0;
}
