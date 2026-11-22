/* TCP and UDP across a veth pair (so as root): a child, B, makes a network
   namespace of its own and waits; the parent, A, makes another and a pair,
   its end "va" (1000, 10.77.0.1/24) in A and "vb" (1001, 10.77.0.2/24) in
   B, and brings both ends and both loopbacks up. Then A connects to B's
   listener, and the two talk; a port nobody listens on refuses; an
   address of the subnet nobody has gives EHOSTUNREACH once ARP gives up,
   about 3 s later, to a blocking connect and to a nonblocking one; a
   connection from a loopback address is EINVAL. UDP datagrams go both
   ways; one to a port nobody has comes back as ICMP's port unreachable,
   which a connected socket learns of; one to an address nobody has is
   dropped. Before A has an address, a route through va leaves from
   0.0.0.0, as no address of a scope to fit is there: ARP is answered,
   and B drops what comes as a martian; with a global address on lo, it
   leaves from that one, which B, with no route back, drops with loose
   reverse path filtering and takes without it. TCP takes no broadcast or
   multicast route (ENETUNREACH), and UDP no broadcast one without
   SO_BROADCAST (EACCES). The two processes take turns through pipes, so their lines
   come in one order; the carrier, which Linux's link watch may change a
   little later, is waited for on RTNLGRP_LINK. */
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
#define RTM_DELADDR 21
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
static void set_up(int fd, int index, const char *label) {
    struct body b = {0};
    info(&b, index, IFF_UP, IFF_UP);
    request(fd, RTM_NEWLINK, 0, &b, label);
}
/* Adds, or removes with RTM_DELADDR, `ip`/`prefix` on the device of
   `index`. */
static void address_of(int fd, unsigned short type, int index, const char *ip, int prefix, const char *label) {
    struct body b = {0};
    struct ifaddrmsg_ a = {.family = AF_INET, .prefix = (unsigned char)prefix, .index = index};
    struct in_addr in;
    inet_pton(AF_INET, ip, &in);
    raw(&b, &a, sizeof a);
    put(&b, IFA_LOCAL, &in, 4);
    put(&b, IFA_ADDRESS, &in, 4);
    request(fd, type, type == RTM_NEWADDR ? NLM_F_CREATE | NLM_F_EXCL : 0, &b, label);
}
static void address(int fd, int index, const char *ip, const char *label) {
    address_of(fd, RTM_NEWADDR, index, ip, 24, label);
}
/* Adds or removes a route to `dst`/`prefix` on link through the device
   of `index`, of the main table. */
static void route(int fd, unsigned short type, const char *dst, int prefix, int index, const char *label) {
    struct body b = {0};
    const unsigned char rtm[12] = {AF_INET, (unsigned char)prefix, 0, 0, 254, 3, 253, 1};
    struct in_addr in;
    inet_pton(AF_INET, dst, &in);
    raw(&b, rtm, sizeof rtm);
    put(&b, RTA_DST, &in, 4);
    put32(&b, RTA_OIF, (unsigned)index);
    request(fd, type, type == RTM_NEWROUTE ? NLM_F_CREATE | NLM_F_EXCL : 0, &b, label);
}
/* Waits, up to 5 s, until the member links hears that the device of
   `index` has its carrier. */
static void carrier(int links, int index) {
    static unsigned char buf[65536];
    for (;;) {
        struct pollfd ready = {.fd = links, .events = POLLIN};
        if (poll(&ready, 1, 5000) <= 0) {
            printf("%s: no carrier on %d\n", side, index);
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
                    if ((kind & 0x3fff) == IFLA_CARRIER && alen >= 5 && body[a + 4] == 1) return;
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
/* The address of a socket's end, without its port where `port` is 0. */
static void show_name(int fd, int peer, int port, const char *label) {
    struct sockaddr_in a = {0};
    socklen_t len = sizeof a;
    long r = result(peer ? getpeername(fd, (void *)&a, &len) : getsockname(fd, (void *)&a, &len));
    char ip[32] = "?";
    inet_ntop(AF_INET, &a.sin_addr, ip, sizeof ip);
    if (port)
        printf("%s: %s=%ld %s:%u\n", side, label, r, ip, ntohs(a.sin_port));
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
    struct sockaddr_in from = {0};
    socklen_t len = sizeof from;
    long n = result(recvfrom(fd, buf, sizeof buf - 1, 0, (void *)&from, &len));
    char ip[32] = "-";
    if (len == sizeof from && from.sin_family == AF_INET) inet_ntop(AF_INET, &from.sin_addr, ip, sizeof ip);
    printf("%s: %s=%ld \"%s\" from %s\n", side, label, n, n > 0 ? buf : "", ip);
}

/* Writes `value` to IPv4's `rp_filter` of `device` in this namespace. */
static void rp_filter(const char *device, const char *value) {
    char path[64];
    snprintf(path, sizeof path, "/proc/sys/net/ipv4/conf/%s/rp_filter", device);
    int fd = open(path, O_WRONLY);
    if (fd < 0 || write(fd, value, strlen(value)) < 0) printf("%s: %s=%d\n", side, path, -errno);
    if (fd >= 0) close(fd);
}

/* B: makes its namespace, then does what A writes to `in`, one letter at
   a time, writing back to `out` when done. */
static void child(int in, int out) {
    side = "B";
    if (unshare(CLONE_NEWNET) < 0) printf("B: unshare=%d\n", -errno);
    int ctl = route_socket(0), links = route_socket(1);
    int listener = -1, conn = -1, udp = -1;
    fflush(stdout);
    if (write(out, "r", 1) != 1) _exit(2);
    for (char command; read(in, &command, 1) == 1;) {
        if (command == 'u') {
            set_up(ctl, 1, "up lo");
            address(ctl, B_INDEX, "10.77.0.2", "add 10.77.0.2/24");
            set_up(ctl, B_INDEX, "up vb");
            carrier(links, B_INDEX);
            listener = socket(AF_INET, SOCK_STREAM, 0);
            struct sockaddr_in any = at("0.0.0.0", 5000);
            printf("B: bind=%ld\n", result(bind(listener, (void *)&any, sizeof any)));
            printf("B: listen=%ld\n", result(listen(listener, 4)));
            udp = socket(AF_INET, SOCK_DGRAM, 0);
            any = at("0.0.0.0", 6000);
            printf("B: bind udp=%ld\n", result(bind(udp, (void *)&any, sizeof any)));
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
        } else if (command == 'd') {
            receive(udp, "udp recvfrom");
            struct sockaddr_in back = at("10.77.0.1", 6100);
            printf("B: udp reply=%ld\n", result(sendto(udp, "back", 4, 0, (void *)&back, sizeof back)));
        } else if (command == 'g') {
            receive(udp, "udp recvfrom");
        } else if (command == 'L' || command == 'O') {
            /* Reverse path filtering loose, or off, whatever a new
               namespace took from the first one (devconf_inherit_init_net). */
            const char *value = command == 'L' ? "2" : "0";
            rp_filter("all", value);
            rp_filter("vb", value);
            printf("B: rp_filter %s\n", value);
        } else if (command == 'n') {
            /* Nothing more came. */
            int none = (int)result(recv(udp, (char[8]){0}, 8, MSG_DONTWAIT));
            printf("B: udp nothing more=%d\n", none);
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
    if (argc < 2 || strcmp(argv[1], "veth-traffic")) return 99;
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
    set_up(ctl, 1, "up lo");
    set_up(ctl, A_INDEX, "up va");
    B_DOES("u");
    carrier(links, A_INDEX);

    /* No address yet: a route through va leaves from 0.0.0.0. */
    route(ctl, RTM_NEWROUTE, "10.77.0.0", 24, A_INDEX, "route through va");
    int zero = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in to = at("10.77.0.2", 6000);
    printf("A: udp connect from none=%ld\n", result(connect(zero, (void *)&to, sizeof to)));
    show_name(zero, 0, 0, "udp connected from none");
    printf("A: udp send from none=%ld\n", result(send(zero, "zero", 4, 0)));
    close(zero);
    B_DOES("n");
    zero = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    to = at("10.77.0.2", 5000);
    printf("A: connect from none=%ld\n", result(connect(zero, (void *)&to, sizeof to)));
    struct pollfd waiting = {.fd = zero, .events = POLLIN | POLLOUT};
    printf("A: poll for 4 s=%d\n", poll(&waiting, 1, 4000));
    show_name(zero, 0, 0, "connecting from");
    close(zero);
    /* From 0.0.0.0 to an address nobody has: ARP goes unanswered. */
    zero = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    to = at("10.77.0.9", 5000);
    printf("A: connect from none to nobody=%ld\n", result(connect(zero, (void *)&to, sizeof to)));
    waiting = (struct pollfd){.fd = zero, .events = POLLIN | POLLOUT};
    printf("A: poll for 4 s=%d\n", poll(&waiting, 1, 4000));
    int lost = 0;
    socklen_t size = sizeof lost;
    getsockopt(zero, SOL_SOCKET, SO_ERROR, &lost, &size);
    printf("A: SO_ERROR from none=%d\n", lost);
    close(zero);
    /* With a global address on lo, the route leaves from it, as
       inet_select_addr takes another device's address of a scope to fit
       where the end has none. B, which has no route back to it, drops
       what comes from it with loose reverse path filtering and takes it
       with none (fib_validate_source). */
    address_of(ctl, RTM_NEWADDR, 1, "10.9.9.9", 32, "add 10.9.9.9/32 on lo");
    zero = socket(AF_INET, SOCK_DGRAM, 0);
    to = at("10.77.0.2", 6000);
    printf("A: udp connect from lo's=%ld\n", result(connect(zero, (void *)&to, sizeof to)));
    show_name(zero, 0, 0, "udp connected from lo's");
    B_DOES("L");
    printf("A: udp send from lo's=%ld\n", result(send(zero, "loose", 5, 0)));
    B_DOES("g");
    B_DOES("O");
    printf("A: udp send from lo's=%ld\n", result(send(zero, "lo's", 4, 0)));
    close(zero);
    B_DOES("g");
    zero = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    to = at("10.77.0.2", 5000);
    printf("A: connect from lo's=%ld\n", result(connect(zero, (void *)&to, sizeof to)));
    show_name(zero, 0, 0, "connecting from lo's");
    close(zero);
    address_of(ctl, RTM_DELADDR, 1, "10.9.9.9", 32, "remove 10.9.9.9/32");
    route(ctl, RTM_DELROUTE, "10.77.0.0", 24, A_INDEX, "route gone");
    address(ctl, A_INDEX, "10.77.0.1", "add 10.77.0.1/24");

    /* A connection to B's listener, and a few bytes each way. */
    int c = socket(AF_INET, SOCK_STREAM, 0);
    to = at("10.77.0.2", 5000);
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
    c = socket(AF_INET, SOCK_STREAM, 0);
    to = at("10.77.0.2", 5001);
    printf("A: connect to a closed port=%ld\n", result(connect(c, (void *)&to, sizeof to)));
    close(c);

    /* An address of the subnet nobody has: ARP gives up. */
    c = socket(AF_INET, SOCK_STREAM, 0);
    to = at("10.77.0.3", 5000);
    double start = seconds();
    printf("A: connect to nobody=%ld\n", result(connect(c, (void *)&to, sizeof to)));
    printf("A: it took %s\n", about_three(seconds() - start));
    close(c);
    c = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    to = at("10.77.0.4", 5000);
    start = seconds();
    printf("A: nonblocking connect to nobody=%ld\n", result(connect(c, (void *)&to, sizeof to)));
    struct pollfd p = {.fd = c, .events = POLLIN | POLLOUT};
    printf("A: poll=%d\n", poll(&p, 1, 10000));
    printf("A: revents=%#x, it took %s\n", p.revents, about_three(seconds() - start));
    int error = 0;
    socklen_t len = sizeof error;
    getsockopt(c, SOL_SOCKET, SO_ERROR, &error, &len);
    printf("A: SO_ERROR=%d\n", error);
    close(c);

    /* From a loopback address, nothing goes out through va. */
    c = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in local = at("127.0.0.1", 0);
    printf("A: bind 127.0.0.1=%ld\n", result(bind(c, (void *)&local, sizeof local)));
    to = at("10.77.0.2", 5000);
    printf("A: connect from 127.0.0.1=%ld\n", result(connect(c, (void *)&to, sizeof to)));
    close(c);

    /* UDP: a datagram to B and its answer. */
    int u = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in mine = at("0.0.0.0", 6100);
    printf("A: bind udp=%ld\n", result(bind(u, (void *)&mine, sizeof mine)));
    to = at("10.77.0.2", 6000);
    printf("A: udp sendto=%ld\n", result(sendto(u, "hello", 5, 0, (void *)&to, sizeof to)));
    B_DOES("d");
    receive(u, "udp recvfrom");
    /* Connected to a port nobody has: the second send learns of the
       first's port unreachable. */
    int cu = socket(AF_INET, SOCK_DGRAM, 0);
    to = at("10.77.0.2", 6001);
    printf("A: udp connect=%ld\n", result(connect(cu, (void *)&to, sizeof to)));
    show_name(cu, 0, 0, "udp connected from");
    printf("A: udp send=%ld\n", result(send(cu, "x", 1, 0)));
    usleep(200000);
    printf("A: udp send again=%ld\n", result(send(cu, "x", 1, 0)));
    close(cu);
    /* To an address nobody has: sent, and dropped. */
    to = at("10.77.0.3", 6000);
    printf("A: udp sendto nobody=%ld\n", result(sendto(u, "lost", 4, 0, (void *)&to, sizeof to)));
    B_DOES("n");

    /* Broadcast and multicast: TCP takes neither; UDP a broadcast one
       only with SO_BROADCAST. Nobody listens on 6002. */
    c = socket(AF_INET, SOCK_STREAM, 0);
    to = at("10.77.0.255", 5000);
    printf("A: connect to broadcast=%ld\n", result(connect(c, (void *)&to, sizeof to)));
    close(c);
    to = at("10.77.0.255", 6002);
    printf("A: udp sendto broadcast=%ld\n", result(sendto(u, "all", 3, 0, (void *)&to, sizeof to)));
    cu = socket(AF_INET, SOCK_DGRAM, 0);
    printf("A: udp connect broadcast=%ld\n", result(connect(cu, (void *)&to, sizeof to)));
    int on = 1;
    setsockopt(u, SOL_SOCKET, SO_BROADCAST, &on, sizeof on);
    setsockopt(cu, SOL_SOCKET, SO_BROADCAST, &on, sizeof on);
    printf("A: udp sendto broadcast, allowed=%ld\n", result(sendto(u, "all", 3, 0, (void *)&to, sizeof to)));
    printf("A: udp connect broadcast, allowed=%ld\n", result(connect(cu, (void *)&to, sizeof to)));
    close(cu);
    to = at("255.255.255.255", 6002);
    printf("A: udp sendto limited broadcast=%ld\n", result(sendto(u, "all", 3, 0, (void *)&to, sizeof to)));
    /* Bound to va's address, a limited broadcast or a group needs no route
       (ip_route_output_key_hash_rcu takes the source's device). */
    int bound = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in va = at("10.77.0.1", 6101);
    printf("A: bind udp to va's=%ld\n", result(bind(bound, (void *)&va, sizeof va)));
    setsockopt(bound, SOL_SOCKET, SO_BROADCAST, &on, sizeof on);
    printf("A: udp sendto limited broadcast from va's=%ld\n", result(sendto(bound, "all", 3, 0, (void *)&to, sizeof to)));
    to = at("224.1.2.3", 6002);
    printf("A: udp sendto a group, no route=%ld\n", result(sendto(u, "some", 4, 0, (void *)&to, sizeof to)));
    printf("A: udp sendto a group from va's, no route=%ld\n", result(sendto(bound, "some", 4, 0, (void *)&to, sizeof to)));
    printf("A: udp connect a group from va's, no route=%ld\n", result(connect(bound, (void *)&to, sizeof to)));
    close(bound);
    route(ctl, RTM_NEWROUTE, "224.0.0.0", 4, A_INDEX, "multicast through va");
    c = socket(AF_INET, SOCK_STREAM, 0);
    to = at("224.1.2.3", 5000);
    printf("A: connect to a group=%ld\n", result(connect(c, (void *)&to, sizeof to)));
    close(c);
    to = at("224.1.2.3", 6002);
    printf("A: udp sendto a group=%ld\n", result(sendto(u, "some", 4, 0, (void *)&to, sizeof to)));
    B_DOES("n");
    close(u);

    fflush(stdout);
    if (write(to_b[1], "x", 1) != 1) printf("A: B gone\n");
    int status = 0;
    waitpid(b, &status, 0);
    printf("A: B exited=%d\n", WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    return 0;
}
