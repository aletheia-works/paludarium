/* Socket filters on UDP sockets across a veth pair (so as root): a child,
   B, makes a network namespace of its own and waits; the parent, A, makes
   another and a pair, its end "va" (1000, 10.77.0.1/24, 02:00:00:00:00:0a)
   in A and "vb" (1001, 10.77.0.2/24, 02:00:00:00:00:0b) in B, and brings
   both ends and both loopbacks up. Each side binds a UDP socket to port
   7000 and attaches the same classic filter, one at a time, which loads a
   value and keeps that many bytes and 8 (the UDP header) less an offset,
   so that what is received shows the value. A sends a datagram of 1400
   bytes to B, then a broadcast to the subnet with SO_BROADCAST, which B
   takes from across the pair and A from its own end, as ip_mc_output
   loops it back (dev_loopback_xmit). The values: the device's index and
   type, the packet's type (PACKET_HOST, PACKET_BROADCAST,
   PACKET_LOOPBACK), its protocol, the payload's offset, the MAC header's
   bytes (Ethernet's from va to vb or to the broadcast address; a looped
   copy's is where its network header is, so that two of those loads read
   its random IPv4 ID and checksum, which are not printed), and the IP
   header's TTL and protocol. A broadcast's sendto returns once it has been delivered, and
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
static int bound(const char *ip, int port) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0), on = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on);
    struct sockaddr_in a = at(ip, port);
    printf("%s: bind %s:%d=%ld\n", side, ip, port, result(bind(fd, (void *)&a, sizeof a)));
    return fd;
}

/* Classic filters: struct sock_filter and struct sock_fprog. */
struct sf {
    unsigned short code;
    unsigned char jt, jf;
    unsigned k;
};
struct fprog {
    unsigned short len;
    const struct sf *filter;
};
#define AD(n) (-0x1000 + (n))
#define NET(n) (-0x100000 + (n))
#define LL(n) (-0x200000 + (n))
#define LD_W_ABS 0x20
#define LD_H_ABS 0x28
#define LD_B_ABS 0x30
static const struct {
    const char *name;
    unsigned short code;
    int k, add;
    /* On a looped copy, whose MAC header is its network header, it reads
       the IPv4 ID or the header's checksum, random in both kernels. */
    int random_looped;
} loads[] = {
    {"ifindex", LD_W_ABS, AD(8), 8},
    {"hatype", LD_W_ABS, AD(28), 8},
    {"pkttype", LD_W_ABS, AD(4), 8},
    {"protocol less 1000", LD_W_ABS, AD(0), 8 - 1000},
    {"payload offset", LD_W_ABS, AD(52), 8},
    {"queue", LD_W_ABS, AD(24), 8},
    {"mark", LD_W_ABS, AD(20), 8},
    {"mac 0", LD_B_ABS, LL(0), 8},
    {"mac 5", LD_B_ABS, LL(5), 8, 1},
    {"mac 6", LD_B_ABS, LL(6), 8},
    {"mac 11", LD_B_ABS, LL(11), 8, 1},
    {"mac 12 less 1000", LD_H_ABS, LL(12), 8 - 1000},
    {"ttl", LD_B_ABS, NET(8), 8},
    {"ip protocol", LD_B_ABS, NET(9), 8},
    {"udp length less 1000", LD_H_ABS, 4, 8 - 1000},
};
#define LOADS (int)(sizeof loads / sizeof loads[0])

static void attach(int fd, int i) {
    struct sf f[] = {{loads[i].code, 0, 0, (unsigned)loads[i].k},
                     {0x04, 0, 0, (unsigned)loads[i].add},
                     {0x16, 0, 0, 0}};
    struct fprog p = {3, f};
    long r = result(setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &p, sizeof p));
    if (r) printf("%s: attach %s=%ld\n", side, loads[i].name, r);
}
/* What a socket received of the last datagram, waiting up to 2 s. */
static void receive(int fd, const char *how, int i) {
    static char buf[2048];
    struct pollfd ready = {.fd = fd, .events = POLLIN};
    if (poll(&ready, 1, 2000) <= 0) {
        printf("%s: %s %s: nothing\n", side, how, loads[i].name);
        return;
    }
    long n = result(recv(fd, buf, sizeof buf, MSG_DONTWAIT));
    if (loads[i].random_looped && !strcmp(how, "looped"))
        printf("%s: %s %s received %d\n", side, how, loads[i].name, n >= 0);
    else
        printf("%s: %s %s=%ld\n", side, how, loads[i].name, n);
}

/* B: makes its namespace, then does what A writes to `in`, a letter and
   a load's number at a time, writing back to `out` when done. */
static void child(int in, int out) {
    side = "B";
    if (unshare(CLONE_NEWNET) < 0) printf("B: unshare=%d\n", -errno);
    int ctl = route_socket(0), links = route_socket(1), fd = -1;
    fflush(stdout);
    if (write(out, "r", 1) != 1) _exit(2);
    for (char command[2]; read(in, command, 2) == 2;) {
        if (command[0] == 'u') {
            set_link(ctl, 1, 1, "up lo");
            address(ctl, B_INDEX, "10.77.0.2", "add 10.77.0.2/24");
            set_link(ctl, B_INDEX, 1, "up vb");
            carrier(links, B_INDEX, 1);
            fd = bound("0.0.0.0", 7000);
        } else if (command[0] == 'a') {
            attach(fd, command[1]);
        } else if (command[0] == 'r') {
            receive(fd, "unicast", command[1]);
            receive(fd, "broadcast", command[1]);
        } else if (command[0] == 'x') {
            fflush(stdout);
            _exit(0);
        }
        fflush(stdout);
        if (write(out, "d", 1) != 1) _exit(2);
    }
    _exit(0);
}

int main(int argc, char **argv) {
    if (argc < 2 || strcmp(argv[1], "veth-filter")) return 99;
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
#define B_DOES(letter, i)                                                     \
    do {                                                                      \
        char command_[2] = {(letter), (char)(i)};                             \
        fflush(stdout);                                                       \
        if (write(to_b[1], command_, 2) != 2 || read(to_a[0], &ready, 1) != 1) \
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
    B_DOES('u', 0);
    carrier(links, A_INDEX, 1);

    int own = bound("0.0.0.0", 7000);
    int sender = bound("10.77.0.1", 7001), on = 1;
    printf("A: SO_BROADCAST=%ld\n", result(setsockopt(sender, SOL_SOCKET, SO_BROADCAST, &on, sizeof on)));
    static char payload[1400];
    memset(payload, 'p', sizeof payload);
    struct sockaddr_in unicast = at("10.77.0.2", 7000), broadcast = at("10.77.0.255", 7000);
    for (int i = 0; i < LOADS; i++) {
        attach(own, i);
        B_DOES('a', i);
        long u = result(sendto(sender, payload, sizeof payload, 0, (void *)&unicast, sizeof unicast));
        long c = result(sendto(sender, payload, sizeof payload, 0, (void *)&broadcast, sizeof broadcast));
        if (u != (long)sizeof payload || c != (long)sizeof payload) printf("A: sendto=%ld %ld\n", u, c);
        receive(own, "looped", i);
        B_DOES('r', i);
    }

    fflush(stdout);
    if (write(to_b[1], "x", 2) != 2) printf("A: B gone\n");
    int status = 0;
    waitpid(b, &status, 0);
    printf("A: B exited=%d\n", WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    return 0;
}
